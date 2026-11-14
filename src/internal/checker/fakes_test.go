package checker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"

	"github.com/JairJosafath/mcp-customs/src/internal/canary"
	"github.com/JairJosafath/mcp-customs/src/internal/checker/sandbox"
	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// memoryRecorder keeps every write the handler makes, in order, and
// creates a check only once, as the store does. putErr and stepErr make
// those writes fail, as an outage would; loseFirstReply makes the first
// create succeed but answer an error, as a reply lost on the network does.
type memoryRecorder struct {
	mu             sync.Mutex
	checks         []store.Check
	created        []store.Check
	steps          []store.Step
	stepsOf        []string
	updates        []store.CheckUpdate
	verdicts       map[string]store.Verdict
	verdictPuts    int
	putErr         error
	stepErr        error
	loseFirstReply bool
	puts           int
}

func (m *memoryRecorder) PutCheck(_ context.Context, c store.Check) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.putErr != nil {
		return m.putErr
	}
	if slices.ContainsFunc(m.checks, func(made store.Check) bool { return made.ID == c.ID }) {
		return store.ErrCheckExists
	}
	m.checks = append(m.checks, c)
	m.created = append(m.created, c)
	if m.loseFirstReply && m.puts == 1 {
		return errors.New("connection reset")
	}
	return nil
}

func (m *memoryRecorder) GetCheck(_ context.Context, id string) (store.Check, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := slices.IndexFunc(m.checks, func(made store.Check) bool { return made.ID == id })
	if i < 0 {
		return store.Check{}, false, nil
	}
	return m.checks[i], true, nil
}

func (m *memoryRecorder) UpdateCheck(_ context.Context, id string, u store.CheckUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := slices.IndexFunc(m.checks, func(made store.Check) bool { return made.ID == id })
	if i < 0 {
		return store.ErrNoCheck
	}
	m.updates = append(m.updates, u)
	c := &m.checks[i]
	if u.Status != "" {
		c.Status = u.Status
	}
	if u.Verdict != "" {
		c.Verdict = u.Verdict
	}
	if u.CallbackID != "" {
		c.CallbackID = u.CallbackID
	}
	if u.SandboxID != "" {
		c.SandboxID = u.SandboxID
	}
	return nil
}

func (m *memoryRecorder) AppendStep(_ context.Context, checkID string, step store.Step) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stepErr != nil {
		return m.stepErr
	}
	// As DynamoDB does, refuse an item larger than it keeps.
	if size, err := store.StepSize(checkID, step); err != nil || size > store.MaxItemSize {
		return errors.Join(err, store.ErrItemTooLarge)
	}
	m.steps = append(m.steps, step)
	m.stepsOf = append(m.stepsOf, checkID)
	return nil
}

func (m *memoryRecorder) GetVerdict(_ context.Context, hash string) (store.Verdict, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.verdicts[hash]
	return v, ok, nil
}

func (m *memoryRecorder) PutVerdict(_ context.Context, v store.Verdict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.verdicts == nil {
		m.verdicts = map[string]store.Verdict{}
	}
	m.verdicts[v.Hash] = v
	m.verdictPuts++
	return nil
}

func (m *memoryRecorder) stepNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.steps))
	for _, s := range m.steps {
		names = append(names, s.Name)
	}
	return names
}

// memoryReports keeps the objects the handler puts, by key.
type memoryReports struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    int
}

func (m *memoryReports) PutReport(_ context.Context, checkID string, report []byte) error {
	return m.put("reports/"+checkID+".json", report)
}

func (m *memoryReports) PutObservations(_ context.Context, checkID string, observations []byte) error {
	return m.put("observations/"+checkID+".json", observations)
}

func (m *memoryReports) PutOversized(_ context.Context, checkID, what string, body []byte) error {
	return m.put("observations/"+checkID+"-"+what+".json", body)
}

func (m *memoryReports) put(key string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objects == nil {
		m.objects = map[string][]byte{}
	}
	m.objects[key] = body
	m.puts++
	return nil
}

func (m *memoryReports) report() (Report, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.objects["reports/c1.json"]
	if !ok {
		return Report{}, false
	}
	var r Report
	return r, json.Unmarshal(raw, &r) == nil
}

// server is the server under test as the fake harness plays it: what it
// installs to, lists and answers, and what it is seen doing.
type server struct {
	hash         string
	initialize   string
	tools        []string
	results      map[string]string
	installObs   []findings.Observation
	observations []findings.Observation
	// fail answers a path with this status and message instead.
	fail map[string]int
	// errors are the JSON-RPC errors tools answer instead of a result.
	errors map[string]string
	// hang makes /install never answer: the invocation's timeout cuts the
	// resolve step short after the launch.
	hang bool
	// tokens are the run tokens the calls carried, in order.
	mu     sync.Mutex
	tokens []string
}

// cutShort is a sandbox client whose invocation the timeout ends while
// resolve is still waiting on /install: the process is gone before
// resolve's own terminate of the sandbox can reach it. Only a later
// invocation's terminate does.
type cutShort struct {
	*sandbox.Fake
	mu  sync.Mutex
	cut bool
}

func (c *cutShort) Terminate(ctx context.Context, vm sandbox.VM) error {
	c.mu.Lock()
	first := !c.cut
	c.cut = true
	c.mu.Unlock()
	if first {
		return errInterrupted
	}
	return c.Fake.Terminate(ctx, vm)
}

// errInterrupted is a call the invocation's timeout cut short.
var errInterrupted = errors.New("the invocation timed out")

const depsHash = "5f3e0b8e6a4b2c1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d"

var weatherTool = `{"name":"get_weather","description":"Gets the weather for a city.","inputSchema":{"type":"object","properties":{"city":{"type":"string"},"days":{"type":"integer"},"units":{"enum":["metric","imperial"]}},"required":["city"]}}`

func cleanServer() *server {
	return &server{
		hash:       depsHash,
		initialize: `{"serverInfo":{"name":"weather"},"instructions":"Use get_weather for forecasts."}`,
		tools:      []string{weatherTool},
		results:    map[string]string{"get_weather": `{"content":[{"type":"text","text":"Sunny, 21°C."}]}`},
	}
}

// respond answers a Harness API call as the harness would for s.
func (s *server) respond(vm sandbox.VM, req sandbox.Request) (sandbox.Response, error) {
	s.mu.Lock()
	s.tokens = append(s.tokens, vm.Token)
	s.mu.Unlock()
	if status, ok := s.fail[req.Path]; ok {
		return answer(status, map[string]any{"message": "the server failed " + req.Path, "observations": []any{}}), nil
	}
	if s.hang && req.Path == "/install" {
		return sandbox.Response{}, errInterrupted
	}
	switch req.Path {
	case "/install":
		return answer(http.StatusOK, map[string]any{"log": "added 3 packages", "dependencies": "{}", "sha256": s.hash, "observations": orEmpty(s.installObs)}), nil
	case "/start":
		return answer(http.StatusOK, map[string]any{"initialize": json.RawMessage(s.initialize), "observations": []any{}}), nil
	case "/list":
		tools := make([]json.RawMessage, 0, len(s.tools))
		for _, t := range s.tools {
			tools = append(tools, json.RawMessage(t))
		}
		return answer(http.StatusOK, map[string]any{"tools": tools, "resources": []any{}, "prompts": []any{}, "observations": []any{}}), nil
	case "/call":
		body, _ := req.Body.(map[string]any)
		name, _ := body["tool"].(string)
		if e, ok := s.errors[name]; ok {
			return answer(http.StatusOK, map[string]any{"error": json.RawMessage(e), "observations": []any{}}), nil
		}
		return answer(http.StatusOK, map[string]any{"result": json.RawMessage(s.results[name]), "observations": []any{}}), nil
	case "/observations":
		all := append(append([]findings.Observation{}, s.installObs...), s.observations...)
		return answer(http.StatusOK, map[string]any{"observations": orEmpty(all)}), nil
	}
	return answer(http.StatusNotFound, map[string]any{"message": "no such route"}), nil
}

func orEmpty(obs []findings.Observation) []findings.Observation {
	if obs == nil {
		return []findings.Observation{}
	}
	return obs
}

func answer(status int, body any) sandbox.Response {
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return sandbox.Response{Status: status, Body: raw}
}

// fixedCanaries is one canary set for every run of a test, so a test can
// plant a canary in what the server is seen doing.
var fixedCanaries = canary.New()

// world is one test's Checker and everything it talks to.
type world struct {
	rec     *memoryRecorder
	reports *memoryReports
	vms     *sandbox.Fake
	srv     *server
}

func newWorld(srv *server) *world {
	w := &world{rec: &memoryRecorder{}, reports: &memoryReports{}, srv: srv}
	w.vms = &sandbox.Fake{Respond: srv.respond}
	return w
}

func (w *world) deps() Deps {
	return Deps{
		Store:    w.rec,
		Reports:  w.reports,
		Sandbox:  w.vms,
		Judge:    StubJudge{},
		Canaries: func() canary.Set { return fixedCanaries },
		Token:    func(checkID string) string { return "run-token-" + checkID },
	}
}

// paths are the Harness API paths the fake sandbox was called on, in order.
func (w *world) paths() []string {
	calls := w.vms.Calls()
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.Request.Path)
	}
	return out
}
