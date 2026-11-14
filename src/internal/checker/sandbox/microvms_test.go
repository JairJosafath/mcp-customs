package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms/types"
)

var testConfig = Config{
	ImageARN:            "arn:aws:lambda:us-east-2:123456789012:microvm-image:mcp-customs-harness",
	IngressConnectorARN: "arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:HTTP_INGRESS",
	EgressConnectorARN:  "arn:aws:lambda:us-east-2:aws:network-connector:aws-network-connector:INTERNET_EGRESS",
}

var testCanaries = []Canary{{Kind: "github-token", Value: "ghp_test"}, {Kind: "email", Value: "dev@example.com"}}

// fakeAPI records the Lambda MicroVMs calls made and answers each with the
// next of its states, or its error.
type fakeAPI struct {
	runs       []*lambdamicrovms.RunMicrovmInput
	tokens     []*lambdamicrovms.CreateMicrovmAuthTokenInput
	suspended  []string
	resumed    []string
	terminated []string
	// states are what GetMicrovm answers, one per call; the last repeats.
	states       []types.MicrovmState
	gets         int
	err          error
	terminateErr error
}

func (f *fakeAPI) RunMicrovm(_ context.Context, in *lambdamicrovms.RunMicrovmInput, _ ...func(*lambdamicrovms.Options)) (*lambdamicrovms.RunMicrovmOutput, error) {
	f.runs = append(f.runs, in)
	if f.err != nil {
		return nil, f.err
	}
	return &lambdamicrovms.RunMicrovmOutput{
		MicrovmId: aws.String("mvm-1"),
		Endpoint:  aws.String("mvm-1.lambda-microvm.us-east-2.on.aws"),
		State:     types.MicrovmStatePending,
	}, nil
}

func (f *fakeAPI) GetMicrovm(_ context.Context, in *lambdamicrovms.GetMicrovmInput, _ ...func(*lambdamicrovms.Options)) (*lambdamicrovms.GetMicrovmOutput, error) {
	state := f.states[min(f.gets, len(f.states)-1)]
	f.gets++
	return &lambdamicrovms.GetMicrovmOutput{MicrovmId: in.MicrovmIdentifier, State: state, StateReason: aws.String("test")}, nil
}

func (f *fakeAPI) CreateMicrovmAuthToken(_ context.Context, in *lambdamicrovms.CreateMicrovmAuthTokenInput, _ ...func(*lambdamicrovms.Options)) (*lambdamicrovms.CreateMicrovmAuthTokenOutput, error) {
	f.tokens = append(f.tokens, in)
	if f.err != nil {
		return nil, f.err
	}
	return &lambdamicrovms.CreateMicrovmAuthTokenOutput{AuthToken: map[string]string{"X-aws-proxy-auth": "jwe-token"}}, nil
}

func (f *fakeAPI) SuspendMicrovm(_ context.Context, in *lambdamicrovms.SuspendMicrovmInput, _ ...func(*lambdamicrovms.Options)) (*lambdamicrovms.SuspendMicrovmOutput, error) {
	f.suspended = append(f.suspended, aws.ToString(in.MicrovmIdentifier))
	return &lambdamicrovms.SuspendMicrovmOutput{}, f.err
}

func (f *fakeAPI) ResumeMicrovm(_ context.Context, in *lambdamicrovms.ResumeMicrovmInput, _ ...func(*lambdamicrovms.Options)) (*lambdamicrovms.ResumeMicrovmOutput, error) {
	f.resumed = append(f.resumed, aws.ToString(in.MicrovmIdentifier))
	return &lambdamicrovms.ResumeMicrovmOutput{}, f.err
}

func (f *fakeAPI) TerminateMicrovm(_ context.Context, in *lambdamicrovms.TerminateMicrovmInput, _ ...func(*lambdamicrovms.Options)) (*lambdamicrovms.TerminateMicrovmOutput, error) {
	f.terminated = append(f.terminated, aws.ToString(in.MicrovmIdentifier))
	return &lambdamicrovms.TerminateMicrovmOutput{}, f.terminateErr
}

// fakeDoer records the requests sent and answers each with its status and body.
type fakeDoer struct {
	requests []*http.Request
	bodies   []string
	status   int
	body     string
}

func (d *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	d.requests = append(d.requests, req)
	body := ""
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = string(b)
	}
	d.bodies = append(d.bodies, body)
	return &http.Response{StatusCode: d.status, Body: io.NopCloser(strings.NewReader(d.body))}, nil
}

// newTestMicroVMs is a MicroVMs on fakes, whose waits return at once and
// are counted.
func newTestMicroVMs(api *fakeAPI, doer *fakeDoer) (*MicroVMs, *int) {
	m := NewMicroVMs(api, doer, testConfig)
	sleeps := 0
	m.sleep = func(context.Context, time.Duration) error {
		sleeps++
		return nil
	}
	return m, &sleeps
}

func testLaunch() Launch {
	return Launch{IdempotencyKey: "check-1-a1", Token: "run-token", Canaries: testCanaries}
}

func TestLaunchRunsTheImageWithTheTokenAndCanariesAndWaitsUntilRunning(t *testing.T) {
	api := &fakeAPI{states: []types.MicrovmState{types.MicrovmStatePending, types.MicrovmStatePending, types.MicrovmStateRunning}}
	m, sleeps := newTestMicroVMs(api, &fakeDoer{})

	vm, err := m.Launch(t.Context(), testLaunch())
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	want := VM{ID: "mvm-1", Endpoint: "mvm-1.lambda-microvm.us-east-2.on.aws", Token: "run-token"}
	if vm != want {
		t.Errorf("Launch = %+v, want %+v", vm, want)
	}
	if *sleeps != 2 {
		t.Errorf("waited %d times for RUNNING, want 2", *sleeps)
	}
	if len(api.runs) != 1 {
		t.Fatalf("RunMicrovm called %d times, want 1", len(api.runs))
	}
	run := api.runs[0]
	if aws.ToString(run.ImageIdentifier) != testConfig.ImageARN || aws.ToString(run.ClientToken) != "check-1-a1" {
		t.Errorf("RunMicrovm image %q, client token %q", aws.ToString(run.ImageIdentifier), aws.ToString(run.ClientToken))
	}
	if len(run.IngressNetworkConnectors) != 1 || run.IngressNetworkConnectors[0] != testConfig.IngressConnectorARN ||
		len(run.EgressNetworkConnectors) != 1 || run.EgressNetworkConnectors[0] != testConfig.EgressConnectorARN {
		t.Errorf("RunMicrovm connectors in %v out %v", run.IngressNetworkConnectors, run.EgressNetworkConnectors)
	}
	if run.ExecutionRoleArn != nil {
		t.Errorf("RunMicrovm gave the sandbox an execution role, %q: the server under test must get no AWS credentials", aws.ToString(run.ExecutionRoleArn))
	}
	if aws.ToInt32(run.MaximumDurationInSeconds) != 7200 {
		t.Errorf("RunMicrovm maximum duration %d, want 7200", aws.ToInt32(run.MaximumDurationInSeconds))
	}
	if _, ok := run.Logging.(*types.LoggingMemberDisabled); !ok {
		t.Errorf("RunMicrovm logging %T, want disabled", run.Logging)
	}
	var payload runHookPayload
	if err := json.Unmarshal([]byte(aws.ToString(run.RunHookPayload)), &payload); err != nil {
		t.Fatalf("run hook payload: %v", err)
	}
	if payload.Token != "run-token" || len(payload.Canaries) != 2 || payload.Canaries[1] != testCanaries[1] {
		t.Errorf("run hook payload = %+v", payload)
	}
}

func TestLaunchTerminatesAMicroVMThatNeverRuns(t *testing.T) {
	tests := []struct {
		name   string
		states []types.MicrovmState
	}{
		{"terminated while starting", []types.MicrovmState{types.MicrovmStatePending, types.MicrovmStateTerminated}},
		{"terminating", []types.MicrovmState{types.MicrovmStateTerminating}},
		{"an unknown state", []types.MicrovmState{"EXPLODED"}},
		{"pending forever", []types.MicrovmState{types.MicrovmStatePending}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{states: tt.states}
			m, _ := newTestMicroVMs(api, &fakeDoer{})
			_, err := m.Launch(t.Context(), testLaunch())
			if !errors.Is(err, ErrNotRunning) {
				t.Errorf("Launch error = %v, want ErrNotRunning", err)
			}
			if len(api.terminated) != 1 || api.terminated[0] != "mvm-1" {
				t.Errorf("terminated %v, want [mvm-1]", api.terminated)
			}
		})
	}
}

func TestLaunchRefusesWhatTheHarnessCantStartWith(t *testing.T) {
	big := strings.Repeat("x", maxRunHookPayload)
	tests := []struct {
		name string
		in   Launch
		want error
	}{
		{"no idempotency key", Launch{Token: "t", Canaries: testCanaries}, ErrBadLaunch},
		{"a long idempotency key", Launch{IdempotencyKey: strings.Repeat("k", 65), Token: "t", Canaries: testCanaries}, ErrBadLaunch},
		{"no token", Launch{IdempotencyKey: "k", Canaries: testCanaries}, ErrBadLaunch},
		{"no canaries", Launch{IdempotencyKey: "k", Token: "t"}, ErrBadLaunch},
		{"over 16 KB", Launch{IdempotencyKey: "k", Token: "t", Canaries: []Canary{{Kind: "password", Value: big}}}, ErrPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &fakeAPI{states: []types.MicrovmState{types.MicrovmStateRunning}}
			m, _ := newTestMicroVMs(api, &fakeDoer{})
			if _, err := m.Launch(t.Context(), tt.in); !errors.Is(err, tt.want) {
				t.Errorf("Launch error = %v, want %v", err, tt.want)
			}
			if len(api.runs) != 0 {
				t.Error("RunMicrovm called for a bad launch")
			}
		})
	}
}

func TestLaunchReportsAFailedRun(t *testing.T) {
	api := &fakeAPI{err: &types.ServiceQuotaExceededException{Message: aws.String("quota")}}
	m, _ := newTestMicroVMs(api, &fakeDoer{})
	_, err := m.Launch(t.Context(), testLaunch())
	if quota := (*types.ServiceQuotaExceededException)(nil); !errors.As(err, &quota) {
		t.Errorf("Launch error = %v, want the quota error wrapped", err)
	}
}

func TestCallSendsBothTokensToTheHarnessPortOnly(t *testing.T) {
	api := &fakeAPI{}
	doer := &fakeDoer{status: http.StatusOK, body: `{"observations":[]}`}
	m, _ := newTestMicroVMs(api, doer)
	vm := VM{ID: "mvm-1", Endpoint: "mvm-1.lambda-microvm.us-east-2.on.aws", Token: "run-token"}

	resp, err := m.Call(t.Context(), vm, Request{Method: http.MethodPost, Path: "/install", Body: map[string]string{"kind": "npm"}})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != `{"observations":[]}` {
		t.Errorf("Call = %d %s", resp.Status, resp.Body)
	}
	if len(api.tokens) != 1 {
		t.Fatalf("CreateMicrovmAuthToken called %d times, want 1", len(api.tokens))
	}
	tok := api.tokens[0]
	port, ok := tok.AllowedPorts[0].(*types.PortSpecificationMemberPort)
	if len(tok.AllowedPorts) != 1 || !ok || port.Value != HarnessPort {
		t.Errorf("endpoint token opens %#v, want port %d only", tok.AllowedPorts, HarnessPort)
	}
	if aws.ToString(tok.MicrovmIdentifier) != "mvm-1" || aws.ToInt32(tok.ExpirationInMinutes) > 60 {
		t.Errorf("endpoint token for %q lasting %d minutes", aws.ToString(tok.MicrovmIdentifier), aws.ToInt32(tok.ExpirationInMinutes))
	}
	req := doer.requests[0]
	if req.Method != http.MethodPost || req.URL.String() != "https://mvm-1.lambda-microvm.us-east-2.on.aws/install" {
		t.Errorf("request %s %s", req.Method, req.URL)
	}
	for header, want := range map[string]string{
		"X-Aws-Proxy-Auth": "jwe-token",
		"X-Aws-Proxy-Port": "8080",
		"Authorization":    "Bearer run-token",
		"Content-Type":     "application/json",
	} {
		if got := req.Header.Get(header); got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}
	if doer.bodies[0] != `{"kind":"npm"}` {
		t.Errorf("body = %s", doer.bodies[0])
	}
}

func TestCallAnswersTheHarnessStatusOrWhyThereIsNone(t *testing.T) {
	vm := VM{ID: "mvm-1", Endpoint: "mvm-1.lambda-microvm.us-east-2.on.aws", Token: "run-token"}
	tests := []struct {
		name       string
		req        Request
		status     int
		body       string
		apiErr     error
		wantStatus int
		wantErr    error
	}{
		{"a GET without a body", Request{Method: http.MethodGet, Path: "/observations"}, http.StatusOK, `{"observations":[]}`, nil, http.StatusOK, nil},
		{"the harness's 401", Request{Method: http.MethodPost, Path: "/list", Body: struct{}{}}, http.StatusUnauthorized, `{"error":"unauthorized"}`, nil, http.StatusUnauthorized, nil},
		{"Lambda's 502 without JSON", Request{Method: http.MethodPost, Path: "/list"}, http.StatusBadGateway, "Bad Gateway", nil, 0, ErrNotJSON},
		{"no path", Request{Method: http.MethodPost}, http.StatusOK, `{}`, nil, 0, ErrBadRequest},
		{"no token from Lambda", Request{Method: http.MethodPost, Path: "/list"}, http.StatusOK, `{}`, errors.New("denied"), 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doer := &fakeDoer{status: tt.status, body: tt.body}
			m, _ := newTestMicroVMs(&fakeAPI{err: tt.apiErr}, doer)
			resp, err := m.Call(t.Context(), vm, tt.req)
			switch {
			case tt.apiErr != nil:
				if !errors.Is(err, tt.apiErr) || len(doer.requests) != 0 {
					t.Errorf("Call error = %v after %d requests, want the token error and none", err, len(doer.requests))
				}
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Call error = %v, want %v", err, tt.wantErr)
				}
			default:
				if err != nil || resp.Status != tt.wantStatus {
					t.Errorf("Call = %d, %v; want %d", resp.Status, err, tt.wantStatus)
				}
			}
		})
	}
}

func TestSuspendResumeAndTerminateTheMicroVM(t *testing.T) {
	api := &fakeAPI{states: []types.MicrovmState{types.MicrovmStateSuspended, types.MicrovmStateRunning}}
	m, sleeps := newTestMicroVMs(api, &fakeDoer{})
	vm := VM{ID: "mvm-1"}

	if err := m.Suspend(t.Context(), vm); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if err := m.Resume(t.Context(), vm); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := m.Terminate(t.Context(), vm); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if len(api.suspended) != 1 || len(api.resumed) != 1 || len(api.terminated) != 1 {
		t.Errorf("suspended %v, resumed %v, terminated %v", api.suspended, api.resumed, api.terminated)
	}
	// SUSPENDED while the /resume hook runs, then RUNNING.
	if *sleeps != 1 {
		t.Errorf("waited %d times after resuming, want 1", *sleeps)
	}
}

func TestTerminateOfAGoneMicroVMSucceedsAndOtherErrorsDont(t *testing.T) {
	m, _ := newTestMicroVMs(&fakeAPI{terminateErr: &types.ResourceNotFoundException{Message: aws.String("gone")}}, &fakeDoer{})
	if err := m.Terminate(t.Context(), VM{ID: "mvm-1"}); err != nil {
		t.Errorf("Terminate of a gone MicroVM = %v, want nil", err)
	}
	denied := errors.New("denied")
	m, _ = newTestMicroVMs(&fakeAPI{terminateErr: denied}, &fakeDoer{})
	if err := m.Terminate(t.Context(), VM{ID: "mvm-1"}); !errors.Is(err, denied) {
		t.Errorf("Terminate = %v, want the error wrapped", err)
	}
}

func TestWaitStopsWhenTheContextEnds(t *testing.T) {
	api := &fakeAPI{states: []types.MicrovmState{types.MicrovmStatePending}}
	m := NewMicroVMs(api, &fakeDoer{}, testConfig)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := m.waitRunning(ctx, "mvm-1"); !errors.Is(err, context.Canceled) {
		t.Errorf("waitRunning = %v, want context.Canceled", err)
	}
}
