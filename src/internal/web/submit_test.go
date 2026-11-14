package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

func TestPostAPIChecksStartsTheCheckerAndAnswersTheCheckID(t *testing.T) {
	for name, s := range map[string]store.Submission{
		"a Go module":        {Kind: "go", Ref: "github.com/acme/weather-mcp@v1.2.3"},
		"an npm package":     {Kind: "npm", Ref: "@acme/weather-mcp@1.0.0"},
		"a PyPI package":     {Kind: "pypi", Ref: "weather-mcp@1.0.0"},
		"a remote server":    {Kind: "remote", Ref: "https://mcp.example.com/sse?team=a"},
		"a public address":   {Kind: "remote", Ref: "https://93.184.215.14:8443/mcp"},
		"a public IPv6":      {Kind: "remote", Ref: "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/mcp"},
		"a name with digits": {Kind: "remote", Ref: "https://mcp1.example.com/"},
	} {
		f := newFixture(t)
		in, _ := json.Marshal(s)
		resp := f.answer(t, jsonPost(string(in)))
		var out struct {
			CheckID string `json:"checkId"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &out); err != nil || resp.StatusCode != http.StatusAccepted || out.CheckID != "check-1" {
			t.Errorf("%s: = %d %s, want 202 check-1", name, resp.StatusCode, resp.Body)
		}
		if resp.Headers["location"] != "/api/checks/check-1" {
			t.Errorf("%s: location %q", name, resp.Headers["location"])
		}
		if len(f.checker.started) != 1 || f.checker.started[0] != (started{"check-1", s}) {
			t.Errorf("%s: started %v, want check-1 of %v", name, f.checker.started, s)
		}
	}
}

func TestPostAPIChecksAnswers400WithAMessageForBadInput(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"an unknown kind":                {`{"kind":"cargo","ref":"x@1.0.0"}`, `The kind must be "go", "npm", "pypi" or "remote".`},
		"no kind":                        {`{"ref":"x@1.0.0"}`, `The kind must be "go", "npm", "pypi" or "remote".`},
		"no ref":                         {`{"kind":"npm","ref":""}`, "The ref must be 1 to 512 characters."},
		"a ref too long":                 {`{"kind":"npm","ref":"` + strings.Repeat("a", 510) + `@1.0.0"}`, "The ref must be 1 to 512 characters."},
		"an npm tag":                     {`{"kind":"npm","ref":"weather-mcp@latest"}`, "The ref of an npm package must be its name pinned to one version, such as weather-mcp@1.0.0."},
		"an npm range":                   {`{"kind":"npm","ref":"weather-mcp@^1.0.0"}`, "The ref of an npm package must be its name pinned to one version, such as weather-mcp@1.0.0."},
		"no version":                     {`{"kind":"pypi","ref":"weather-mcp"}`, "The ref of a PyPI package must be its name pinned to one version, such as weather-mcp@1.0.0."},
		"a Go module at a tag":           {`{"kind":"go","ref":"github.com/acme/x@main"}`, "The ref of a Go module must be its name pinned to one version, such as github.com/acme/weather-mcp@v1.2.3."},
		"a name read as a flag":          {`{"kind":"npm","ref":"--global@1.0.0"}`, "The ref of an npm package must be its name pinned to one version, such as weather-mcp@1.0.0."},
		"plain http":                     {`{"kind":"remote","ref":"http://mcp.example.com/"}`, sentence(errBadURL)},
		"a URL with a password":          {`{"kind":"remote","ref":"https://u:p@mcp.example.com/"}`, sentence(errBadURL)},
		"a URL with no host":             {`{"kind":"remote","ref":"https:///sse"}`, sentence(errBadURL)},
		"a URL with a space":             {`{"kind":"remote","ref":"https://mcp.example.com/a b"}`, sentence(errBadURL)},
		"a URL with hidden text":         {`{"kind":"remote","ref":"https://mcp.example.com/\u200B"}`, sentence(errBadURL)},
		"localhost":                      {`{"kind":"remote","ref":"https://localhost:8080/mcp"}`, sentence(errNotPublic)},
		"a name under localhost":         {`{"kind":"remote","ref":"https://api.localhost/mcp"}`, sentence(errNotPublic)},
		"a single label":                 {`{"kind":"remote","ref":"https://intranet/mcp"}`, sentence(errNotPublic)},
		"the instance metadata":          {`{"kind":"remote","ref":"https://169.254.169.254/latest/meta-data/"}`, sentence(errNotPublic)},
		"a link-local address":           {`{"kind":"remote","ref":"https://169.254.10.1/"}`, sentence(errNotPublic)},
		"loopback":                       {`{"kind":"remote","ref":"https://127.0.0.1/"}`, sentence(errNotPublic)},
		"another loopback":               {`{"kind":"remote","ref":"https://127.1.2.3:443/"}`, sentence(errNotPublic)},
		"this network":                   {`{"kind":"remote","ref":"https://0.0.0.0/"}`, sentence(errNotPublic)},
		"a private 10/8 address":         {`{"kind":"remote","ref":"https://10.0.0.5/"}`, sentence(errNotPublic)},
		"a private 172.16/12 address":    {`{"kind":"remote","ref":"https://172.31.255.1/"}`, sentence(errNotPublic)},
		"a private 192.168/16 address":   {`{"kind":"remote","ref":"https://192.168.1.1/"}`, sentence(errNotPublic)},
		"a shared address":               {`{"kind":"remote","ref":"https://100.64.0.1/"}`, sentence(errNotPublic)},
		"IPv6 loopback":                  {`{"kind":"remote","ref":"https://[::1]/"}`, sentence(errNotPublic)},
		"IPv6 link-local":                {`{"kind":"remote","ref":"https://[fe80::1]/"}`, sentence(errNotPublic)},
		"IPv6 unique local":              {`{"kind":"remote","ref":"https://[fd00::1]/"}`, sentence(errNotPublic)},
		"the IPv6 instance metadata":     {`{"kind":"remote","ref":"https://[fd00:ec2::254]/"}`, sentence(errNotPublic)},
		"IPv4 mapped into IPv6":          {`{"kind":"remote","ref":"https://[::ffff:169.254.169.254]/"}`, sentence(errNotPublic)},
		"IPv4 translated into IPv6":      {`{"kind":"remote","ref":"https://[64:ff9b::a9fe:a9fe]/"}`, sentence(errNotPublic)},
		"a decimal address":              {`{"kind":"remote","ref":"https://2130706433/"}`, sentence(errNotPublic)},
		"a hex address":                  {`{"kind":"remote","ref":"https://0x7f.0x1/"}`, sentence(errNotPublic)},
		"a dotted name of numbers":       {`{"kind":"remote","ref":"https://127.1/"}`, sentence(errNotPublic)},
		"a metadata name":                {`{"kind":"remote","ref":"https://metadata.google.internal/"}`, sentence(errNotPublic)},
		"an internal name":               {`{"kind":"remote","ref":"https://ip-10-0-0-1.ec2.internal/"}`, sentence(errNotPublic)},
		"a trailing dot after localhost": {`{"kind":"remote","ref":"https://localhost./"}`, sentence(errNotPublic)},
		"an upper-case localhost":        {`{"kind":"remote","ref":"https://LOCALHOST/"}`, sentence(errNotPublic)},
		"not JSON":                       {`kind=npm`, `The body must be one JSON object: {"kind":"npm","ref":"weather-mcp@1.0.0"}.`},
		"an unknown field":               {`{"kind":"npm","ref":"x@1.0.0","force":true}`, `The body must be one JSON object: {"kind":"npm","ref":"weather-mcp@1.0.0"}.`},
		"two objects":                    {`{"kind":"npm","ref":"x@1.0.0"}{}`, `The body must be one JSON object: {"kind":"npm","ref":"weather-mcp@1.0.0"}.`},
		"a body too large":               {`{"kind":"npm","ref":"` + strings.Repeat("a", maxBody) + `"}`, "The body is too large or not base64."},
	} {
		f := newFixture(t)
		resp := f.answer(t, jsonPost(tc.body))
		var out struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal([]byte(resp.Body), &out)
		if resp.StatusCode != http.StatusBadRequest || out.Message != tc.want {
			t.Errorf("%s: = %d %q, want 400 %q", name, resp.StatusCode, out.Message, tc.want)
		}
		if len(f.checker.started) != 0 {
			t.Errorf("%s: started %v", name, f.checker.started)
		}
	}
}

func TestPostAPIChecksWantsJSON(t *testing.T) {
	f := newFixture(t)
	req := jsonPost(`{"kind":"npm","ref":"x@1.0.0"}`)
	req.Headers["content-type"] = "text/plain"
	if resp := f.answer(t, req); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("= %d %s, want 415", resp.StatusCode, resp.Body)
	}
}

func TestPostAPIChecksReadsABase64Body(t *testing.T) {
	f := newFixture(t)
	req := jsonPost(base64.StdEncoding.EncodeToString([]byte(`{"kind":"npm","ref":"x@1.0.0"}`)))
	req.IsBase64Encoded = true
	req.Headers = map[string]string{"Content-Type": "application/json; charset=utf-8"}
	if resp := f.answer(t, req); resp.StatusCode != http.StatusAccepted || len(f.checker.started) != 1 {
		t.Errorf("= %d %s", resp.StatusCode, resp.Body)
	}
}

func TestPostAPIChecksWithAnIdempotencyKeyAnswersTheSameCheckTwice(t *testing.T) {
	f := newFixture(t)
	ids := map[string]bool{}
	for range 2 {
		req := jsonPost(`{"kind":"npm","ref":"x@1.0.0"}`)
		req.Headers["idempotency-key"] = "retry-1"
		resp := f.answer(t, req)
		var out struct {
			CheckID string `json:"checkId"`
		}
		_ = json.Unmarshal([]byte(resp.Body), &out)
		if resp.StatusCode != http.StatusAccepted || !store.ValidCheckID(out.CheckID) {
			t.Fatalf("= %d %s", resp.StatusCode, resp.Body)
		}
		ids[out.CheckID] = true
	}
	if len(ids) != 1 || len(f.checker.started) != 2 || f.checker.started[0] != f.checker.started[1] {
		t.Errorf("ids %v, started %v; want one check, started twice under one name", ids, f.checker.started)
	}
}

func TestPostAPIChecksRefusesAnIdempotencyKeyReusedForAnotherSubmission(t *testing.T) {
	f := newFixture(t)
	for i, body := range []string{`{"kind":"npm","ref":"x@1.0.0"}`, `{"kind":"npm","ref":"x@1.0.1"}`} {
		req := jsonPost(body)
		req.Headers["Idempotency-Key"] = "retry-1"
		want := []int{http.StatusAccepted, http.StatusConflict}[i]
		if resp := f.answer(t, req); resp.StatusCode != want {
			t.Errorf("%s: = %d %s, want %d", body, resp.StatusCode, resp.Body, want)
		}
	}
	if len(f.checker.started) != 1 {
		t.Errorf("started %v, want only the first", f.checker.started)
	}
}

func TestPostAPIChecksRefusesABadIdempotencyKey(t *testing.T) {
	for _, key := range []string{"", strings.Repeat("k", maxIdempotencyKey+1), "tab\there", "caf\u00e9"} {
		f := newFixture(t)
		req := jsonPost(`{"kind":"npm","ref":"x@1.0.0"}`)
		req.Headers["idempotency-key"] = key
		if resp := f.answer(t, req); resp.StatusCode != http.StatusBadRequest || len(f.checker.started) != 0 {
			t.Errorf("%q: = %d %s, started %v", key, resp.StatusCode, resp.Body, f.checker.started)
		}
	}
}

func TestPostAPIChecksAnswersAConflictAndAFailedStart(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"a name taken by another submission": {ErrAlreadyStarted, http.StatusConflict},
		"Lambda failing":                     {errors.New("throttled"), http.StatusInternalServerError},
	} {
		f := newFixture(t)
		f.checker.startErr = tc.err
		if resp := f.answer(t, jsonPost(`{"kind":"npm","ref":"x@1.0.0"}`)); resp.StatusCode != tc.want {
			t.Errorf("%s: = %d %s, want %d", name, resp.StatusCode, resp.Body, tc.want)
		}
	}
}

func TestTheFormOnTheHomePageStartsACheckAndGoesToItsPage(t *testing.T) {
	f := newFixture(t)
	resp := f.answer(t, formPost("/checks", url.Values{"kind": {"npm"}, "ref": {" weather-mcp@1.0.0 "}}))
	if resp.StatusCode != http.StatusSeeOther || resp.Headers["location"] != "/checks/check-1" {
		t.Errorf("= %d %v, want 303 to /checks/check-1", resp.StatusCode, resp.Headers)
	}
	want := started{"check-1", store.Submission{Kind: "npm", Ref: "weather-mcp@1.0.0"}}
	if len(f.checker.started) != 1 || f.checker.started[0] != want {
		t.Errorf("started %v, want %v", f.checker.started, want)
	}
}

func TestTheFormShowsBadInputAgainWith400AndAMessage(t *testing.T) {
	f := newFixture(t)
	resp := f.answer(t, formPost("/checks", url.Values{"kind": {"npm"}, "ref": {`"><script>alert(1)</script>@latest`}}))
	if resp.StatusCode != http.StatusBadRequest || resp.Headers["content-type"] != "text/html; charset=utf-8" {
		t.Errorf("= %d %v, want a 400 page", resp.StatusCode, resp.Headers)
	}
	if !strings.Contains(resp.Body, "The ref of an npm package must be its name pinned to one version") {
		t.Errorf("the page lacks the message: %s", resp.Body)
	}
	if strings.Contains(resp.Body, "<script>alert") || !strings.Contains(resp.Body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("the ref is not shown escaped: %s", resp.Body)
	}
	if len(f.checker.started) != 0 {
		t.Errorf("started %v", f.checker.started)
	}
}

func TestTheFormOffersTheKindSubmittedLastFirst(t *testing.T) {
	resp := newFixture(t).answer(t, formPost("/checks", url.Values{"kind": {"go"}, "ref": {"x"}}))
	if first, npm := strings.Index(resp.Body, `value="go"`), strings.Index(resp.Body, `value="npm"`); first < 0 || first > npm {
		t.Errorf("go is not first: %s", resp.Body)
	}
}
