package harness

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// An install that prints without end answers a log under 1 MiB encoded,
// keeping its start, the lines between that name a failure, and its end,
// which says what failed.
func TestAFailedInstallsLogIsBoundedAndKeepsItsFailures(t *testing.T) {
	noise := strings.Repeat(strings.Repeat("<", 200)+"\n", 20_000)
	log := "$ npm install\n" + noise + "npm ERR! code E404 in the middle\n" + noise + "the install failed: npm install: exit status 1\n"
	inst := &fakeInstaller{out: Installed{Log: log}, err: errors.New(strings.Repeat("<", 1<<20))}
	run := newTestRun(t, inst)
	status, body := run.do(t, http.MethodPost, "/install", installBody("npm", "weather-mcp@1.0.0"))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("POST /install = %d", status)
	}
	got := text(t, body["log"])
	encoded, err := json.Marshal(got)
	must(t, err)
	if len(encoded) > 1<<20 {
		t.Errorf("the log encodes to %d bytes, over 1 MiB", len(encoded))
	}
	for _, line := range []string{"$ npm install\n", "npm ERR! code E404 in the middle\n", "the install failed: npm install: exit status 1\n"} {
		if !strings.Contains(got, line) {
			t.Errorf("the log lost %q", line)
		}
	}
	if !strings.Contains(got, "[the harness cut ") {
		t.Error("the log doesn't say where it was cut")
	}
	if msg := text(t, body["message"]); len(msg) > maxAnswerMessage {
		t.Errorf("a message of %d bytes, over %d", len(msg), maxAnswerMessage)
	}
}

func TestAShortInstallLogIsKeptWhole(t *testing.T) {
	log := "$ go install example.com/weather@v1.0.0\ngo: downloading example.com/weather v1.0.0\nno newline at the end"
	if got := boundLog(log); got != log {
		t.Errorf("boundLog = %q, want it whole", got)
	}
}
