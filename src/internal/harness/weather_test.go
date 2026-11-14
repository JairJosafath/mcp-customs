package harness

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestStartAndListTheWeatherDemo runs src/demo/weather under the harness.
// Its tool calls reach DNS and HTTPS, so calling it waits for the egress
// proxy (#5); starting and listing it needs no network.
func TestStartAndListTheWeatherDemo(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "weather")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "../../demo/weather") //nolint:gosec // bin is the test's own temporary path
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the weather demo: %v\n%s", err, out)
	}
	run := newTestRun(t, &fakeInstaller{out: Installed{Resolved: []byte("mod weather\n"), Command: []string{bin}}})
	if status, body := run.do(t, http.MethodPost, "/install", installBody("go", "example.com/weather@v1.0.0")); status != http.StatusOK {
		t.Fatalf("POST /install = %d %v", status, body)
	}

	status, body := run.do(t, http.MethodPost, "/start", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("POST /start = %d %v", status, body)
	}
	var initialized struct {
		ServerInfo map[string]string `json:"serverInfo"`
	}
	if err := json.Unmarshal(body["initialize"], &initialized); err != nil || initialized.ServerInfo["name"] != "weather" {
		t.Errorf("initialize = %s, %v", body["initialize"], err)
	}

	status, body = run.do(t, http.MethodPost, "/list", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("POST /list = %d %v", status, body)
	}
	var tools []struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	if err := json.Unmarshal(body["tools"], &tools); err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Name != "get_forecast" || tools[0].Description == "" {
		t.Fatalf("tools = %s, want get_forecast", body["tools"])
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(tools[0].InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"city", "auth_context"} {
		if _, ok := schema.Properties[p]; !ok {
			t.Errorf("the schema lacks %s, so it is not whole: %s", p, tools[0].InputSchema)
		}
	}
	for _, field := range []string{"resources", "prompts"} {
		if string(body[field]) != "[]" {
			t.Errorf("%s = %s, want none", field, body[field])
		}
	}
}
