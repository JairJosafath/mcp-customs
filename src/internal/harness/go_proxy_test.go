package harness

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/module"

	"github.com/JairJosafath/mcp-customs/src/internal/demoproxy"
)

func TestTheChecksumDatabaseIsSkippedForTheDemoModulesOnly(t *testing.T) {
	if env := goProxyEnv(""); env != nil {
		t.Errorf("no list: %v, want Go's defaults", env)
	}
	env := goProxyEnv("https://demo.example/goproxy,https://proxy.golang.org")
	if len(env) != 2 || env[0] != "GOPROXY=https://demo.example/goproxy,https://proxy.golang.org" {
		t.Fatalf("env %v, want GOPROXY and GONOSUMDB", env)
	}
	noSumDB, ok := strings.CutPrefix(env[1], "GONOSUMDB=")
	if !ok {
		t.Fatalf("%q is not GONOSUMDB", env[1])
	}
	cases := map[string]bool{
		demoproxy.ModulePrefix + "/mail":            true,
		demoproxy.ModulePrefix + "/weather":         true,
		"github.com/JairJosafath/mcp-customs/src":   false,
		"github.com/JairJosafath/mcp-customs":       false,
		"github.com/JairJosafath/mcp-customs/demo2": false,
		"github.com/acme/weather":                   false,
	}
	for path, skipped := range cases {
		if module.MatchPrefixPatterns(noSumDB, path) != skipped {
			t.Errorf("%s: checksum database skipped %v, want %v", path, !skipped, skipped)
		}
	}
}

// connectRecorder is an HTTPS proxy that lets nothing through and keeps
// the host of every tunnel asked of it: every request outside the test.
type connectRecorder struct {
	mu    sync.Mutex
	hosts []string
}

func (c *connectRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.hosts = append(c.hosts, r.Host)
	c.mu.Unlock()
	http.Error(w, "no", http.StatusForbidden)
}

func (c *connectRecorder) asked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.hosts...)
}

func TestAGoInstallOfADemoResolvesThroughTheDemoProxyAndBuildsThatVersion(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("needs go on the PATH")
	}
	mail := demoproxy.ModulePrefix + "/mail"
	cases := []struct {
		version string
		copied  bool
	}{
		{"v1.0.0", false},
		{"v1.0.1", true},
	}
	// One build cache for both installs: the second builds only what differs.
	cache := t.TempDir()
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			files, err := demoproxy.Files(os.DirFS("../.."), c.version)
			if err != nil {
				t.Fatal(err)
			}
			demo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, ok := files[strings.TrimPrefix(r.URL.Path, "/goproxy/")]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(body)
			}))
			defer demo.Close()
			outside := &connectRecorder{}
			gate := httptest.NewServer(outside)
			defer gate.Close()

			// The sandbox's environment, as the harness makes it, with every
			// HTTPS request outside the test sent to the recorder.
			home := t.TempDir()
			w := filepath.Join(home, "work")
			a := Account{Name: "dev", Home: home}
			env := a.env(os.Getenv("PATH"), append([]string{
				"TMPDIR=" + home,
				"HTTPS_PROXY=" + gate.URL,
				"GOPATH=" + filepath.Join(w, ".go"),
				"GOBIN=" + filepath.Join(w, "bin"),
				"GOCACHE=" + cache,
				"GOFLAGS=-modcacherw",
			}, goProxyEnv(demo.URL+"/goproxy,https://proxy.golang.org")...)...)
			if err := os.Mkdir(w, 0o700); err != nil {
				t.Fatal(err)
			}
			sb := Sandbox{Workdir: w, Env: env, Run: func(ctx context.Context, args []string, out io.Writer) error {
				return a.run(ctx, w, env, args, out)
			}}
			installed, err := Toolchain{}.Install(t.Context(), Package{EcosystemGo, mail, c.version}, sb)
			if err != nil {
				t.Fatalf("install: %v\n%s", err, installed.Log)
			}
			if hosts := outside.asked(); len(hosts) != 0 {
				t.Errorf("the install reached %v outside the demo proxy", hosts)
			}
			if !strings.Contains(string(installed.Resolved), "mod "+mail+" "+c.version+" h1:") {
				t.Errorf("resolved %q, want %s %s", installed.Resolved, mail, c.version)
			}

			// The installed server, told to send a message, copies it out
			// only in v1.0.1: its default build is that version.
			cmd := exec.CommandContext(t.Context(), installed.Command[0]) //nolint:gosec // the server this test just installed
			cmd.Env = env
			cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
				`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@example.com","subject":"s","body":"b"}}}` + "\n")
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("run: %v\n%s", err, out.String())
			}
			copied := strings.Join(outside.asked(), " ") == "mail-sink.example:443"
			if copied != c.copied {
				t.Errorf("the server reached %v, want the copy to mail-sink.example %v", outside.asked(), c.copied)
			}
		})
	}
}
