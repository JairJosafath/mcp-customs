package poller

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestTheRegistryOfEachKindAnswersItsLatestVersion(t *testing.T) {
	doer := &fakeDoer{answers: map[string]fakeAnswer{
		"https://registry.npmjs.org/@acme%2Fweather-mcp/latest":            {http.StatusOK, `{"name":"@acme/weather-mcp","version":"1.0.1"}`},
		"https://proxy.golang.org/github.com/!jair!josafath/mail/@latest":  {http.StatusOK, `{"Version":"v1.0.1","Time":"2026-11-14T10:00:00Z"}`},
		"https://pypi.org/pypi/weather-mcp/json":                           {http.StatusOK, `{"info":{"name":"weather-mcp","version":"2.1"},"releases":{}}`},
		"https://npm.internal.example/registry/mail-mcp/latest":            {http.StatusOK, `{"version":"0.2.0"}`},
		"https://registry.npmjs.org/weather-mcp/latest":                    {http.StatusOK, `{"version":"3.0.0"}`},
		"https://proxy.golang.org/github.com/jairjosafath/lower/@latest":   {http.StatusOK, `{"Version":"v2.0.0"}`},
		"https://pypi.org/pypi/mail_mcp/json":                              {http.StatusOK, `{"info":{"version":"0.9"}}`},
		"https://registry.npmjs.org/@acme%2Fweather-mcp/latest?unexpected": {http.StatusOK, `{"version":"9"}`},
	}}
	for _, tc := range []struct {
		bases            Registries
		kind, name, want string
	}{
		{DefaultRegistries, "npm", "@acme/weather-mcp", "1.0.1"},
		{DefaultRegistries, "npm", "weather-mcp", "3.0.0"},
		{DefaultRegistries, "go", "github.com/JairJosafath/mail", "v1.0.1"},
		{DefaultRegistries, "go", "github.com/jairjosafath/lower", "v2.0.0"},
		{DefaultRegistries, "pypi", "weather-mcp", "2.1"},
		{DefaultRegistries, "pypi", "mail_mcp", "0.9"},
		{Registries{NPM: "https://npm.internal.example/registry/"}, "npm", "mail-mcp", "0.2.0"},
	} {
		got, err := NewHTTPRegistry(doer, tc.bases).Latest(t.Context(), tc.kind, tc.name)
		if err != nil || got != tc.want {
			t.Errorf("Latest(%s, %s) = %q, %v; want %q", tc.kind, tc.name, got, err, tc.want)
		}
	}
}

func TestARegistryThatAnswersNoVersionIsAnError(t *testing.T) {
	const u = "https://registry.npmjs.org/mail-mcp/latest"
	for name, tc := range map[string]struct {
		answer fakeAnswer
		want   error
	}{
		"not found":        {fakeAnswer{http.StatusNotFound, `{}`}, ErrNotPublished},
		"unpublished":      {fakeAnswer{http.StatusGone, `{}`}, ErrNotPublished},
		"a server error":   {fakeAnswer{http.StatusBadGateway, `<html>`}, ErrRegistryFailed},
		"not JSON":         {fakeAnswer{http.StatusOK, `<html>`}, ErrRegistryFailed},
		"no version":       {fakeAnswer{http.StatusOK, `{"name":"mail-mcp"}`}, ErrRegistryFailed},
		"an empty version": {fakeAnswer{http.StatusOK, `{"version":""}`}, ErrRegistryFailed},
		"a number":         {fakeAnswer{http.StatusOK, `{"version":1}`}, ErrRegistryFailed},
		"too large":        {fakeAnswer{http.StatusOK, `{"version":"1","pad":"` + strings.Repeat("x", maxAnswer) + `"}`}, ErrRegistryFailed},
	} {
		doer := &fakeDoer{answers: map[string]fakeAnswer{u: tc.answer}}
		if _, err := NewHTTPRegistry(doer, DefaultRegistries).Latest(t.Context(), "npm", "mail-mcp"); !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v, want %v", name, err, tc.want)
		}
	}
	unreachable := &fakeDoer{err: errors.New("dial tcp: i/o timeout")}
	if _, err := NewHTTPRegistry(unreachable, DefaultRegistries).Latest(t.Context(), "npm", "mail-mcp"); err == nil {
		t.Error("an unreachable registry answered no error")
	}
	if _, err := NewHTTPRegistry(unreachable, DefaultRegistries).Latest(t.Context(), "remote", "https://x.example/"); !errors.Is(err, ErrUnknownKind) {
		t.Errorf("a remote server: error %v, want %v", err, ErrUnknownKind)
	}
	if len(unreachable.asked) != 1 {
		t.Errorf("asked %v, want no request for a remote server", unreachable.asked)
	}
}

func TestEachRegistryIsASettingWithAWorkingDefault(t *testing.T) {
	got, err := RegistriesFrom(func(string) string { return "" })
	if err != nil || got != DefaultRegistries {
		t.Errorf("unset: %+v, %v; want the defaults", got, err)
	}
	env := map[string]string{EnvNPMRegistry: "https://npm.internal.example/registry", EnvPyPI: "https://pypi.internal.example"}
	got, err = RegistriesFrom(func(name string) string { return env[name] })
	want := Registries{NPM: env[EnvNPMRegistry], Go: DefaultRegistries.Go, PyPI: env[EnvPyPI]}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("set: %+v, %v; want %+v", got, err, want)
	}
	list := "https://demo.example/goproxy,https://proxy.golang.org"
	got, err = RegistriesFrom(func(name string) string { return map[string]string{EnvGoProxy: list}[name] })
	if err != nil || got.Go != list {
		t.Errorf("a GOPROXY list: %+v, %v; want Go %q", got, err, list)
	}
	for _, bad := range []string{"https://demo.example,direct", "https://demo.example,", "http://npm.example", "npm.example", "https://", "https://u:p@npm.example", "https://npm.example/?x=1", "https://npm.example/#x"} {
		if _, err := RegistriesFrom(func(name string) string {
			if name == EnvGoProxy {
				return bad
			}
			return ""
		}); !errors.Is(err, ErrBadRegistry) || !strings.Contains(err.Error(), EnvGoProxy) {
			t.Errorf("%q: error %v, want %v naming %s", bad, err, ErrBadRegistry, EnvGoProxy)
		}
	}
}
