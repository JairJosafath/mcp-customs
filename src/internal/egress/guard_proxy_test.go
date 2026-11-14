package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// guardedProxy is a proxy whose upstream transport dials through a Guard
// that records each address it dials and connects to none. The API's
// demo Go proxy is its InstallGet prefix; relay.attacker.net, allowed,
// resolves to the API's address.
func guardedProxy(dialed *[]string) *Egress {
	const api = "abc123.execute-api.eu-west-1.amazonaws.com"
	g := testGuard(map[string][][]string{
		api:                   {{"3.248.245.10"}},
		"relay.attacker.net":  {{"3.248.245.10"}},
		"api.weather.example": {{"198.51.100.7"}},
	}, dialed)
	g.Dial = func(_ context.Context, _, address string) (net.Conn, error) {
		*dialed = append(*dialed, address)
		return nil, errors.New("no network in tests")
	}
	return New(Config{
		Upstream:     &http.Transport{DialContext: g.DialContext},
		Allow:        []string{"relay.attacker.net", "api.weather.example", "abc\u00ad123.execute-api.eu-west-1.amazonaws.com"},
		InstallAllow: RegistryHosts,
		InstallGet:   []string{"https://" + api + "/goproxy/"},
	})
}

func TestTheProxyReachesTheAPIOnlyForAnInstallsGetUnderItsPrefix(t *testing.T) {
	const api = "abc123.execute-api.eu-west-1.amazonaws.com"
	for name, tc := range map[string]struct {
		installing   bool
		method, host string
		path         string
		dial         string
	}{
		"an install's GET of the demo proxy":    {true, http.MethodGet, api, "/goproxy/x/@v/list", "3.248.245.10:443"},
		"an install's POST to the API":          {true, http.MethodPost, api, "/api/checks", ""},
		"a GET of the demo proxy after":         {false, http.MethodGet, api, "/goproxy/x/@v/list", ""},
		"an allowed name for the API's address": {true, http.MethodGet, "relay.attacker.net", "/goproxy/x/@v/list", ""},
		"the API, with a soft hyphen":           {false, http.MethodPost, "abc\u00ad123.execute-api.eu-west-1.amazonaws.com", "/approve", ""},
		"the API, with ideographic full stops":  {false, http.MethodPost, "abc123\u3002execute-api\u3002eu-west-1\u3002amazonaws\u3002com", "/approve", ""},
		"the API, with a fullwidth letter":      {false, http.MethodPost, "\uff41bc123.execute-api.eu-west-1.amazonaws.com", "/approve", ""},
		"the API, in punycode":                  {false, http.MethodPost, "xn--abc123-dja.execute-api.eu-west-1.amazonaws.com", "/approve", ""},
		"an allowed host elsewhere":             {false, http.MethodGet, "api.weather.example", "/forecast", "198.51.100.7:443"},
	} {
		var dialed []string
		e := guardedProxy(&dialed)
		e.Installing(tc.installing)
		e.forward(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, strings.NewReader("{}")), "https", tc.host)
		want := []string{}
		if tc.dial != "" {
			want = []string{tc.dial}
		}
		if !slices.Equal(append([]string{}, dialed...), want) {
			t.Errorf("%s: dialed %v, want %v", name, dialed, want)
		}
	}
}

func TestTheAllowlistKeepsOnlyPlainASCIINames(t *testing.T) {
	var dialed []string
	if got := guardedProxy(&dialed).Allow(); !slices.Equal(got, []string{"api.weather.example", "relay.attacker.net"}) {
		t.Errorf("allowlist %v, want the plain ASCII names alone", got)
	}
}

// closeRecorder records whether each request it is sent asks to close
// its connection.
type closeRecorder struct{ closes []bool }

func (c *closeRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	c.closes = append(c.closes, r.Close)
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
}

func TestAnInstallsGetKeepsNoConnectionForAnotherRequest(t *testing.T) {
	const api = "abc123.execute-api.eu-west-1.amazonaws.com"
	up := &closeRecorder{}
	e := New(Config{Upstream: up, Allow: []string{"api.weather.example"}, InstallGet: []string{"https://" + api + "/goproxy/"}})
	e.Installing(true)
	e.forward(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/goproxy/x/@v/list", nil), "https", api)
	e.forward(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/forecast", nil), "https", "api.weather.example")
	if !slices.Equal(up.closes, []bool{true, false}) {
		t.Errorf("closes %v, want the install's GET alone to close its connection", up.closes)
	}
}
