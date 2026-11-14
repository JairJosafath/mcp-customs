package poller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// Registries are the base URLs the poller asks for each kind's latest
// version: an npm registry, a Go module proxy and a PyPI index.
type Registries struct {
	NPM  string
	Go   string
	PyPI string
}

// DefaultRegistries are the public ones.
var DefaultRegistries = Registries{
	NPM:  "https://registry.npmjs.org",
	Go:   "https://proxy.golang.org",
	PyPI: "https://pypi.org",
}

// The environment variables that set the registries, each optional.
const (
	EnvNPMRegistry = "NPM_REGISTRY_URL"
	EnvGoProxy     = "GO_PROXY_URL"
	EnvPyPI        = "PYPI_URL"
)

// ErrBadRegistry says a registry's URL is not an https URL with a host.
var ErrBadRegistry = errors.New("a registry must be an https:// URL with a host, and no query or fragment")

// RegistriesFrom reads the registries from the environment through
// getenv, each one unset keeping its default.
func RegistriesFrom(getenv func(string) string) (Registries, error) {
	r := DefaultRegistries
	for name, field := range map[string]*string{EnvNPMRegistry: &r.NPM, EnvGoProxy: &r.Go, EnvPyPI: &r.PyPI} {
		value := getenv(name)
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return Registries{}, fmt.Errorf("%s: %w", name, ErrBadRegistry)
		}
		*field = value
	}
	return r, nil
}

// Doer sends a request: an *http.Client.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPRegistry asks the registries over HTTPS.
type HTTPRegistry struct {
	client Doer
	bases  Registries
}

// NewHTTPRegistry returns the registries at bases, asked through client.
func NewHTTPRegistry(client Doer, bases Registries) *HTTPRegistry {
	return &HTTPRegistry{client: client, bases: bases}
}

// maxAnswer bounds a registry's answer: PyPI's names every release.
const maxAnswer = 16 << 20

// ErrUnknownKind says the poller has no registry for a kind.
var ErrUnknownKind = errors.New("no registry for this kind")

// Latest answers the latest version of package name of kind.
func (r *HTTPRegistry) Latest(ctx context.Context, kind, name string) (string, error) {
	var (
		u       string
		version func([]byte) (string, error)
	)
	switch kind {
	case "npm":
		// A scoped name's slash is escaped: @scope%2Fname.
		u, version = strings.TrimSuffix(r.bases.NPM, "/")+"/"+url.PathEscape(name)+"/latest", field("version")
	case "go":
		u, version = strings.TrimSuffix(r.bases.Go, "/")+"/"+escapeModule(name)+"/@latest", field("Version")
	case "pypi":
		u, version = strings.TrimSuffix(r.bases.PyPI, "/")+"/pypi/"+url.PathEscape(name)+"/json", pypiVersion
	default:
		return "", fmt.Errorf("%q: %w", kind, ErrUnknownKind)
	}
	body, err := r.get(ctx, u)
	if err != nil {
		return "", err
	}
	v, err := version(body)
	if err != nil {
		return "", fmt.Errorf("read the latest version of %s package %s: %w", kind, name, err)
	}
	return v, nil
}

// get answers the body of u, and ErrNotPublished for a 404 or a 410.
func (r *HTTPRegistry) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("make the request to %s: %w", u, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ask %s: %w", req.URL.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return nil, ErrNotPublished
	default:
		return nil, fmt.Errorf("%s answered %d: %w", req.URL.Host, resp.StatusCode, ErrRegistryFailed)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("read the answer of %s: %w", req.URL.Host, err)
	}
	if len(body) > maxAnswer {
		return nil, fmt.Errorf("%s answered more than %d MB: %w", req.URL.Host, maxAnswer>>20, ErrRegistryFailed)
	}
	return body, nil
}

// ErrRegistryFailed says a registry answered something other than a version.
var ErrRegistryFailed = errors.New("the registry did not answer a version")

// field reads the version from the top-level string field name.
func field(name string) func([]byte) (string, error) {
	return func(body []byte) (string, error) {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(body, &doc); err != nil {
			return "", fmt.Errorf("%w: %w", ErrRegistryFailed, err)
		}
		return versionIn(doc[name])
	}
}

// pypiVersion reads PyPI's info.version.
func pypiVersion(body []byte) (string, error) {
	var doc struct {
		Info struct {
			Version json.RawMessage `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("%w: %w", ErrRegistryFailed, err)
	}
	return versionIn(doc.Info.Version)
}

// versionIn reads raw as a version: a non-empty JSON string.
func versionIn(raw json.RawMessage) (string, error) {
	var v string
	if err := json.Unmarshal(raw, &v); err != nil || v == "" {
		return "", ErrRegistryFailed
	}
	return v, nil
}

// escapeModule is a module path as the module proxy protocol has it: each
// capital letter as "!" and its lower case. A path the harness accepted
// has nothing else to escape.
func escapeModule(path string) string {
	var b strings.Builder
	for _, c := range path {
		if unicode.IsUpper(c) {
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(c))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}
