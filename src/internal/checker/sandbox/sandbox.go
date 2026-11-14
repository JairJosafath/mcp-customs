// Package sandbox is the Checker's side of the sandbox: it launches one
// Lambda MicroVM per check from the harness image, calls the Harness API
// (docs/contracts.md) over the MicroVM's HTTPS endpoint, and suspends,
// resumes and terminates it. Client is what the Checker uses; MicroVMs is
// the AWS implementation and Fake the one tests use.
package sandbox

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Client runs a check's sandbox.
type Client interface {
	// Launch starts a MicroVM for one check and returns once its harness
	// has the run's token and canaries and can be called.
	Launch(ctx context.Context, in Launch) (VM, error)
	// Call sends one Harness API request to the VM and answers the
	// harness's status and JSON body. A body of nil sends no body.
	Call(ctx context.Context, vm VM, req Request) (Response, error)
	// Suspend keeps the VM's memory and disk and stops its compute.
	Suspend(ctx context.Context, vm VM) error
	// Resume brings a suspended VM back and returns once it can be called.
	Resume(ctx context.Context, vm VM) error
	// Terminate ends the VM and releases everything it held.
	Terminate(ctx context.Context, vm VM) error
}

// Canary is one planted fake secret, in the shape internal/canary makes.
type Canary struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Launch is what a MicroVM starts with.
type Launch struct {
	// IdempotencyKey makes a retried launch return the first one's VM
	// rather than start a second: the check's id and its attempt.
	IdempotencyKey string
	// Token is the run's bearer token, which the harness then requires on
	// every call (NewRunToken).
	Token string
	// Canaries fill the fake developer home before anything is installed.
	Canaries []Canary
}

// VM is a running sandbox: what the Checker keeps between steps.
type VM struct {
	ID string `json:"id"`
	// Endpoint is the MicroVM's HTTPS host name, without a scheme.
	Endpoint string `json:"endpoint"`
	// Token is the run's bearer token. It is a secret: never log it.
	Token string `json:"token"`
}

// Request is one Harness API call.
type Request struct {
	Method string
	// Path is the Harness API route, such as /install.
	Path string
	// Body is marshalled to JSON; nil sends no body.
	Body any
}

// Response is what the harness answered.
type Response struct {
	Status int
	Body   json.RawMessage
}

// The largest run hook payload Lambda accepts, in bytes.
const maxRunHookPayload = 16 * 1024

// ErrBadLaunch says a launch is missing what the harness needs.
var ErrBadLaunch = errors.New("a launch needs an idempotency key of 1 to 64 characters, a run token and at least one canary")

// ErrPayloadTooLarge says the token and canaries don't fit in Lambda's
// 16 KB run hook payload.
var ErrPayloadTooLarge = errors.New("the run token and canaries are larger than the 16 KB run hook payload")

// ErrBadRequest says a Harness API call names no route.
var ErrBadRequest = errors.New("a harness call needs a method and a path starting with /")

// runHookPayload is what the harness's /run hook receives, as a string,
// in the `runHookPayload` field of the body Lambda posts.
type runHookPayload struct {
	Token    string   `json:"token"`
	Canaries []Canary `json:"canaries"`
}

// encodeRunHookPayload checks in and encodes the token and canaries for
// the /run hook.
func encodeRunHookPayload(in Launch) (string, error) {
	if in.IdempotencyKey == "" || len(in.IdempotencyKey) > 64 || in.Token == "" || len(in.Canaries) == 0 {
		return "", ErrBadLaunch
	}
	b, err := json.Marshal(runHookPayload{Token: in.Token, Canaries: in.Canaries})
	if err != nil {
		return "", fmt.Errorf("encode the run hook payload: %w", err)
	}
	if len(b) > maxRunHookPayload {
		return "", ErrPayloadTooLarge
	}
	return string(b), nil
}

// validRequest says whether req names a Harness API route.
func validRequest(req Request) bool {
	return req.Method != "" && strings.HasPrefix(req.Path, "/")
}

// NewRunToken makes a fresh bearer token for one run: 32 random bytes,
// base64url. Each MicroVM gets its own, so one sandbox's token opens no
// other.
func NewRunToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes for a run token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// derivationLabel keeps run tokens apart from anything else the key might
// one day derive.
const derivationLabel = "mcp-customs run token v1\x00"

// DeriveRunToken is check checkID's run token: HMAC-SHA256 of the check's
// id under key, base64url. The same key and id give the same token, so a
// replayed execution derives it again instead of keeping it; a token
// opens no other check's sandbox, and without the key none can be made.
func DeriveRunToken(key []byte, checkID string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(derivationLabel + checkID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
