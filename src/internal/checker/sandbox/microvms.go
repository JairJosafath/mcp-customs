package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms/types"
)

// API is the Lambda MicroVMs calls the Checker makes; *lambdamicrovms.Client
// implements it, and tests fake it.
type API interface {
	RunMicrovm(ctx context.Context, in *lambdamicrovms.RunMicrovmInput, optFns ...func(*lambdamicrovms.Options)) (*lambdamicrovms.RunMicrovmOutput, error)
	GetMicrovm(ctx context.Context, in *lambdamicrovms.GetMicrovmInput, optFns ...func(*lambdamicrovms.Options)) (*lambdamicrovms.GetMicrovmOutput, error)
	CreateMicrovmAuthToken(ctx context.Context, in *lambdamicrovms.CreateMicrovmAuthTokenInput, optFns ...func(*lambdamicrovms.Options)) (*lambdamicrovms.CreateMicrovmAuthTokenOutput, error)
	SuspendMicrovm(ctx context.Context, in *lambdamicrovms.SuspendMicrovmInput, optFns ...func(*lambdamicrovms.Options)) (*lambdamicrovms.SuspendMicrovmOutput, error)
	ResumeMicrovm(ctx context.Context, in *lambdamicrovms.ResumeMicrovmInput, optFns ...func(*lambdamicrovms.Options)) (*lambdamicrovms.ResumeMicrovmOutput, error)
	TerminateMicrovm(ctx context.Context, in *lambdamicrovms.TerminateMicrovmInput, optFns ...func(*lambdamicrovms.Options)) (*lambdamicrovms.TerminateMicrovmOutput, error)
}

// Doer sends an HTTP request; *http.Client implements it, and tests fake it.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config names what the stack made: the image and the network connectors
// a MicroVM runs with.
type Config struct {
	// ImageARN is the harness image, arn:...:microvm-image:<name>.
	ImageARN string
	// IngressConnectorARN is Lambda's HTTP_INGRESS connector: the HTTPS
	// endpoint the Checker calls.
	IngressConnectorARN string
	// EgressConnectorARN is Lambda's INTERNET_EGRESS connector. Which hosts
	// the server under test may reach is the harness's egress proxy's
	// decision; Lambda only offers the internet or a VPC.
	EgressConnectorARN string
}

const (
	// HarnessPort is the port the Harness API listens on: the endpoint's
	// default, and the only port a Checker token opens. The lifecycle hooks
	// listen on HooksPort, which no token opens.
	HarnessPort = 8080
	// HooksPort is where the harness serves Lambda's lifecycle hooks.
	HooksPort = 9000
	// maxLifetime bounds a sandbox, running and suspended: Lambda ends it
	// even if the Checker never does. Lambda's own limit is 8 hours.
	maxLifetime = 2 * time.Hour
	// authTokenMinutes is how long an endpoint token lasts. One is made for
	// each call, so it only has to outlast the call's start.
	authTokenMinutes = 15
	// pollInterval and maxPolls bound the wait for a MicroVM to run.
	pollInterval = time.Second
	maxPolls     = 180
	// maxResponseBytes bounds what a harness answer may hold.
	maxResponseBytes = 16 << 20
)

// ErrNotRunning says a MicroVM ended, or never reached RUNNING, while the
// Checker waited for it.
var ErrNotRunning = errors.New("the MicroVM did not reach RUNNING")

// ErrNotJSON says the endpoint answered something other than the harness's
// JSON: Lambda's own 403 or 502, for instance.
var ErrNotJSON = errors.New("the MicroVM endpoint answered without JSON")

// ErrTooLarge says the harness answered more than maxResponseBytes: the
// answer is not read, so whether it was JSON is unknown.
var ErrTooLarge = errors.New("the MicroVM endpoint answered more than 16 MiB")

// MicroVMs is the Client on AWS Lambda MicroVMs.
type MicroVMs struct {
	api   API
	http  Doer
	cfg   Config
	sleep func(ctx context.Context, d time.Duration) error
}

// NewMicroVMs is the Client that launches cfg's image through api and calls
// the harness through httpc.
func NewMicroVMs(api API, httpc Doer, cfg Config) *MicroVMs {
	return &MicroVMs{api: api, http: httpc, cfg: cfg, sleep: sleepContext}
}

var _ Client = (*MicroVMs)(nil)

// Launch runs a MicroVM from the image with the run's token and canaries
// as its /run hook payload, then waits until it is RUNNING: Lambda forwards
// nothing until that hook has answered. A MicroVM that never gets there is
// terminated.
func (m *MicroVMs) Launch(ctx context.Context, in Launch) (VM, error) {
	payload, err := encodeRunHookPayload(in)
	if err != nil {
		return VM{}, err
	}
	out, err := m.api.RunMicrovm(ctx, &lambdamicrovms.RunMicrovmInput{
		ImageIdentifier:          aws.String(m.cfg.ImageARN),
		ClientToken:              aws.String(in.IdempotencyKey),
		IngressNetworkConnectors: []string{m.cfg.IngressConnectorARN},
		EgressNetworkConnectors:  []string{m.cfg.EgressConnectorARN},
		// No execution role: the server under test gets no AWS credentials,
		// and so Lambda writes no runtime logs. Observations come back
		// through the Harness API instead.
		Logging:                  &types.LoggingMemberDisabled{},
		MaximumDurationInSeconds: aws.Int32(int32(maxLifetime / time.Second)),
		RunHookPayload:           aws.String(payload),
	})
	if err != nil {
		return VM{}, fmt.Errorf("run a MicroVM from %s: %w", m.cfg.ImageARN, err)
	}
	vm := VM{ID: aws.ToString(out.MicrovmId), Endpoint: aws.ToString(out.Endpoint), Token: in.Token}
	if err := m.waitRunning(ctx, vm.ID); err != nil {
		// The check is failing anyway; the MicroVM must not outlive it.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		return VM{}, errors.Join(err, m.Terminate(cleanup, vm))
	}
	return vm, nil
}

// Call sends req to the harness on HarnessPort, with a fresh endpoint token
// for Lambda and the run's bearer token for the harness.
func (m *MicroVMs) Call(ctx context.Context, vm VM, req Request) (Response, error) {
	if !validRequest(req) {
		return Response{}, ErrBadRequest
	}
	proxyToken, err := m.authToken(ctx, vm.ID)
	if err != nil {
		return Response{}, err
	}
	var body io.Reader
	if req.Body != nil {
		b, err := json.Marshal(req.Body)
		if err != nil {
			return Response{}, fmt.Errorf("encode the body of %s %s: %w", req.Method, req.Path, err)
		}
		body = bytes.NewReader(b)
	}
	target := url.URL{Scheme: "https", Host: vm.Endpoint, Path: req.Path}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), body)
	if err != nil {
		return Response{}, fmt.Errorf("build %s %s: %w", req.Method, req.Path, err)
	}
	// Lambda reads and removes the X-aws-proxy-* headers; the harness sees
	// only the Authorization header.
	httpReq.Header.Set("X-Aws-Proxy-Auth", proxyToken)
	httpReq.Header.Set("X-Aws-Proxy-Port", strconv.Itoa(HarnessPort))
	httpReq.Header.Set("Authorization", "Bearer "+vm.Token)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := m.http.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("call %s %s on MicroVM %s: %w", req.Method, req.Path, vm.ID, err)
	}
	// The body is only read: closing it can't lose anything worth an error.
	defer func() { _ = resp.Body.Close() }()
	// One byte past the limit tells an answer that fills it from one over it.
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("read the answer to %s %s from MicroVM %s: %w", req.Method, req.Path, vm.ID, err)
	}
	if len(b) > maxResponseBytes {
		return Response{}, fmt.Errorf("%s %s on MicroVM %s answered %d: %w", req.Method, req.Path, vm.ID, resp.StatusCode, ErrTooLarge)
	}
	if !json.Valid(b) {
		return Response{}, fmt.Errorf("%s %s on MicroVM %s answered %d: %w", req.Method, req.Path, vm.ID, resp.StatusCode, ErrNotJSON)
	}
	return Response{Status: resp.StatusCode, Body: b}, nil
}

// Suspend suspends the MicroVM, keeping its memory and disk.
func (m *MicroVMs) Suspend(ctx context.Context, vm VM) error {
	if _, err := m.api.SuspendMicrovm(ctx, &lambdamicrovms.SuspendMicrovmInput{MicrovmIdentifier: aws.String(vm.ID)}); err != nil {
		return fmt.Errorf("suspend MicroVM %s: %w", vm.ID, err)
	}
	return nil
}

// Resume resumes the MicroVM and waits until it is RUNNING again: it stays
// SUSPENDED while the harness's /resume hook runs.
func (m *MicroVMs) Resume(ctx context.Context, vm VM) error {
	if _, err := m.api.ResumeMicrovm(ctx, &lambdamicrovms.ResumeMicrovmInput{MicrovmIdentifier: aws.String(vm.ID)}); err != nil {
		return fmt.Errorf("resume MicroVM %s: %w", vm.ID, err)
	}
	return m.waitRunning(ctx, vm.ID)
}

// Terminate ends the MicroVM. One that is already gone counts as ended, so
// a retried step changes nothing.
func (m *MicroVMs) Terminate(ctx context.Context, vm VM) error {
	_, err := m.api.TerminateMicrovm(ctx, &lambdamicrovms.TerminateMicrovmInput{MicrovmIdentifier: aws.String(vm.ID)})
	if notFound := (*types.ResourceNotFoundException)(nil); errors.As(err, &notFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("terminate MicroVM %s: %w", vm.ID, err)
	}
	return nil
}

// authToken makes an endpoint token for the MicroVM that opens HarnessPort
// only, never HooksPort.
func (m *MicroVMs) authToken(ctx context.Context, id string) (string, error) {
	out, err := m.api.CreateMicrovmAuthToken(ctx, &lambdamicrovms.CreateMicrovmAuthTokenInput{
		MicrovmIdentifier:   aws.String(id),
		ExpirationInMinutes: aws.Int32(authTokenMinutes),
		AllowedPorts:        []types.PortSpecification{&types.PortSpecificationMemberPort{Value: HarnessPort}},
	})
	if err != nil {
		return "", fmt.Errorf("create an endpoint token for MicroVM %s: %w", id, err)
	}
	token := out.AuthToken["X-aws-proxy-auth"]
	if token == "" {
		return "", fmt.Errorf("create an endpoint token for MicroVM %s: the answer holds no X-aws-proxy-auth token", id)
	}
	return token, nil
}

// waitRunning polls the MicroVM until it is RUNNING, and fails when it
// ends, or when it takes longer than maxPolls polls.
func (m *MicroVMs) waitRunning(ctx context.Context, id string) error {
	for range maxPolls {
		out, err := m.api.GetMicrovm(ctx, &lambdamicrovms.GetMicrovmInput{MicrovmIdentifier: aws.String(id)})
		if err != nil {
			return fmt.Errorf("read the state of MicroVM %s: %w", id, err)
		}
		switch out.State {
		case types.MicrovmStateRunning:
			return nil
		case types.MicrovmStateTerminating, types.MicrovmStateTerminated:
			return fmt.Errorf("MicroVM %s is %s (%s): %w", id, out.State, aws.ToString(out.StateReason), ErrNotRunning)
		case types.MicrovmStatePending, types.MicrovmStateSuspending, types.MicrovmStateSuspended:
		default:
			return fmt.Errorf("MicroVM %s is in a state the Checker doesn't know, %q: %w", id, out.State, ErrNotRunning)
		}
		if err := m.sleep(ctx, pollInterval); err != nil {
			return fmt.Errorf("wait for MicroVM %s to run: %w", id, err)
		}
	}
	return fmt.Errorf("MicroVM %s still isn't running after %d polls: %w", id, maxPolls, ErrNotRunning)
}

// sleepContext waits d, or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
