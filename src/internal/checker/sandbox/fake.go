package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
)

// Fake is a Client in memory, for the Checker's tests. It keeps each VM's
// state as Lambda would, refuses calls to a VM that isn't running, and
// answers calls with Respond, recording each one.
type Fake struct {
	// Respond answers a call to a running VM. Nil answers 200 with {}.
	Respond func(vm VM, req Request) (Response, error)

	mu       sync.Mutex
	launches map[string]VM // by idempotency key
	states   map[string]State
	calls    []FakeCall
}

// State is where a fake VM is in its life.
type State string

// The states a fake VM goes through.
const (
	StateRunning    State = "RUNNING"
	StateSuspended  State = "SUSPENDED"
	StateTerminated State = "TERMINATED"
)

// FakeCall is one call a Fake answered.
type FakeCall struct {
	VMID    string
	Request Request
}

var _ Client = (*Fake)(nil)

// ErrUnknownVM says a Fake never launched the VM.
var ErrUnknownVM = errors.New("the fake never launched this VM")

// ErrWrongState says a fake VM isn't in the state the call needs: a call
// to a suspended VM, say, or a resume of a running one.
var ErrWrongState = errors.New("the fake VM is not in the state this call needs")

// Launch starts a fake VM, or returns the one an earlier launch with the
// same idempotency key started, as RunMicrovm's client token does.
func (f *Fake) Launch(_ context.Context, in Launch) (VM, error) {
	if _, err := encodeRunHookPayload(in); err != nil {
		return VM{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.launches == nil {
		f.launches = map[string]VM{}
		f.states = map[string]State{}
	}
	if vm, ok := f.launches[in.IdempotencyKey]; ok {
		return vm, nil
	}
	id := "mvm-fake-" + strconv.Itoa(len(f.launches)+1)
	vm := VM{ID: id, Endpoint: id + ".lambda-microvm.example.on.aws", Token: in.Token}
	f.launches[in.IdempotencyKey] = vm
	f.states[id] = StateRunning
	return vm, nil
}

// Call records req and answers it with Respond, if the VM is running.
func (f *Fake) Call(_ context.Context, vm VM, req Request) (Response, error) {
	if !validRequest(req) {
		return Response{}, ErrBadRequest
	}
	f.mu.Lock()
	if err := f.need(vm, StateRunning); err != nil {
		f.mu.Unlock()
		return Response{}, err
	}
	f.calls = append(f.calls, FakeCall{VMID: vm.ID, Request: req})
	respond := f.Respond
	f.mu.Unlock()
	if respond == nil {
		return Response{Status: http.StatusOK, Body: json.RawMessage(`{}`)}, nil
	}
	return respond(vm, req)
}

// Suspend suspends a running fake VM.
func (f *Fake) Suspend(_ context.Context, vm VM) error {
	return f.move(vm, StateRunning, StateSuspended)
}

// Resume resumes a suspended fake VM.
func (f *Fake) Resume(_ context.Context, vm VM) error {
	return f.move(vm, StateSuspended, StateRunning)
}

// Terminate ends a fake VM; ending one twice is not an error.
func (f *Fake) Terminate(_ context.Context, vm VM) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.states[vm.ID]; !ok {
		return fmt.Errorf("terminate %s: %w", vm.ID, ErrUnknownVM)
	}
	f.states[vm.ID] = StateTerminated
	return nil
}

// StateOf answers the fake VM's state, or "" for a VM it never launched.
func (f *Fake) StateOf(vm VM) State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[vm.ID]
}

// Calls answers every call the Fake answered, in order.
func (f *Fake) Calls() []FakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeCall(nil), f.calls...)
}

// Launched answers how many VMs the Fake started.
func (f *Fake) Launched() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.launches)
}

// move changes vm from one state to another.
func (f *Fake) move(vm VM, from, to State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.need(vm, from); err != nil {
		return err
	}
	f.states[vm.ID] = to
	return nil
}

// need fails unless vm is in state want. The caller holds f.mu.
func (f *Fake) need(vm VM, want State) error {
	got, ok := f.states[vm.ID]
	if !ok {
		return fmt.Errorf("%s: %w", vm.ID, ErrUnknownVM)
	}
	if got != want {
		return fmt.Errorf("%s is %s, not %s: %w", vm.ID, got, want, ErrWrongState)
	}
	return nil
}
