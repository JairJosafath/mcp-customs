package sandbox

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestFakeLaunchesOnceAKeyAndKeepsStateAsLambdaWould(t *testing.T) {
	f := &Fake{Respond: func(_ VM, req Request) (Response, error) {
		return Response{Status: http.StatusOK, Body: json.RawMessage(`{"path":"` + req.Path + `"}`)}, nil
	}}
	ctx := t.Context()

	vm, err := f.Launch(ctx, testLaunch())
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	again, err := f.Launch(ctx, testLaunch())
	if err != nil || again != vm || f.Launched() != 1 {
		t.Errorf("a retried launch = %+v, %v with %d launched; want the same VM", again, err, f.Launched())
	}
	if vm.Token != "run-token" || f.StateOf(vm) != StateRunning {
		t.Errorf("launched %+v in state %s", vm, f.StateOf(vm))
	}

	resp, err := f.Call(ctx, vm, Request{Method: http.MethodPost, Path: "/list"})
	if err != nil || string(resp.Body) != `{"path":"/list"}` {
		t.Errorf("Call = %s, %v", resp.Body, err)
	}
	if err := f.Suspend(ctx, vm); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if _, err := f.Call(ctx, vm, Request{Method: http.MethodPost, Path: "/list"}); !errors.Is(err, ErrWrongState) {
		t.Errorf("Call while suspended = %v, want ErrWrongState", err)
	}
	if err := f.Suspend(ctx, vm); !errors.Is(err, ErrWrongState) {
		t.Errorf("Suspend twice = %v, want ErrWrongState", err)
	}
	if err := f.Resume(ctx, vm); err != nil || f.StateOf(vm) != StateRunning {
		t.Errorf("Resume = %v, state %s", err, f.StateOf(vm))
	}
	if err := f.Terminate(ctx, vm); err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if err := f.Terminate(ctx, vm); err != nil || f.StateOf(vm) != StateTerminated {
		t.Errorf("Terminate twice = %v, state %s", err, f.StateOf(vm))
	}
	if calls := f.Calls(); len(calls) != 1 || calls[0].VMID != vm.ID || calls[0].Request.Path != "/list" {
		t.Errorf("Calls = %+v, want the one call to a running VM", calls)
	}
}

func TestFakeRefusesWhatTheRealClientRefuses(t *testing.T) {
	f := &Fake{}
	ctx := t.Context()
	if _, err := f.Launch(ctx, Launch{IdempotencyKey: "k", Token: "t"}); !errors.Is(err, ErrBadLaunch) {
		t.Errorf("Launch without canaries = %v, want ErrBadLaunch", err)
	}
	stranger := VM{ID: "mvm-other"}
	if err := f.Terminate(ctx, stranger); !errors.Is(err, ErrUnknownVM) {
		t.Errorf("Terminate of an unknown VM = %v, want ErrUnknownVM", err)
	}
	if _, err := f.Call(ctx, stranger, Request{Method: http.MethodGet, Path: "/observations"}); !errors.Is(err, ErrUnknownVM) {
		t.Errorf("Call to an unknown VM = %v, want ErrUnknownVM", err)
	}
	vm, err := f.Launch(ctx, testLaunch())
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if _, err := f.Call(ctx, vm, Request{Path: "/list"}); !errors.Is(err, ErrBadRequest) {
		t.Errorf("Call without a method = %v, want ErrBadRequest", err)
	}
	resp, err := f.Call(ctx, vm, Request{Method: http.MethodGet, Path: "/observations"})
	if err != nil || resp.Status != http.StatusOK || string(resp.Body) != `{}` {
		t.Errorf("default answer = %d %s, %v", resp.Status, resp.Body, err)
	}
}
