package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func echoTool() Tool {
	return Tool{
		Name:        "echo",
		Description: "Echo the message back.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}`),
		Handler: func(_ context.Context, arguments json.RawMessage) Result {
			var a struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(arguments, &a) != nil {
				return ErrorText("bad arguments")
			}
			return Text(a.Message)
		},
	}
}

func decode(t *testing.T, b []byte) rpcResponse {
	t.Helper()
	var resp rpcResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v (%s)", err, b)
	}
	return resp
}

func TestInitializeReportsProtocolAndName(t *testing.T) {
	s := New("demo", "9.9.9", echoTool())
	out, ok := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if !ok {
		t.Fatal("initialize produced no response")
	}
	var res initializeResult
	if err := json.Unmarshal(decode(t, out).Result, &res); err != nil {
		t.Fatalf("decoding initialize result: %v", err)
	}
	if res.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocolVersion = %q, want %q", res.ProtocolVersion, ProtocolVersion)
	}
	if res.ServerInfo.Name != "demo" || res.ServerInfo.Version != "9.9.9" {
		t.Errorf("serverInfo = %+v, want demo/9.9.9", res.ServerInfo)
	}
}

func TestToolsListReturnsTheTool(t *testing.T) {
	s := New("demo", "1.0.0", echoTool())
	out, ok := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if !ok {
		t.Fatal("tools/list produced no response")
	}
	var res toolsListResult
	if err := json.Unmarshal(decode(t, out).Result, &res); err != nil {
		t.Fatalf("decoding tools/list result: %v", err)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "echo" {
		t.Fatalf("tools = %+v, want one tool named echo", res.Tools)
	}
}

func TestToolsCallRunsTheHandler(t *testing.T) {
	s := New("demo", "1.0.0", echoTool())
	out, ok := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}`))
	if !ok {
		t.Fatal("tools/call produced no response")
	}
	var res Result
	if err := json.Unmarshal(decode(t, out).Result, &res); err != nil {
		t.Fatalf("decoding call result: %v", err)
	}
	if len(res.Content) != 1 || res.Content[0].Text != "hi" {
		t.Errorf("content = %+v, want text \"hi\"", res.Content)
	}
}

func TestUnknownToolIsAnError(t *testing.T) {
	s := New("demo", "1.0.0", echoTool())
	out, _ := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}`))
	resp := decode(t, out)
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "unknown tool") {
		t.Errorf("error = %+v, want an unknown tool error", resp.Error)
	}
}

func TestUnknownMethodIsAnError(t *testing.T) {
	s := New("demo", "1.0.0", echoTool())
	out, _ := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":5,"method":"resources/list"}`))
	if resp := decode(t, out); resp.Error == nil || resp.Error.Code != -32601 {
		t.Errorf("error = %+v, want method not found (-32601)", resp.Error)
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	s := New("demo", "1.0.0", echoTool())
	if _, ok := s.handle(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); ok {
		t.Error("a notification (no id) must get no response")
	}
}

func TestServeRoundTrip(t *testing.T) {
	s := New("demo", "1.0.0", echoTool())
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"ping"}}}` + "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !strings.Contains(out.String(), `"ping"`) {
		t.Errorf("Serve output = %q, want it to contain the echoed text", out.String())
	}
}
