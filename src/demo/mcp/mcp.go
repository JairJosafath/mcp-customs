// Package mcp is a tiny Model Context Protocol server over stdio: enough for
// the demo servers to answer initialize, tools/list and tools/call. It is not
// a general MCP implementation; it exists so the demo servers can be launched
// and driven inside the MCP Customs sandbox like any other MCP server.
//
// Messages are newline-delimited JSON-RPC 2.0, as the MCP stdio transport
// specifies: one request per line in, one response per line out, notifications
// (requests without an id) answered with nothing.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// ProtocolVersion is the MCP protocol version the demo servers report from
// initialize.
const ProtocolVersion = "2025-06-18"

// maxLine is the largest single JSON-RPC message the server will read. Tool
// results can carry whole schemas, so it is generous.
const maxLine = 16 * 1024 * 1024

// Content is one item of a tool result. The demo servers use only text.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Result is what a tool returns on tools/call: its content and whether the
// call is reported to the client as an error.
type Result struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Text builds a plain, successful text result.
func Text(s string) Result {
	return Result{Content: []Content{{Type: "text", Text: s}}}
}

// ErrorText builds a text result flagged as an error.
func ErrorText(s string) Result {
	return Result{Content: []Content{{Type: "text", Text: s}}, IsError: true}
}

// Handler runs one tools/call with the raw JSON arguments object. A failure is
// reported as a Result with IsError set, which the client reads as a failed
// tool call; there is no separate protocol-error path for a tool.
type Handler func(ctx context.Context, arguments json.RawMessage) Result

// Tool is one tool the server offers. Name, Description and InputSchema are
// returned verbatim by tools/list; Handler runs on tools/call.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Handler     Handler
}

// Server offers a fixed set of tools over one stdio connection.
type Server struct {
	name    string
	version string
	tools   []Tool
}

// New makes a Server with the given server name, version and tools.
func New(name, version string, tools ...Tool) *Server {
	return &Server{name: name, version: version, tools: tools}
}

// Serve reads JSON-RPC messages from r and writes responses to w until r is
// exhausted. It returns nil at a clean end of input.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		resp, ok := s.handle(ctx, line)
		if !ok {
			continue
		}
		if _, err := w.Write(append(resp, '\n')); err != nil {
			return fmt.Errorf("writing response: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	return nil
}

// ToolsListJSON returns the exact bytes of the tools/list result. Tests use it
// to check that a server's tool list is clean and that two builds offer a
// byte-identical list.
func (s *Server) ToolsListJSON() ([]byte, error) {
	return json.Marshal(s.toolsListResult())
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// handle dispatches one message. The bool is false when the message is a
// notification, which gets no response.
func (s *Server) handle(ctx context.Context, line []byte) ([]byte, bool) {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return s.errorResponse(nil, -32700, "parse error"), true
	}
	if len(req.ID) == 0 {
		return nil, false
	}
	switch req.Method {
	case "initialize":
		return s.resultResponse(req.ID, s.initializeResult()), true
	case "tools/list":
		return s.resultResponse(req.ID, s.toolsListResult()), true
	case "tools/call":
		return s.callTool(ctx, req), true
	default:
		return s.errorResponse(req.ID, -32601, "method not found: "+req.Method), true
	}
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type capabilities struct {
	Tools struct{} `json:"tools"`
}

type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      serverInfo   `json:"serverInfo"`
}

func (s *Server) initializeResult() initializeResult {
	return initializeResult{
		ProtocolVersion: ProtocolVersion,
		ServerInfo:      serverInfo{Name: s.name, Version: s.version},
	}
}

type toolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type toolsListResult struct {
	Tools []toolInfo `json:"tools"`
}

func (s *Server) toolsListResult() toolsListResult {
	infos := make([]toolInfo, 0, len(s.tools))
	for i := range s.tools {
		infos = append(infos, toolInfo{
			Name:        s.tools[i].Name,
			Description: s.tools[i].Description,
			InputSchema: s.tools[i].InputSchema,
		})
	}
	return toolsListResult{Tools: infos}
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) callTool(ctx context.Context, req rpcRequest) []byte {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return s.errorResponse(req.ID, -32602, "invalid params")
	}
	for i := range s.tools {
		if s.tools[i].Name != p.Name {
			continue
		}
		return s.resultResponse(req.ID, s.tools[i].Handler(ctx, p.Arguments))
	}
	return s.errorResponse(req.ID, -32602, "unknown tool: "+p.Name)
}

func (s *Server) resultResponse(id json.RawMessage, result any) []byte {
	raw, err := json.Marshal(result)
	if err != nil {
		return s.errorResponse(id, -32603, "marshaling result")
	}
	out, err := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: id, Result: raw})
	if err != nil {
		return s.errorResponse(id, -32603, "marshaling response")
	}
	return out
}

func (s *Server) errorResponse(id json.RawMessage, code int, msg string) []byte {
	out, err := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
	if err != nil {
		// A fixed, already-valid fallback: the structured marshal cannot fail,
		// but the error must still be handled rather than discarded.
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`)
	}
	return out
}
