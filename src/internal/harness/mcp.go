package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// What the harness tells the server about itself: a common client, which
// asks for sampling and elicitation so a server that wants them shows it.
const protocolVersion = "2025-06-18"

var clientInfo = map[string]string{"name": "claude-code", "version": "2.0.14"}

var clientCapabilities = map[string]any{
	"sampling":    map[string]any{},
	"elicitation": map[string]any{},
}

// maxMessage bounds one JSON-RPC message from the server.
const maxMessage = 16 << 20

// maxPending bounds the server's requests the harness answers at once,
// each with a goroutine. A real client has one or two open; a server
// sending more without reading its answers is flooding the harness.
const maxPending = 64

// maxRequestID bounds a request id the harness keeps until it answers: a
// JSON-RPC id is a number or a short string.
const maxRequestID = 256

// observer is what a session tells of the server's requests.
type observer interface {
	add(kind ObservationKind, detail any)
	truncate(kind ObservationKind, why string)
}

var errServerGone = errors.New("the server under test has stopped")

// RPCError is a JSON-RPC error, as the server sent it or as the harness
// answers it.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// conn is an MCP client session over newline-delimited JSON-RPC: requests
// to the server, the server's answers, and the server's own requests, which
// become observations.
type conn struct {
	out chan []byte
	obs observer
	// slots holds one token per request of the server being answered: at
	// most maxPending, each with its goroutine.
	slots chan struct{}

	mu      sync.Mutex
	next    int64
	pending map[int64]chan rpcMessage

	closed chan struct{}
}

// newConn starts a session writing to w and reading r. Its goroutines end
// when r ends or w fails; then every waiting call fails and closed closes.
func newConn(w io.Writer, r io.Reader, obs observer) *conn {
	c := &conn{
		out:     make(chan []byte),
		obs:     obs,
		slots:   make(chan struct{}, maxPending),
		pending: map[int64]chan rpcMessage{},
		closed:  make(chan struct{}),
	}
	go c.write(w)
	go c.read(r)
	return c
}

func (c *conn) write(w io.Writer) {
	for {
		select {
		case line := <-c.out:
			if _, err := w.Write(line); err != nil {
				return
			}
		case <-c.closed:
			return
		}
	}
}

func (c *conn) read(r io.Reader) {
	defer close(c.closed)
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 0, 64<<10), maxMessage)
	for scan.Scan() {
		var msg rpcMessage
		if json.Unmarshal(scan.Bytes(), &msg) != nil {
			continue
		}
		switch {
		case msg.Method != "" && len(msg.ID) > 0:
			c.request(msg)
		case msg.Method != "":
			// A notification: logging and progress say nothing a check needs.
		default:
			c.deliver(msg)
		}
	}
}

func (c *conn) deliver(msg rpcMessage) {
	id, err := strconv.ParseInt(string(msg.ID), 10, 64)
	if err != nil {
		return
	}
	c.mu.Lock()
	wait, ok := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ok {
		wait <- msg
	}
}

// request takes a request the server sent: sampling and elicitation are
// observed as they arrive, then every request is answered on a goroutine
// of its own, at most maxPending at once. Past that, a request is not
// answered, with one truncated observation of kind request.
func (c *conn) request(msg rpcMessage) {
	kind := requestKind(msg.Method)
	select {
	case c.slots <- struct{}{}:
	default:
		c.obs.truncate(ObservedRequest, fmt.Sprintf("more than %d requests of the server unanswered at once; that one and any after went unanswered", maxPending))
		return
	}
	if kind != "" {
		c.obs.add(kind, requestDetail(msg))
	}
	if len(msg.ID) > maxRequestID {
		<-c.slots
		return
	}
	reply := rpcMessage{JSONRPC: "2.0", ID: msg.ID}
	go func() {
		defer func() { <-c.slots }()
		c.answer(msg.Method, reply)
	}()
}

// requestDetail is what an observation keeps of a request: its params
// whole, or their start as a string when they are over maxRequestParams.
func requestDetail(msg rpcMessage) RequestDetail {
	if len(msg.Params) <= maxRequestParams {
		return RequestDetail{Method: msg.Method, Params: msg.Params}
	}
	start, err := json.Marshal(strings.ToValidUTF8(string(msg.Params[:maxRequestParams]), "\uFFFD"))
	if err != nil {
		start = json.RawMessage(`""`)
	}
	return RequestDetail{Method: msg.Method, Params: start, Cut: true}
}

// requestKind is the observation kind of a request the server sends, or
// "" when it is not observed.
func requestKind(method string) ObservationKind {
	switch method {
	case "sampling/createMessage":
		return ObservedSampling
	case "elicitation/create":
		return ObservedElicitation
	}
	return ""
}

// answer answers a request the server sent: sampling and elicitation
// blandly, as a user who declines would.
func (c *conn) answer(method string, reply rpcMessage) {
	switch method {
	case "sampling/createMessage":
		reply.Result = json.RawMessage(`{"role":"assistant","content":{"type":"text","text":"I can't help with that."},"model":"claude-sonnet-4-5","stopReason":"endTurn"}`)
	case "elicitation/create":
		reply.Result = json.RawMessage(`{"action":"decline"}`)
	case "ping":
		reply.Result = json.RawMessage(`{}`)
	default:
		reply.Error = &RPCError{Code: -32601, Message: "Method not found"}
	}
	_ = c.send(context.Background(), reply)
}

func (c *conn) send(ctx context.Context, msg rpcMessage) error {
	line, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode %s: %w", msg.Method, err)
	}
	select {
	case c.out <- append(line, '\n'):
		return nil
	case <-c.closed:
		return errServerGone
	case <-ctx.Done():
		return fmt.Errorf("send %s: %w", msg.Method, ctx.Err())
	}
}

// call sends a request and waits for its answer. A JSON-RPC error from the
// server is returned as an *RPCError.
func (c *conn) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", method, err)
	}
	wait := make(chan rpcMessage, 1)
	c.mu.Lock()
	c.next++
	id := c.next
	c.pending[id] = wait
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()
	msg := rpcMessage{JSONRPC: "2.0", ID: json.RawMessage(strconv.FormatInt(id, 10)), Method: method, Params: body}
	if err := c.send(ctx, msg); err != nil {
		return nil, err
	}
	select {
	case reply := <-wait:
		if reply.Error != nil {
			return nil, reply.Error
		}
		return reply.Result, nil
	case <-c.closed:
		return nil, errServerGone
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for %s: %w", method, ctx.Err())
	}
}

func (c *conn) notify(ctx context.Context, method string) error {
	return c.send(ctx, rpcMessage{JSONRPC: "2.0", Method: method})
}

// initialize opens the MCP session and returns the server's answer.
func (c *conn) initialize(ctx context.Context) (json.RawMessage, error) {
	result, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    clientCapabilities,
		"clientInfo":      clientInfo,
	})
	if err != nil {
		return nil, err
	}
	if err := c.notify(ctx, "notifications/initialized"); err != nil {
		return nil, err
	}
	return result, nil
}

// maxPages bounds a paginated list, against a server that never ends one.
const maxPages = 100

// list collects every page of a list method's items, as the server sent
// them, until they hold more than budget bytes: then it stops reading
// pages and says the list was cut.
func (c *conn) list(ctx context.Context, method, field string, budget int) ([]json.RawMessage, bool, error) {
	items := []json.RawMessage{}
	cursor := ""
	size := 0
	for range maxPages {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, err := c.call(ctx, method, params)
		if err != nil {
			return nil, false, err
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(result, &page); err != nil {
			return nil, false, fmt.Errorf("read the answer to %s: %w", method, err)
		}
		var some []json.RawMessage
		if raw, ok := page[field]; ok {
			if err := json.Unmarshal(raw, &some); err != nil {
				return nil, false, fmt.Errorf("read the %s of %s: %w", field, method, err)
			}
			size += len(raw)
		}
		items = append(items, some...)
		cursor = ""
		if raw, ok := page["nextCursor"]; ok {
			_ = json.Unmarshal(raw, &cursor)
		}
		if cursor == "" {
			return items, false, nil
		}
		if size > budget {
			return items, true, nil
		}
	}
	return items, false, fmt.Errorf("%s did not end after %d pages", method, maxPages)
}
