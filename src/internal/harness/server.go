package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// maxStderr bounds the tail of the server's stderr the harness keeps.
const maxStderr = 64 << 10

// server is the running server under test and its MCP session.
type server struct {
	conn    *conn
	stdout  io.Closer
	stop    context.CancelFunc
	exited  chan struct{}
	stderr  *tail
	initial json.RawMessage
}

// startServer starts args as the account in dir, with exactly env, and
// speaks MCP to it over its stdin and stdout.
func startServer(a Account, dir string, env, args []string, observe func(ObservationKind, any)) (*server, error) {
	ctx, stop := context.WithCancel(context.Background())
	cmd := a.command(ctx, dir, env, args)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		stop()
		return nil, fmt.Errorf("connect to the server's stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stop()
		return nil, fmt.Errorf("connect to the server's stdout: %w", err)
	}
	s := &server{stdout: stdout, stop: stop, exited: make(chan struct{}), stderr: &tail{max: maxStderr}}
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		stop()
		return nil, fmt.Errorf("start %s: %w", args[0], err)
	}
	s.conn = newConn(stdin, stdout, observe)
	go func() {
		// The reader has read stdout to its end before Wait closes it.
		<-s.conn.closed
		_ = cmd.Wait()
		close(s.exited)
	}()
	return s, nil
}

// close kills the server and all it started, and waits for it to end. It
// closes stdout itself too, in case something the server started outside
// its process group still holds it open.
func (s *server) close() {
	s.stop()
	_ = s.stdout.Close()
	<-s.exited
}

// tail keeps the last max bytes written to it. It is safe for concurrent use.
type tail struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append([]byte{}, t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
