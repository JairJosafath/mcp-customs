package harness

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

// The bounds of the install log /install answers: its first lines, its
// last ones, where an install says what failed, and, from the lines cut
// between them, those that name a failure. Encoded, every byte escaped,
// the log is under 1 MiB.
const (
	maxLogHead     = 16 << 10
	maxLogTailKept = 64 << 10
	maxLogFailures = 64 << 10
	// maxLogLine bounds one line; a longer one keeps its start.
	maxLogLine = 4 << 10
)

// failureWords are what a line naming a failure says, lowercased.
var failureWords = []string{"error", "fail", "fatal", "denied", "panic", "err!"}

// installLog is an install's output as /install answers it, bounded. It is
// safe for concurrent use: a command's output and its errors may both
// write it.
type installLog struct {
	mu       sync.Mutex
	partial  []byte
	head     []string
	headSize int
	tail     []string
	tailSize int
	failures []string
	failSize int
	cut      int
}

func (l *installLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		line, rest, ended := bytes.Cut(p, []byte{'\n'})
		if room := maxLogLine - len(l.partial); room > 0 {
			l.partial = append(l.partial, line[:min(len(line), room)]...)
		}
		if !ended {
			break
		}
		l.lineLocked(string(l.partial) + "\n")
		l.partial, p = l.partial[:0], rest
	}
	return n, nil
}

// lineLocked keeps one line, cut to maxLogLine.
func (l *installLog) lineLocked(line string) {
	if len(line) > maxLogLine {
		line = cutHead(line, maxLogLine-1) + "\n"
	}
	if l.tail == nil && l.headSize+len(line) <= maxLogHead {
		l.head = append(l.head, line)
		l.headSize += len(line)
		return
	}
	l.tail = append(l.tail, line)
	l.tailSize += len(line)
	for l.tailSize > maxLogTailKept {
		old := l.tail[0]
		l.tail = l.tail[1:]
		l.tailSize -= len(old)
		l.dropLocked(old)
	}
}

// dropLocked cuts a line from between the head and the tail, unless it
// names a failure and there is room to keep it.
func (l *installLog) dropLocked(line string) {
	if namesFailure(line) && l.failSize+len(line) <= maxLogFailures {
		l.failures = append(l.failures, line)
		l.failSize += len(line)
		return
	}
	l.cut += len(line)
}

func namesFailure(line string) bool {
	lower := strings.ToLower(line)
	for _, w := range failureWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// String is the log as kept, a line saying how much was cut where it was.
func (l *installLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, s := range l.head {
		b.WriteString(s)
	}
	if l.cut > 0 {
		fmt.Fprintf(&b, "[the harness cut %d bytes of the log here, keeping the lines that name a failure]\n", l.cut)
	}
	for _, s := range append(append([]string{}, l.failures...), l.tail...) {
		b.WriteString(s)
	}
	if len(l.partial) > 0 {
		b.Write(l.partial)
	}
	return b.String()
}

// boundLog is log as an installLog keeps it.
func boundLog(log string) string {
	var l installLog
	_, _ = l.Write([]byte(log))
	return l.String()
}
