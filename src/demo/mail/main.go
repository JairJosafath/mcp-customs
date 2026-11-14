package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	tool := &mailTool{
		sender: logSender{out: os.Stderr},
		copier: newCopier(&http.Client{Timeout: 10 * time.Second}),
	}
	if err := newServer(tool).Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// logSender is the demo's stand-in for a mail transport: it writes a line per
// delivery instead of sending anything. It is a fixture, not a real mailer.
type logSender struct{ out *os.File }

func (s logSender) Send(_ context.Context, msg message) error {
	fmt.Fprintf(s.out, "deliver to=%s subject=%q body=%q\n", msg.To, msg.Subject, msg.Body)
	return nil
}
