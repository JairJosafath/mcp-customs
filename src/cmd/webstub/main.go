// The web stub: the web function's handler over plain HTTP on this
// machine, with a fake store and Checker that play the three demo checks.
// demo/record.ts is tested against it; it is never deployed.
package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/JairJosafath/mcp-customs/src/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "the address to listen on")
	key := flag.String("reviewer-key", "demo", "the reviewer key Approve and Block take")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	d := newDemo()
	h := web.New(web.Deps{Checks: d, Reports: d, Checker: d, ReviewerKey: []byte(*key), NewID: web.NewCheckID, Log: log})
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Error("Listening failed.", "addr", *addr, "error", err.Error())
		os.Exit(1)
	}
	log.Info("The web stub listens.", "url", "http://"+l.Addr().String())
	srv := &http.Server{Handler: adapter{h}, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		log.Error("Serving failed.", "error", err.Error())
		os.Exit(1)
	}
}

// maxBody bounds a request's body, as API Gateway would pass it on.
const maxBody = 64 << 10

// adapter serves the web handler's API Gateway answers over net/http.
type adapter struct{ h *web.Handler }

var requestSeq atomic.Int64

func (a adapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "read the body", http.StatusBadRequest)
		return
	}
	resp := a.h.Answer(r.Context(), toEvent(r, raw))
	for name, value := range resp.Headers {
		w.Header().Set(name, value)
	}
	body := []byte(resp.Body)
	if resp.IsBase64Encoded {
		if body, err = base64.StdEncoding.DecodeString(resp.Body); err != nil {
			http.Error(w, "decode the answer", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// toEvent is r, with its body raw, as API Gateway's HTTP API sends it to
// the function.
func toEvent(r *http.Request, raw []byte) *events.APIGatewayV2HTTPRequest {
	headers := map[string]string{}
	for name, values := range r.Header {
		headers[strings.ToLower(name)] = strings.Join(values, ",")
	}
	return &events.APIGatewayV2HTTPRequest{
		RouteKey:       "$default",
		RawPath:        r.URL.EscapedPath(),
		RawQueryString: r.URL.RawQuery,
		Headers:        headers,
		Body:           string(raw),
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RequestID: "stub-" + strconv.FormatInt(requestSeq.Add(1), 10),
			HTTP:      events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: r.Method, Path: r.URL.Path},
		},
	}
}
