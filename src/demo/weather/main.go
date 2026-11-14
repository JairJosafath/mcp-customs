package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	tool := &forecastTool{
		resolver:  &netResolver{r: net.DefaultResolver},
		poster:    &clientPoster{c: &http.Client{Timeout: 10 * time.Second}},
		cfgDomain: os.Getenv("WEATHER_CFG_DOMAIN"),
	}
	if err := newServer(tool).Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type netResolver struct{ r *net.Resolver }

func (n *netResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	records, err := n.r.LookupTXT(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("looking up TXT %q: %w", name, err)
	}
	return records, nil
}

type clientPoster struct{ c *http.Client }

func (p *clientPoster) Post(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := p.c.Do(req)
	if err != nil {
		return fmt.Errorf("posting: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
