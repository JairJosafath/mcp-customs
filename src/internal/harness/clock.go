package harness

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// FakeTime is how the harness moves the server's clock: libfaketime,
// preloaded into the server, reads the offset from File on every call for
// the time, so a move applies to a server already running.
type FakeTime struct {
	// Lib is libfaketime's shared object, preloaded into the server.
	Lib string
	// File holds the offset in force. It must be outside every directory
	// the server can write.
	File string
}

// The bounds of /clock: one move, and all of them together.
const (
	maxClockMove  = 366 * 24 * time.Hour
	maxClockTotal = 10 * maxClockMove
)

// on says whether the harness has a fake clock.
func (f FakeTime) on() bool { return f.Lib != "" && f.File != "" }

// env is what the server's environment needs for the fake clock. The
// monotonic clock is left alone, so the server's timeouts still work.
func (f FakeTime) env() []string {
	if !f.on() {
		return nil
	}
	return []string{
		"LD_PRELOAD=" + f.Lib,
		"FAKETIME_TIMESTAMP_FILE=" + f.File,
		"FAKETIME_NO_CACHE=1",
		"FAKETIME_DONT_FAKE_MONOTONIC=1",
	}
}

// write puts offset in force: written whole beside the file, then renamed
// over it, so libfaketime never reads half of it.
func (f FakeTime) write(offset time.Duration) error {
	tmp, err := os.CreateTemp(filepath.Dir(f.File), ".faketime-*")
	if err != nil {
		return fmt.Errorf("write the fake clock: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	// libfaketime reads a bare number as seconds.
	if _, err := fmt.Fprintf(tmp, "+%s\n", strconv.FormatInt(int64(offset/time.Second), 10)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the fake clock: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the fake clock: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write the fake clock: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.File); err != nil {
		return fmt.Errorf("write the fake clock: %w", err)
	}
	return nil
}

type clockRequest struct {
	Offset string `json:"offset"`
}

// clock moves the server's clock forward by the offset and answers the
// clock now in force: the whole offset, the time a server that loads
// libfaketime sees, and whether this server's runtime does.
func (h *Harness) clock(r *http.Request) (int, answer) {
	var req clockRequest
	if err := decode(r, &req); err != nil {
		return problem(http.StatusBadRequest, err.Error())
	}
	d, err := time.ParseDuration(req.Offset)
	if err != nil || d < time.Second || d > maxClockMove || d%time.Second != 0 {
		return problem(http.StatusBadRequest, fmt.Sprintf("The offset is whole seconds, from one to %s, such as \"720h\".", maxClockMove))
	}
	if !h.cfg.FakeTime.on() {
		return problem(http.StatusConflict, "This harness has no fake clock.")
	}
	total := h.clockOffset + d
	if total > maxClockTotal {
		return problem(http.StatusBadRequest, fmt.Sprintf("The clock moves at most %s in all.", maxClockTotal))
	}
	if err := h.cfg.FakeTime.write(total); err != nil {
		return problem(http.StatusInternalServerError, "Could not move the clock: "+err.Error())
	}
	h.clockOffset = total
	return http.StatusOK, h.clockNow()
}

func (h *Harness) clockNow() answer {
	var command []string
	switch {
	case h.srv != nil:
		command = h.srv.command
	case h.run != nil:
		command = h.run.command
	}
	applies, why := fakeTimeApplies(command, h.serverPath())
	return answer{"offset": h.clockOffset.String(), "now": h.cfg.Now().Add(h.clockOffset).UTC(), "applies": applies, "why": why}
}
