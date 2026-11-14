package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/JairJosafath/mcp-customs/src/internal/demoscene"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/web"
)

// script is what a fake check of one demo server writes: the scene the
// real Checker writes for it (internal/demoscene, which a Checker test
// holds to what the Checker writes), and whether it stalls.
type script struct {
	scene demoscene.Scene
	// stalls says the check never settles, for the recorder's give-up test.
	stalls bool
	// recheckOf is the approved check of the earlier version, for a re-check.
	recheckOf *demoscene.Approved
}

// Fake hashes, as the Checker prints them.
var (
	weatherDeps = strings.Repeat("a1", 32)
	weatherList = strings.Repeat("b2", 32)
	mailDeps    = strings.Repeat("c3", 32)
	mailNext    = strings.Repeat("d4", 32)
	mailList    = strings.Repeat("e5", 32)
)

// scriptOf picks the demo a submission names: the weather server, a check
// that stalls, the mail server's v1.0.1, re-checked against approved when
// there is one, or any other as the clean mail server.
func scriptOf(s store.Submission, approved *demoscene.Approved) script {
	switch {
	case strings.Contains(s.Ref, "weather"):
		return script{scene: demoscene.Weather(demoscene.Params{Submission: s, DependencyHash: weatherDeps, ToolListHash: weatherList})}
	case strings.Contains(s.Ref, "stall"):
		sc := demoscene.Mail(demoscene.Params{Submission: s, DependencyHash: mailDeps, ToolListHash: mailList})
		sc.Steps = sc.Steps[:4]
		return script{scene: sc, stalls: true}
	case strings.Contains(s.Ref, "1.0.1"):
		return script{recheckOf: approved, scene: demoscene.MailNext(demoscene.Params{Submission: s, DependencyHash: mailNext, ToolListHash: mailList, Approved: approved})}
	default:
		return script{scene: demoscene.Mail(demoscene.Params{Submission: s, DependencyHash: mailDeps, ToolListHash: mailList})}
	}
}

// fakeCheck is one check of the demo: how many of its steps it has
// written, and the person's decision once there is one.
type fakeCheck struct {
	submission store.Submission
	script     script
	written    int
	decision   string
}

// all is every step c will write: its scene's, and once a person has
// decided, those the scene writes after.
func (c *fakeCheck) all() []store.Step {
	steps := c.script.scene.Steps
	if c.decision == "" {
		return steps
	}
	after, _ := c.script.scene.Decided(c.decision)
	return append(steps[:len(steps):len(steps)], after...)
}

func (c *fakeCheck) verdict() string {
	if c.decision != "" {
		_, v := c.script.scene.Decided(c.decision)
		return string(v)
	}
	return string(c.script.scene.Verdict)
}

func (c *fakeCheck) decidedBy() string {
	if c.decision != "" {
		return "a person " + c.decision + "ed"
	}
	return "code"
}

// waiting says c has written its scene's steps and waits for a person.
func (c *fakeCheck) waiting() bool {
	return c.script.scene.Waits && c.decision == "" && c.written == len(c.script.scene.Steps)
}

// done says c has written every step and has a verdict.
func (c *fakeCheck) done() bool {
	return !c.script.stalls && !c.waiting() && c.written == len(c.all()) && (c.decision != "" || !c.script.scene.Waits)
}

// demo is the store, the reports and the Checker the stub's web handler
// works with. A check writes one more step each time it is read, so the
// page's own polling moves it on, with no timer.
type demo struct {
	mu     sync.Mutex
	checks map[string]*fakeCheck
	// approved is the last mail check that passed.
	approved *demoscene.Approved
}

func newDemo() *demo { return &demo{checks: map[string]*fakeCheck{}} }

// Start starts check id of s.
func (d *demo) Start(_ context.Context, id string, s store.Submission) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.checks[id]; ok {
		if c.submission != s {
			return web.ErrAlreadyStarted
		}
		return nil
	}
	d.checks[id] = &fakeCheck{submission: s, script: scriptOf(s, d.approved)}
	return nil
}

// Answer decides the check waiting under callbackID, which is its ID.
func (d *demo) Answer(_ context.Context, callbackID, decision string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.checks[callbackID]
	if !ok || !c.waiting() {
		return web.ErrCallbackClosed
	}
	c.decision = decision
	return nil
}

// GetCheck answers check id's META, after writing its next step.
func (d *demo) GetCheck(_ context.Context, id string) (store.Check, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.checks[id]
	if !ok {
		return store.Check{}, false, nil
	}
	if c.written < len(c.all()) {
		c.written++
	}
	meta := store.Check{ID: id, Submission: c.submission, Status: store.StatusRunning}
	if re := c.script.recheckOf; re != nil {
		meta.RecheckOf, meta.RecheckOfRef = re.CheckID, re.Ref
	}
	switch {
	case c.waiting():
		meta.Status, meta.CallbackID = store.StatusWaiting, id
	case c.done():
		meta.Status, meta.Verdict = store.StatusDone, c.verdict()
		if meta.Verdict == "pass" && strings.Contains(c.submission.Ref, "mail") {
			d.approved = &demoscene.Approved{CheckID: id, Ref: c.submission.Ref}
		}
	}
	return meta, true, nil
}

// ListSteps answers the steps check id has written.
func (d *demo) ListSteps(_ context.Context, id string) ([]store.Step, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.checks[id]
	if !ok {
		return nil, nil
	}
	steps := make([]store.Step, c.written)
	for i, s := range c.all()[:c.written] {
		s.Seq = i + 1
		steps[i] = s
	}
	return steps, nil
}

// GetReport answers check id's report: its verdict step's findings, who
// decided, and an install spec for a pass.
func (d *demo) GetReport(_ context.Context, id string) ([]byte, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.checks[id]
	if !ok {
		return nil, false, nil
	}
	report := struct {
		Findings    []store.Finding   `json:"findings"`
		DecidedBy   string            `json:"decidedBy"`
		InstallSpec map[string]string `json:"installSpec"`
		Bound       string            `json:"bound"`
	}{Findings: []store.Finding{}, DecidedBy: c.decidedBy(), Bound: "Dynamic analysis gives a lower bound: " +
		"it shows what the server did while it was watched, not all it can do."}
	if all := c.all(); len(all) > 0 && all[len(all)-1].Name == "verdict" {
		report.Findings = append(report.Findings, all[len(all)-1].Findings...)
	}
	if c.verdict() == "pass" {
		report.InstallSpec = map[string]string{
			"kind": c.submission.Kind, "ref": c.submission.Ref,
			"dependencySha256": mailDeps, "toolListSha256": mailList,
		}
	}
	b, err := json.Marshal(report)
	if err != nil {
		return nil, false, fmt.Errorf("encode the report of check %s: %w", id, err)
	}
	return b, true, nil
}
