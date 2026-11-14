package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/JairJosafath/mcp-customs/src/internal/findings"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
)

// visible is text as a person may see it: each character a person can't
// see but a model reads, shown as a Go escape such as ​. It starts
// from findings.ScanText's escaped form, then escapes every other rune
// that isn't a printable character (controls, format characters such as
// the interlinear annotations U+FFF9 to U+FFFB, line and paragraph
// separators, private-use, surrogate and unassigned code points), every
// variation selector but U+FE0E and U+FE0F, which follow most emoji, and
// every default-ignorable code point. A tab and a new line stay as they
// are. html/template escapes the rest for HTML.
func visible(text string) string {
	escaped := findings.ScanText(text).Escaped
	var b strings.Builder
	for _, r := range escaped {
		if hiddenRune(r) {
			b.WriteString(escapeRune(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hiddenRune reports whether r is one a person can't see.
func hiddenRune(r rune) bool {
	switch r {
	case '\n', '\t', 0xFE0E, 0xFE0F:
		return false
	case unicode.ReplacementChar, 0x2800:
		// U+2800, the blank Braille pattern, is graphic but shows nothing.
		return true
	}
	return !unicode.IsGraphic(r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// escapeRune is r as a Go escape: \uXXXX, or \UXXXXXXXX beyond the BMP.
func escapeRune(r rune) string {
	if r <= 0xFFFF {
		return fmt.Sprintf(`\u%04X`, r)
	}
	return fmt.Sprintf(`\U%08X`, r)
}

// homeView is the home page's: the form, and what was wrong with the last
// submission, if anything.
type homeView struct {
	Service string
	Message string
	// Kind is the kind submitted last, which the form offers first.
	Kind string
	Ref  string
}

// kindOption is one kind the form offers.
type kindOption struct{ Value, Label string }

// kindOptions are the kinds the form offers, in order.
var kindOptions = []kindOption{
	{"npm", "npm package"}, {"pypi", "PyPI package"}, {"go", "Go module"}, {"remote", "Remote URL"},
}

// Kinds are the form's kinds, the one submitted last first, so the browser
// selects it without a template action inside a tag.
func (v homeView) Kinds() []kindOption {
	out := make([]kindOption, 0, len(kindOptions))
	for _, k := range kindOptions {
		if k.Value == v.Kind {
			out = append([]kindOption{k}, out...)
		} else {
			out = append(out, k)
		}
	}
	return out
}

// messageView is a page that says one thing, with a link back.
type messageView struct {
	Service string
	Message string
	Back    string
}

// findingView is a finding as the page and the API show it.
type findingView struct {
	Source   string `json:"source"`
	Rule     string `json:"rule"`
	Evidence string `json:"evidence"`
}

// stepView is a step as the page and the API show it.
type stepView struct {
	Seq      int           `json:"seq"`
	Name     string        `json:"name"`
	Summary  string        `json:"summary"`
	Findings []findingView `json:"findings"`
}

// installSpecView is what a developer copies to install exactly what was
// approved.
type installSpecView struct {
	Kind           string `json:"kind"`
	Ref            string `json:"ref"`
	DependencyHash string `json:"dependencySha256"`
	ToolListHash   string `json:"toolListSha256"`
}

// checkView is a check as its page and GET /api/checks/<id> show it. Every
// string from the store or the report has been through visible, so a
// hidden character shows as an escape in either.
type checkView struct {
	CheckID    string           `json:"checkId"`
	Status     string           `json:"status"`
	Submission store.Submission `json:"submission"`
	// Verdict is pass, review or block once the check is done.
	Verdict   string        `json:"verdict,omitempty"`
	DecidedBy string        `json:"decidedBy,omitempty"`
	Steps     []stepView    `json:"steps"`
	Findings  []findingView `json:"findings"`
	// InstallSpec is given for a pass only.
	InstallSpec *installSpecView `json:"installSpec,omitempty"`
	Bound       string           `json:"bound,omitempty"`
	// Waiting says a person may Approve or Block it now.
	Waiting bool `json:"-"`
	// Service names the service on the page.
	Service string `json:"-"`
	// Found says the check exists; a check just submitted has no META yet.
	Found bool `json:"-"`
}

// InstallSpecJSON is the install spec as the page shows it, to copy.
func (v checkView) InstallSpecJSON() string {
	if v.InstallSpec == nil {
		return ""
	}
	b, _ := json.MarshalIndent(v.InstallSpec, "", "  ")
	return string(b)
}

// reportDoc is the part of a check's report (docs/contracts.md, the
// Checker's Report) the web function shows.
type reportDoc struct {
	Verdict     string          `json:"verdict"`
	Findings    []store.Finding `json:"findings"`
	DecidedBy   string          `json:"decidedBy"`
	InstallSpec installSpecView `json:"installSpec"`
	Bound       string          `json:"bound"`
}

// statuses are the statuses a check may have; anything else shows as unknown.
var statuses = map[store.Status]bool{
	store.StatusRunning: true, store.StatusWaiting: true, store.StatusDone: true, store.StatusFailed: true,
}

// verdicts are the verdicts a check may have; anything else shows as review.
var verdicts = map[string]bool{"pass": true, "review": true, "block": true}

// buildView is check c's view, from its steps and, once it is done, its
// report (nil before). A report that isn't the Checker's JSON is an error.
func buildView(c store.Check, steps []store.Step, report []byte) (checkView, error) {
	v := checkView{
		CheckID:    c.ID,
		Status:     "unknown",
		Submission: store.Submission{Kind: visible(c.Submission.Kind), Ref: visible(c.Submission.Ref)},
		Steps:      make([]stepView, 0, len(steps)),
		Findings:   []findingView{},
		Service:    serviceName,
		Found:      true,
	}
	if statuses[c.Status] {
		v.Status = string(c.Status)
	}
	v.Waiting = c.Status == store.StatusWaiting && c.CallbackID != ""
	for _, s := range steps {
		v.Steps = append(v.Steps, stepView{Seq: s.Seq, Name: visible(s.Name), Summary: visible(s.Summary), Findings: findingViews(s.Findings)})
	}
	if c.Status != store.StatusDone {
		return v, nil
	}
	v.Verdict = c.Verdict
	if !verdicts[v.Verdict] {
		v.Verdict = "review"
	}
	if report == nil {
		return v, nil
	}
	var doc reportDoc
	if err := json.Unmarshal(report, &doc); err != nil {
		return checkView{}, fmt.Errorf("read the report of check %s: %w", c.ID, err)
	}
	v.DecidedBy = visible(doc.DecidedBy)
	v.Findings = findingViews(doc.Findings)
	v.Bound = visible(doc.Bound)
	if v.Verdict == "pass" {
		v.InstallSpec = &installSpecView{
			Kind:           visible(doc.InstallSpec.Kind),
			Ref:            visible(doc.InstallSpec.Ref),
			DependencyHash: visible(doc.InstallSpec.DependencyHash),
			ToolListHash:   visible(doc.InstallSpec.ToolListHash),
		}
	}
	return v, nil
}

func findingViews(fs []store.Finding) []findingView {
	out := make([]findingView, 0, len(fs))
	for _, f := range fs {
		out = append(out, findingView{Source: visible(f.Source), Rule: visible(f.Rule), Evidence: visible(f.Evidence)})
	}
	return out
}
