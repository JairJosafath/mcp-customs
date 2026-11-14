package checker

import (
	"fmt"
	"testing"

	"github.com/aws/aws-durable-execution-sdk-go/durable/durabletest"

	"github.com/JairJosafath/mcp-customs/src/internal/demoscene"
	"github.com/JairJosafath/mcp-customs/src/internal/store"
	"github.com/JairJosafath/mcp-customs/src/internal/verdict"
)

// demoRun runs the check in, in w, to its end, answering decision when
// it waits for a person, and answers the steps it wrote, its verdict and
// its report.
func demoRun(t *testing.T, w *world, in Input, decision string) ([]store.Step, verdict.Verdict, Report) {
	t.Helper()
	before := len(w.rec.steps)
	runner := durabletest.NewLocalRunner(Handler(w.deps()))
	result, err := runner.RunUntilComplete(in)
	if err != nil {
		t.Fatal(err)
	}
	if open := runner.OpenCallbacks(); len(open) > 0 {
		if decision == "" {
			t.Fatalf("check %s waits for a person; the scene says it doesn't", in.CheckID)
		}
		if err := runner.SendCallbackSuccess(open[0].CallbackID, HumanAnswer{Decision: decision}); err != nil {
			t.Fatal(err)
		}
		if result, err = runner.RunUntilComplete(in); err != nil {
			t.Fatal(err)
		}
	}
	out, err := durabletest.ResultAs[Output](result)
	if err != nil {
		t.Fatalf("%v:\n%s", err, result.FormatTree())
	}
	report, _ := w.reports.reportOf(in.CheckID)
	return w.rec.steps[before:], out.Verdict, report
}

// sameSteps fails t on any difference between the Checker's steps and the
// scene's: a missing or extra step, or a step's name, summary or findings.
func sameSteps(t *testing.T, scene string, got, want []store.Step) {
	t.Helper()
	for i := range max(len(got), len(want)) {
		var g, w store.Step
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g.Name != w.Name || g.Summary != w.Summary || fmt.Sprint(g.Findings) != fmt.Sprint(w.Findings) {
			t.Errorf("%s: step %d is\n  %s | %s | %v\nthe Checker writes\n  %s | %s | %v", scene, i+1, w.Name, w.Summary, w.Findings, g.Name, g.Summary, g.Findings)
		}
	}
}

// mailNextAfter runs v1.0.0 and the re-check of v1.0.1 the poller would
// start, answering decision, and answers the re-check's run.
func mailNextAfter(t *testing.T, decision string) ([]store.Step, verdict.Verdict, demoscene.Params) {
	t.Helper()
	first := newWorld(demoMail("v1.0.0"))
	first.judge = mailJudge()
	old := store.Submission{Kind: "npm", Ref: "mail-mcp@1.0.0"}
	_, _, approved := demoRun(t, first, Input{CheckID: "c0", Submission: old}, "")
	second := newWorld(demoMail("v1.0.1"))
	second.rec, second.judge = first.rec, mailJudge()
	sub := store.Submission{Kind: "npm", Ref: "mail-mcp@1.0.1"}
	in := Input{CheckID: "c1", Submission: sub, Recheck: &Recheck{CheckID: "c0", Ref: old.Ref, ToolListHash: approved.InstallSpec.ToolListHash}}
	steps, v, report := demoRun(t, second, in, decision)
	return steps, v, demoscene.Params{
		Submission: sub, DependencyHash: report.InstallSpec.DependencyHash, ToolListHash: report.InstallSpec.ToolListHash,
		Approved: &demoscene.Approved{CheckID: "c0", Ref: old.Ref},
	}
}

func TestTheWebStubsDemoScenesAreWhatTheCheckerWritesFromItsFakes(t *testing.T) {
	weather := store.Submission{Kind: "npm", Ref: "weather-mcp@1.0.0"}
	mail := store.Submission{Kind: "npm", Ref: "mail-mcp@1.0.0"}
	for _, decision := range []string{DecisionBlock, DecisionApprove} {
		t.Run("weather, a person chose to "+decision, func(t *testing.T) {
			w := newWorld(demoWeather())
			w.judge = &recordedJudge{probes: "probes_forecast", judgement: "judgement_poisoned", moves: []string{"move_probe_with_key", "move_ask_human"}}
			got, v, report := demoRun(t, w, Input{CheckID: "c1", Submission: weather}, decision)
			scene := demoscene.Weather(demoscene.Params{Submission: weather, DependencyHash: report.InstallSpec.DependencyHash, ToolListHash: report.InstallSpec.ToolListHash})
			after, want := scene.Decided(decision)
			if !scene.Waits || v != want {
				t.Errorf("the scene waits %t and ends at %s; the Checker ends at %s", scene.Waits, want, v)
			}
			sameSteps(t, "weather", got, append(scene.Steps, after...))
		})
		t.Run("mail-next, a person chose to "+decision, func(t *testing.T) {
			got, v, p := mailNextAfter(t, decision)
			scene := demoscene.MailNext(p)
			after, want := scene.Decided(decision)
			if !scene.Waits || v != want {
				t.Errorf("the scene waits %t and ends at %s; the Checker ends at %s", scene.Waits, want, v)
			}
			sameSteps(t, "mail-next", got, append(scene.Steps, after...))
		})
	}
	t.Run("mail", func(t *testing.T) {
		w := newWorld(demoMail("v1.0.0"))
		w.judge = mailJudge()
		got, v, report := demoRun(t, w, Input{CheckID: "c1", Submission: mail}, "")
		scene := demoscene.Mail(demoscene.Params{Submission: mail, DependencyHash: report.InstallSpec.DependencyHash, ToolListHash: report.InstallSpec.ToolListHash})
		if scene.Waits || v != scene.Verdict {
			t.Errorf("the scene waits %t and ends at %s; the Checker ends at %s", scene.Waits, scene.Verdict, v)
		}
		sameSteps(t, "mail", got, scene.Steps)
	})
}
