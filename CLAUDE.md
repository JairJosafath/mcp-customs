# MCP Customs: guide for sessions

This repository is the home of MCP Customs: the Brief theos builds it from,
the plan with its friction log, the diagrams, the code and, later, the
write-up. Read [docs/plan.md](docs/plan.md) before anything else,
[docs/contracts.md](docs/contracts.md) for how the parts fit, and
[AGENTS.md](AGENTS.md) before changing code: it is theos's aws-standard,
the rules `make check` and the reviewer hold every change to.

- **We use theos; we never change it from here.** Anything theos should do
  differently is an issue on JairJosafath/theos (labels `source/dev`,
  `status/proposed`, plus `kind/bug` or `kind/feature`), with what happened
  and when it's done, and a row in the plan's friction log naming it.
- **The cloud route.** For the weekend, cloud sessions play theos's Crew
  roles and one orchestrator session plays its operator
  ([docs/kickoff.md](docs/kickoff.md)). theos's own parts are used as they
  are: its template and Standard (rendered with theos's `hack/render`) and
  its role guides for the sessions. Nothing runs a cluster. After the deadline the same Brief runs in the real factory, for
  comparison.
- **Only the owner can:** give AWS access for the deploy, upload the demo
  video, and press submit on Builder Center. Ask for these once, when they're needed, and carry on with everything
  else meanwhile.
- **One repository.** The owner chose simplicity over theos's one
  repository per Container: the Checker, the web function, the sandbox
  harness and the demo servers are packages under `src/`, deployed by one
  CDK app in `infra/`. Implementer sessions build it from issues here; the
  orchestrator writes no product code, and a hand-written change is a last
  resort after Sunday noon, logged with why.
- **The design is settled in docs/plan.md.** Code decides what code can;
  the model only writes probes, judges and investigates; findings in code
  can't be cleared by the model. Change the plan first, then the Brief,
  then the diagram.
- **Deadline:** Monday 2026-11-16, 13:00 PT. Scope cuts follow the ranked
  list in the plan's security review.
- **Tooling for `make check`:** Go 1.26, Node 22, `uv`, and golangci-lint
  v2.13.1 or later built with Go 1.26: `GOTOOLCHAIN=go1.26.0 go install
github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1`, then put
  `$(go env GOPATH)/bin` first on the PATH. An older golangci-lint refuses
  the module's Go version.
