# MCP Customs: guide for sessions

This repository is the home of MCP Customs: the Brief theos builds it from,
the plan with its friction log, the diagrams and, later, the write-up. Read
[docs/plan.md](docs/plan.md) before anything else.

- **We use theos; we never change it from here.** Anything theos should do
  differently is an issue on JairJosafath/theos (labels `source/dev`,
  `status/proposed`, plus `kind/bug` or `kind/feature`), with what happened
  and when it's done, and a row in the plan's friction log naming it.
- **The cloud route.** For the weekend, cloud sessions play theos's Crew
  roles and one orchestrator session plays its operator
  ([docs/kickoff.md](docs/kickoff.md)). theos's own parts are used as they
  are: its templates and Standards (rendered with theos's `hack/render`), its
  CRDs for the model, its role guides for the sessions. Nothing runs a
  cluster. After the deadline the same Brief runs in the real factory, for
  comparison.
- **Only the owner can:** create GitHub repositories, give AWS access for
  the deploy, upload the demo video, and press submit on Builder Center.
  Ask for these once, when they're needed, and carry on with everything
  else meanwhile.
- **The product code lives in the Container repositories**
  (`mcp-customs-checker`, `-sandbox`, `-web`), one per Container as theos
  wants, built by implementer sessions from issues. The orchestrator writes
  no product code; a hand-written change is a last resort after Sunday
  noon, and is logged with why.
- **The design is settled in docs/plan.md.** Code decides what code can;
  the model only writes probes, judges and investigates; findings in code
  can't be cleared by the model. Change the plan first, then the Brief,
  then the diagram.
- **Deadline:** Monday 2026-11-16, 13:00 PT. Scope cuts follow the ranked
  list in the plan's security review.
