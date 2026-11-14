# MCP Customs: guide for sessions

This repository is the home of MCP Customs: the Brief theos builds it from,
the plan with its friction log, the diagrams and, later, the write-up. Read
[docs/plan.md](docs/plan.md) before anything else.

- **We use theos; we never change it from here.** Anything theos should do
  differently is an issue on JairJosafath/theos (labels `source/dev`,
  `status/proposed`, plus `kind/bug` or `kind/feature`), with what happened
  and when it's done, and a row in the plan's friction log naming it.
- **The session runs the factory, on the owner's machine.** The owner has
  authorized it: the session installs or reuses theos on the local Kind
  cluster, applies the Brief, watches the Crews, deploys with `cdk deploy`
  to us-east-2 with the owner's AWS profile, and mirrors the repositories to
  GitHub. It never deletes a cluster, a namespace or a repository it didn't
  make, never prints a secret, and never changes theos's own code or chart
  values beyond adding this project. Follow-up prompts go in `spec.prompts`;
  `spec.idea` is immutable once applied.
- **Only the owner can:** make the Claude token (`claude setup-token`) if the
  factory has none, give AWS credentials, upload the demo video, and press
  submit on Builder Center. Ask for these once, when they're needed, and
  carry on with everything else meanwhile.
- **The product code is built by theos's Crews** in the Container
  repositories theos makes, not here. A hand-written change there is a
  last resort after Sunday noon, and is logged with why.
- **The design is settled in docs/plan.md.** Code decides what code can;
  the model only writes probes, judges and investigates; findings in code
  can't be cleared by the model. Change the plan first, then the Brief,
  then the diagram.
- **Deadline:** Monday 2026-11-16, 13:00 PT. Scope cuts follow the ranked
  list in the plan's security review.
