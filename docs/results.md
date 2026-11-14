# Results

The write-up of MCP Customs for the AWS Builder Center weekend challenge
"No Pipeline, No Problem", and what building it said about theos. A
skeleton until the stack is deployed: every place that needs deploy
output says `TODO(deploy)`. Numbers come from the repository's files, as
of commit `6aae615` (2026-11-14); update them from
[runs.md](runs.md) and the [friction log](plan.md#friction-log) before
submitting.

## What was built

MCP Customs checks an MCP server before an AI agent may use it. It
installs the server in a Lambda MicroVM, runs it with fresh canary secrets
planted in a fake developer's home, watches its network and files, and
answers pass, review or block with a report that says why
([plan.md, "The product"](plan.md#the-product)).

- The Checker, a Lambda durable function in Go: the fixed checks, the
  action registry, the judge and its investigation loop
  (`src/cmd/checker`, `src/internal/checker`).
- The sandbox harness in a MicroVM image: install, MCP client, egress
  proxy with TLS interception, DNS and firewall logging
  (`src/cmd/harness`, `src/internal/harness`, `src/internal/egress`,
  `sandbox/Dockerfile`).
- Code-only findings, canaries and the verdict rules
  (`src/internal/findings`, `src/internal/canary`, `src/internal/verdict`).
- The web page and JSON API behind API Gateway (`src/cmd/web`,
  `src/internal/web`).
- Two malicious demo servers: a poisoned weather tool and a rug-pulled
  mail tool (`src/demo`).
- One CDK app for all of it (`infra/`), checked by CDK Nag and cfn-lint.

TODO(deploy): the stack's region, its URL, and how long one check takes.

## The architecture

The C4 views are [docs/c4.html](c4.html): the system context, the
containers, and where code decides and where the model judges. In short: a person or an
agent submits a server to the web function; it starts the Checker, which
launches a MicroVM, drives the harness over HTTPS with a per-run token,
asks Claude on Amazon Bedrock to write probes and judge, and keeps every
step in DynamoDB and the report in S3. The web page shows the steps as
they are written. How the parts fit is in [contracts.md](contracts.md).

TODO(deploy): the diagram exported as an image for the Builder Center
post.

## The security design

Code decides everything code can; the model only writes probes, judges
and investigates, one registered action a turn, at most 8. The design
came from a security review ([plan.md, "Security
review"](plan.md#security-review)):

- **Watch behaviour, not descriptions.** The server runs; all its text
  (tools, schemas, resources, prompts, results) is scanned by code and
  judged by the model.
- **Canaries, traced.** Fresh fake secrets per run in real formats, found
  by the egress proxy in intercepted TLS, plain, base64, hex or
  URL-encoded. Egress is denied by default; unexpected hosts get fake
  answers so a second stage still shows.
- **Findings the model can't clear.** Hidden characters, a canary leaving,
  writes to agent configs or shell startup files, unexplained sampling or
  elicitation. The model may only make a verdict stricter; a judge error
  or running out of turns gives review.
- **Attacker text is evidence.** Fenced between per-call nonce markers for
  the model, escaped on the page with every invisible character shown.
- **Verdicts bound to what installs.** The hash of the whole resolved
  dependency set and the tool list; an install spec to copy.
- **A person can wait.** A check short of pass waits up to 7 days for
  Approve or Block.

Left for later: a runtime gateway pinning the approved tool list,
multi-identity checks of remote servers, argument fuzzing.

## What the demo shows

The video is `demo/record.ts` driving the deployed page, narrated with
[demo/script.md](../demo/script.md):

1. **The weather server: block.** A clean tool list; a result that asks
   for `~/.ssh/id_ed25519`; the planted key seen leaving, base64-encoded;
   a person blocks it.
2. **The mail server v1.0.0: pass,** with its install spec, no person
   needed.
3. **The mail server v1.0.1: block.** The poller's re-check of the
   approved v1.0.0 (#34): the same tool list, probed all the same; the
   planted address copied out.

Each scene has its own budget, its slots in the script, summing to 2:50.
If real checks run longer, `--scene` records each scene to its own file
to cut together.

TODO(deploy): the video's link and length, and each check's duration.
TODO(deploy): the refs the demo servers are published under, passed as
`--weather` and `--mail`, and the re-check's page, `--recheck-url`.

## The numbers

From [runs.md](runs.md), one row per cloud session. Cost is each session's
own report; where a session reported a running total, that total counts
once.

| What                                   | As of `6aae615`                                                     |
| -------------------------------------- | ------------------------------------------------------------------- |
| Cloud sessions                         | 48: 19 implementer, 29 reviewer                                     |
| Sessions that reported a cost          | 27 of 48                                                            |
| Cost reported                          | $96.18: $63.74 implementers, $32.44 reviewers                       |
| Issues worked                          | 18                                                                  |
| Pull requests merged                   | 15, counted from `git log` (squash commits ending in the PR number) |
| Rounds of the 15 merged issues         | 1 round: 7; 2 rounds: 3; 3 rounds: 5                                |
| Wall clock, first session to `6aae615` | 06:27 to 13:57 UTC, 2026-11-14                                      |

TODO(deploy): final rows, the cost of the sessions that didn't report
one, and the deploy's own time and AWS cost.

## What theos built alone, with a prompt, with a hand

What the plan's "Done when" asks for.

- **Alone:** every product change came from an implementer session working
  an issue, and a reviewer session read each pull request. #22, #24, #34
  and #37 merged with commits no reviewer read: their last rounds were
  accepted on the orchestrator's own checks or on the round limit, and the
  pull requests' comments say how.
- **With a prompt:** the orchestrator filed follow-up issues where a review
  found a hole the pull request didn't open (#23, #25, #33, #36), and
  posted replies for implementers.
- **With a hand:** three pull requests, #21, #22 and #24, merged after
  their third round with the reviewer still requesting changes; the
  orchestrator decided it and filed the findings as follow-ups (#23, #25,
  #36; [friction row 20](plan.md#friction-log)). #34 had two reviews: its
  third round, the implementer's push after round 2's only blocking
  finding, a merge conflict with #35, was checked by the orchestrator, not
  reviewed (row 21; follow-ups #40, #42).
  TODO(deploy): the deploy and any hand-written fix after Sunday noon.

## theos's feedback

The [friction log](plan.md#friction-log) has 21 rows. None has blocked
the build yet; row 2, durable functions and MicroVMs in the CDK app, is
still to be seen until the deploy. In groups:

- **Deploy and hosting:** no AWS deploy (row 1), no template for durable
  functions or MicroVMs (2, still to be seen), repositories in Gitea (3).
- **The Standard's checks:** no limits on function size (4,
  [theos#262](https://github.com/JairJosafath/theos/issues/262)); a
  durable function trips three rules (11,
  [theos#275](https://github.com/JairJosafath/theos/issues/275)); gosec
  and `nilerr` against fixtures and handlers (15, 19,
  [theos#279](https://github.com/JairJosafath/theos/issues/279)); a
  deletable bucket fails the Standard's own tests (18,
  [theos#283](https://github.com/JairJosafath/theos/issues/283)).
- **Template and scaffolding:** CI needs an operator's variable (6, 9,
  [theos#263](https://github.com/JairJosafath/theos/issues/263)); wrong
  names from `hack/render` (7,
  [theos#264](https://github.com/JairJosafath/theos/issues/264)); one
  repository per Container (8,
  [theos#270](https://github.com/JairJosafath/theos/issues/270)); a second
  function got the first one's binary (10,
  [theos#274](https://github.com/JairJosafath/theos/issues/274)); tool
  versions disagree (14,
  [theos#278](https://github.com/JairJosafath/theos/issues/278)).
- **Role guides:** they assume the operator, Gitea and one Lambda handler
  (13, 19, [theos#277](https://github.com/JairJosafath/theos/issues/277));
  a runbook change is a Standard change (12, 16,
  [theos#276](https://github.com/JairJosafath/theos/issues/276),
  [theos#282](https://github.com/JairJosafath/theos/issues/282)); no exit
  from the round limit but a person (20,
  [theos#302](https://github.com/JairJosafath/theos/issues/302)); no
  subagents per role (5,
  [theos#259](https://github.com/JairJosafath/theos/issues/259),
  [theos#260](https://github.com/JairJosafath/theos/issues/260)).
- **The Standard's checks, again:** `make check` runs no build-tagged
  tests and CI runs as non-root, so the egress tests skip there; main
  moving between rounds cost #34 a round (21,
  [theos#303](https://github.com/JairJosafath/theos/issues/303)).
- **The cloud route, not theos:** implementer and reviewer sessions share
  the owner's GitHub account, so a review is a comment, never an approval
  or a request for changes (17).

## Unverified until deploy

What only a real AWS account shows, from the pull requests' own notes:

- Lambda MicroVMs: the snapshot, the run hook, the harness's firewall
  with `additionalOsCapabilities`, egress, and the 2-hour lifetime.
- The durable Checker: replay, a callback that waits days, and the web
  function's async invoke with `DurableExecutionName`.
- Bedrock: the inference profile, the judge's tool answers on real
  servers, retries.
- IAM at run time, throttling, cold starts, and the alarms' dimensions.
- The demo servers' real traffic through the proxy, and the recorder's
  selectors against the deployed page (tested here against the web stub,
  `src/cmd/webstub`).

TODO(deploy): what the first real check showed, and every item above that
it confirmed or broke.
