# Results

The write-up of MCP Customs for the AWS Builder Center weekend challenge
"No Pipeline, No Problem", and what building it said about theos. A
skeleton until the stack is deployed: every place that needs deploy
output says `TODO(deploy)`. Numbers come from the repository's files, as
of commit `e62605f` (2026-11-14, 17:02 UTC); `hack/runs-stats` prints
them again from [runs.md](runs.md) and `git log` at any commit. Update
them, and the [friction log](plan.md#friction-log)'s, before submitting.

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

Counted by `hack/runs-stats` (`src/internal/runstats`) from
[runs.md](runs.md) as of commit `e62605f`, and from `git log
--first-parent` at `e62605f`. Run `hack/runs-stats -rev <commit>` to count
again at another commit.

How it counts:

- A session is a distinct `session_…` ID in runs.md's Session column, and
  is an implementer or a reviewer by the Role of its rows. A row without
  an ID is left out: one, #59's own row, "(started 17:02)".
- A merged pull request is a squash commit on main's first-parent history
  whose subject ends in its number, `(#12)`.
- A merged issue is the one whose rows name the merged pull request,
  "PR #12". Its rounds are the highest Rounds among its implementer and
  reviewer rows; `1+` is how runs.md writes #43's round 1 with fixes
  pushed after it that no round counts.
- A session's cost is its last "$N total" cell when it has one, which
  already holds its rounds, else the sum of its per-round cells. So #6's
  implementer counts $7.74, not $6.38 + $7.74, and #5's implementer counts
  $11.89 once, from the row it reported on under #36.

| What (all from runs.md at `e62605f`, but the merges) | Count                                                                                                                                                           |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cloud sessions                                       | 66: 26 implementer, 40 reviewer                                                                                                                                 |
| Sessions that reported a cost                        | 34 of 66: 10 of 26 implementers, 24 of 40 reviewers                                                                                                             |
| Sessions that reported no cost                       | 32: 16 implementer, 16 reviewer                                                                                                                                 |
| Cost reported                                        | $112.46: $63.74 implementers, $48.72 reviewers                                                                                                                  |
| Issues with a row                                    | 27                                                                                                                                                              |
| Pull requests merged (`git log` at `e62605f`)        | 24: #11, #12, #13, #15, #16, #17, #21, #22, #24, #26, #28, #29, #31, #34, #35, #37, #41, #44, #45, #47, #49, #52, #54, #55                                      |
| Rounds of the 24 merged issues                       | 1 round: 11 (#1, #3, #6, #14, #20, #23, #25, #30, #46, #48, #53); 1+: 1 (#43); 2 rounds: 5 (#2, #4, #8, #38, #40); 3 rounds: 7 (#5, #7, #9, #10, #19, #36, #42) |
| Rows started                                         | 06:27 to 17:02 UTC, 2026-11-14                                                                                                                                  |

At commit `69774e5`, which the issue counted at, runs.md had 64 distinct
IDs; `e62605f` added #56's and #51's reviewers.

TODO(deploy): final rows, the cost of the sessions that didn't report
one, and the deploy's own time and AWS cost.

## What theos built alone, with a prompt, with a hand

What the plan's "Done when" asks for. Every product change came from an
implementer session working an issue, and a reviewer session read each
pull request at least once. How each of the 24 merges stood against its
last review, checked against each pull request's commits and comments on
GitHub (every session posts as the same account, so a review is a comment
starting `VERDICT:`, and an orchestrator's note says so):

**1. Code no reviewer read after the last review: 7.** The last round's
commits were accepted on the orchestrator's own checks, on the round
limit, or on nothing written down.

- [#28](https://github.com/JairJosafath/mcp-customs/pull/28): after the
  approval of `9659883`, `b80498e` (host zones, percent-encoding, NAT64)
  and `7d11024` (U+2800), the fixes for two non-blocking findings. No
  comment says what was checked.
- [#34](https://github.com/JairJosafath/mcp-customs/pull/34): round 2
  asked for changes; `745122c` (a merge with conflicts in `run.go`) and
  `d58f02c` (the re-check's approval gated on the newest polled version)
  came after. The orchestrator
  [checked](https://github.com/JairJosafath/mcp-customs/pull/34#issuecomment-6878316223)
  that the re-check guard holds and its test fails without it, and CI; it
  names nothing of `d58f02c`'s `PutApproved` change.
- [#37](https://github.com/JairJosafath/mcp-customs/pull/37): round 2
  asked for changes; `f8dc581` (the whole ClientHello, a held body) came
  after. The orchestrator
  [checked](https://github.com/JairJosafath/mcp-customs/pull/37#issuecomment-6878547918)
  the egress and findings tests as root, that the ClientHello test fails
  without the search, and 50 runs of the held-body and starvation tests.
- [#41](https://github.com/JairJosafath/mcp-customs/pull/41): after the
  approval of `20a9af5`, `60ec7f4` (this file's merge account) and
  `31121a1` (a `--scene` test). No comment says what was checked.
- [#44](https://github.com/JairJosafath/mcp-customs/pull/44): after the
  approval of `9c8e956`, `d92bb21` (an install's GET of a demo module
  path, and its test) and `dece8b6` (the Makefile). The orchestrator
  [checked](https://github.com/JairJosafath/mcp-customs/pull/44#issuecomment-6880032402)
  the new test passes under `-race` and fails when `admit` decides by host
  alone, the packages, and CI.
- [#45](https://github.com/JairJosafath/mcp-customs/pull/45): after the
  approval of `e9edd50`, `b1d7455` (the seal waits for requests in
  flight) and `b6ac750` (its test). The orchestrator
  [checked](https://github.com/JairJosafath/mcp-customs/pull/45#issuecomment-6879319000)
  both seal tests under `-race`, that the second fails without
  `e.inflight.Wait()`, and CI.
- [#49](https://github.com/JairJosafath/mcp-customs/pull/49): round 2
  asked for changes; `8acc925` (the fix), two runbook commits and
  `d1c3ecd` (a merge with conflicts resolved by hand in the Checker and
  the stack) came after, with no third review. runs.md says the
  orchestrator verified it, but no comment on the pull request or #42
  says what was checked.

**2. Merged on the round limit with the last review asking for changes,
which read every commit but a merge of main: 3.**
[#21](https://github.com/JairJosafath/mcp-customs/pull/21) (no commit
after it) and [#22](https://github.com/JairJosafath/mcp-customs/pull/22)
(`5988195`, a merge of main): no comment explains the merge; their
findings went to #23 and #25.
[#24](https://github.com/JairJosafath/mcp-customs/pull/24) (`469da36`, a
merge of main): the orchestrator's
[comment](https://github.com/JairJosafath/mcp-customs/pull/24#issuecomment-6877384416)
moves round 3's findings to #36 on the round limit, and checks nothing of
its own. #34, #37 and #49 above also merged on a review asking for
changes.

**3. Only merges of main after the approval: 10.** #11, #13, #15, #16,
#17, #31, #35, #47, #54 and #55. Three of those merges resolved
conflicts: #17's took main's harness, #47's kept both sides of
`CHANGELOG.md`, and #55's kept both sides in `CHANGELOG.md`,
`finding.go` and `verdict.go`.

**4. Nothing after the approval: 4.** #12, #26, #29 and #52.

The issue that asked for this account (#59) listed #22, #24, #34, #37,
#41, #44, #45 and #49 under 1, and #28, #31, #47 and #55 under 2. #22 and
#24 had no unread code, only a review asking for changes; #28 had unread
code; and six more pull requests had only merges of main after approval.

- **With a prompt:** the orchestrator filed the follow-up issues runs.md
  names from reviews and merges (#23, #25, #30, #32, #33, #36, #39, #42,
  #43, #46, #48, #50, #51, #53, #56), and posted replies for implementers.
- **With a hand:** the round limit ended six pull requests with the last
  review asking for changes (#21, #22, #24, #34, #37, #49); the
  orchestrator decided each and filed the findings as follow-ups
  ([friction row 20](plan.md#friction-log)).
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
