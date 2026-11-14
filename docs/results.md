# Results

The write-up of MCP Customs for the AWS Builder Center weekend challenge
"No Pipeline, No Problem". A skeleton until the stack is deployed: every
place that needs deploy output says `TODO(deploy)`. Numbers come from the
repository's files, as of commit `fc2b5cd` (2026-11-14, 17:19 UTC), and
`hack/runs-stats` prints them again at any commit, in a full clone (it refuses a shallow one).

## The problem

An AI agent that installs an MCP server runs someone else's code with the
developer's keys, files and network. Scanners read what a server says
about itself: its tool descriptions and schemas. A malicious server can
say nothing wrong and still read `~/.ssh` and send it out once it runs, or
pass review at one version and turn at the next. MCP Customs checks what a
server does, before an agent may use it.

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

## How it was built

Built with [theos](https://github.com/JairJosafath/theos), by Claude Code
cloud sessions in implementer and reviewer roles. Each pull request was
written by an implementer session and read by a separate reviewer
session.

| What                                          | Count                                                                                                                                  |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Pull requests merged (`git log` at `fc2b5cd`) | 24                                                                                                                                     |
| Sessions ([runs.md](runs.md) at `fc2b5cd`)    | 68: 27 implementer, 41 reviewer                                                                                                        |
| Review rounds of the 24 merged issues         | 1 round: 11; 1 round and fixes after it: 1 (#43); 2 rounds: 5; 3 rounds: 7                                                             |
| Cost reported (runs.md at `fc2b5cd`)          | $112.46 from 34 of the 68 sessions ($63.74 implementers, $48.72 reviewers); 34 sessions reported none, so it's less than the full cost |
| First session to the last row                 | 06:27 to 17:19 UTC, 2026-11-14                                                                                                         |

`hack/runs-stats` counts these. A session is a distinct ID in runs.md. A
merged pull request is a squash commit on main whose subject ends in its
number. A session's cost is its last reported total when it has one, never
that total plus its per-round figures.

Seven pull requests merged with final commits no reviewer read. For #34,
#37, #44 and #45, the orchestrator's comment says it ran their new tests
and saw each fail with its fix removed
([#34](https://github.com/JairJosafath/mcp-customs/pull/34#issuecomment-6878316223),
[#37](https://github.com/JairJosafath/mcp-customs/pull/37#issuecomment-6878547918),
[#44](https://github.com/JairJosafath/mcp-customs/pull/44#issuecomment-6880032402),
[#45](https://github.com/JairJosafath/mcp-customs/pull/45#issuecomment-6879319000);
#34's covers its re-check guard, not its approval-condition change). For
the other three, the squash commit's message on main is the record:
#49's (`f62d00d`) says the orchestrator verified round 3, with
`TestARetryThatPassesLiftsTheMarkTheFailedRecheckLeft` failing when a
retry may lift only its own ID; #41's (`7e26428`) says the orchestrator
read the post-approval `docs/results.md` changes; #28's (`4ae4677`) names
round 3's fixes, each with tests, and a green check on `7d11024`, but not
who read them. #21, #22
and #24 merged on the round limit with the last review still asking for
changes. The orchestrator's
[note on #24](https://github.com/JairJosafath/mcp-customs/pull/24#issuecomment-6877384416)
gives the call for all three, with their findings moved to #23, #25 and
#36; #21 and #22 carry no note of their own.

TODO(deploy): final rows, the cost of the sessions that reported none, and
the deploy's own time and AWS cost.

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
