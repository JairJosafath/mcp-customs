# Results

The write-up of MCP Customs for the AWS Builder Center weekend challenge
"No Pipeline, No Problem". A skeleton until the stack is deployed: every
place that needs deploy output says `TODO(deploy)`. Numbers come from the
repository's files, as of commit `025bc42` (2026-11-14, 21:13 UTC: main
at `f8990c9` with two rows of runs.md corrected), and
`hack/runs-stats -rev 025bc42` prints them again, in a full clone (it
refuses a shallow one).

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
  proxy with TLS interception, DNS and firewall logging, and the
  investigation's `/clock`, `/source` and `/download`
  (`src/cmd/harness`, `src/internal/harness`, `src/internal/egress`,
  `sandbox/Dockerfile`, whose build fails without what the harness needs;
  `src/cmd/bumpbase` moves it to a new base image).
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
  elicitation, an install that failed, observations the harness stopped
  recording. The model may only make a verdict stricter; a judge error
  or running out of turns gives review.
- **Hidden text, read closely.** Every character a person can't see is a
  finding, against Unicode 17.0.0's tables, so characters assigned after
  Go's own tables (15.0) aren't called unassigned. Control characters
  other than `\n`, `\t` and a `\r\n` are `hidden-control-character`; a
  variation selector is a finding unless Unicode gives that sequence; the
  injection patterns read every blank lookalike (U+2800, the Hangul
  fillers) as a space.
- **No way inside a network.** The egress proxy refuses a name that
  resolves to loopback, link-local, private, shared or metadata addresses
  (so `169.254.169.254.nip.io` reaches nothing), 6to4, Teredo and
  site-local included, and an install's GETs reach only public addresses.
  The stack's own API is refused at every layer, by API Gateway's
  published ranges and plain ASCII names; a judge that asks to allow it
  gets the `allow-own-api` finding.
- **The harness can't be exhausted or blinded quietly.** Observations,
  the server's sampling and elicitation requests, and its pending
  requests are capped within the 16 MiB the Checker reads; reaching a
  cap, or the file watch's limit, is an `observations-truncated` finding,
  and what would block is still recorded past a cap. Every install step
  and the run's end kill every process of the server's account, those
  that called `setsid` included.
- **Installs fail closed.** The dependency set is the resolver's, taken
  before any script runs. PyPI resolves wheels only
  (`--only-binary=:all:`) and installs `--require-hashes`, so no sdist's
  build backend runs; a server that can't be installed ends at review
  with an `install-failed` finding naming what failed.
- **The investigation's own reach.** `/clock` moves the server's clock
  with libfaketime and says whether its runtime sees the move (not a Go
  or static binary), reading only files the server's account could read;
  `/source` answers 64 KB at most of a file inside the installed package,
  refusing links and hard links; `/download` describes only a file the
  server was seen writing: size, SHA-256, kind and a 4 KB excerpt, and
  413 past 256 MB. All three work after the seal and open no egress.
- **Attacker text is evidence.** Fenced between per-call nonce markers for
  the model, escaped on the page with every invisible character shown.
- **Verdicts bound to what installs.** The hash of the whole resolved
  dependency set and the tool list; an install spec to copy. A pass's
  approval is written in one transaction with the check marked done, so
  no approval outlives a check that failed.
- **A busy model isn't a review.** The judge tries a call up to 4 times
  in all, 2, 4 and 8 seconds apart, after a throttle, a 5xx, a model timeout
  or a connection reset; the SDK's own retries are off, so a call is
  never tried more than that.
- **A person can wait.** A check short of pass waits up to 7 days for
  Approve or Block.

Left for later: remote servers (the form takes an `https://` URL, but
the harness refuses to install one, so such a check fails), a runtime
gateway pinning the approved tool list, multi-identity checks of remote
servers, argument fuzzing. Moving the clock shows nothing of a Go or
static server, the demo servers included: `/clock` says so, and the judge
is told.

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

| What                                                         | Count                                                                                                                                  |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Pull requests merged (`git log` at `025bc42`)                | 36                                                                                                                                     |
| Sessions ([runs.md](runs.md) at `025bc42`)                   | 95: 37 implementer, 58 reviewer                                                                                                        |
| Review rounds of the 36 merged issues (runs.md at `025bc42`) | 1 round: 16; 1 round and fixes after it: 1 (#43); 2 rounds: 9; 3 rounds: 10                                                            |
| Cost reported (runs.md at `025bc42`)                         | $155.85 from 50 of the 95 sessions ($83.65 implementers, $72.20 reviewers); 45 sessions reported none, so it's less than the full cost |
| First session to the last row (runs.md at `025bc42`)         | 06:27 to 21:13 UTC, 2026-11-14                                                                                                         |

`hack/runs-stats` counts these. A session is a distinct ID in runs.md. A
merged pull request is a squash commit on main whose subject ends in its
number. A session's cost is its last reported total when it has one, never
that total plus its per-round figures.

Eight pull requests merged with final commits no reviewer read:

- #34, #37, #44 and #45: the orchestrator's comment says it ran their new
  tests and saw each fail with its fix removed
  ([#34](https://github.com/JairJosafath/mcp-customs/pull/34#issuecomment-6878316223),
  [#37](https://github.com/JairJosafath/mcp-customs/pull/37#issuecomment-6878547918),
  [#44](https://github.com/JairJosafath/mcp-customs/pull/44#issuecomment-6880032402),
  [#45](https://github.com/JairJosafath/mcp-customs/pull/45#issuecomment-6879319000)).
  #34's covers its re-check guard, not its approval-condition change.
- #49: the squash commit's message on main (`f62d00d`) says the
  orchestrator verified round 3, with
  `TestARetryThatPassesLiftsTheMarkTheFailedRecheckLeft` failing when a
  retry may lift only its own ID. It says nothing of the conflicts
  `d1c3ecd` resolved by hand in `run.go`, `cmd/checker/main.go`,
  `fakes_test.go` and `api_stack.ts`.
- #41: the squash commit's message (`7e26428`) says the orchestrator read
  the post-approval `docs/results.md` changes. It says nothing of
  `31121a1`'s `--scene` test.
- #28: the orchestrator's
  [record](https://github.com/JairJosafath/mcp-customs/pull/28#issuecomment-6881578992),
  posted after the merge, says it read the round-3 diff of
  `submission.go` and `view.go` from `77e8e8f` to `7d11024` and saw the
  new test rows, did not revert the fixes itself (the implementer
  reported that check), and saw the check green on `7d11024`. It doesn't
  cover the conflicts the merge `77e8e8f` resolved by hand.
- #62: its one verdict, in round 1
  ([comment](https://github.com/JairJosafath/mcp-customs/pull/62#issuecomment-6882166497)),
  found both criteria met and tested, and blocked only on a merge
  conflict with main; its one other finding, an untested CONNECT path,
  was non-blocking. `3d078e4` merged main, leaving the tree as it was,
  and `91c2d29` added that test; no verdict read either, and no reviewer
  approved. The squash commit's message (`c05c114`) says it was approved;
  the orchestrator's
  [correction](https://github.com/JairJosafath/mcp-customs/pull/62#issuecomment-6884443216)
  says it wasn't, and that it checked the diff against main held only
  the change's five files.

Three were verified on the round limit by the orchestrator, at the head
they merged at, in place of a fresh reviewer: #63
([comment](https://github.com/JairJosafath/mcp-customs/pull/63#issuecomment-6882941234)),
#69
([comment](https://github.com/JairJosafath/mcp-customs/pull/69#issuecomment-6884074831))
and #73
([comment](https://github.com/JairJosafath/mcp-customs/pull/73#issuecomment-6883967353)).

#21, #22 and #24 merged on the round limit with the last review still
asking for changes. The orchestrator's
[note on #24](https://github.com/JairJosafath/mcp-customs/pull/24#issuecomment-6877384416)
gives the call for all three, with their findings moved to #23, #25 and
#36; #21 and #22 carry no note of their own. Fourteen pull requests
changed only by merging main after their approval: #11, #13, #15, #16,
#17, #31, #35, #47, #54, #55, #58, #64, #65 and #70, of which #17, #47,
#55, #64, #65 and #70 resolved conflicts (in #64, #65 and #70,
`CHANGELOG.md` only). For #64, #65 and #70 the squash commit's message
says the orchestrator checked that the diff against main held only the
pull request's own files.

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
- libfaketime in the built arm64 image: that Node and Python as the
  image ships them are faked, and that `LD_PRELOAD` survives the switch to
  the server's account.
- Killing every process of the account, and the file watch's limit, in
  the MicroVM.
- That real PyPI servers resolve to wheels only, and which fail closed
  for want of one.
- The demo servers' real traffic through the proxy, and the recorder's
  selectors against the deployed page (tested here against the web stub,
  `src/cmd/webstub`).

TODO(deploy): what the first real check showed, and every item above that
it confirmed or broke.
