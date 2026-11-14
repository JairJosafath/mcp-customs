# Contracts between the parts

The parts of docs/c4.html are packages in one Go module (`src/`), built by
different sessions at once. This file is what they agree on. Change it in
the same pull request as the code that needs the change, and say so in the
pull request.

## Layout

| Path                                | What                                                                                                               |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `src/cmd/checker`                   | The Checker: the durable function's `main`                                                                         |
| `src/cmd/web`                       | The web and API function's `main`                                                                                  |
| `src/cmd/poller`                    | The poller's `main`: run on a schedule, it re-checks approved packages' new versions                               |
| `src/cmd/harness`                   | The sandbox harness's `main`, run in the MicroVM image                                                             |
| `src/internal/findings`             | Code-only findings: hidden characters, injection patterns, canary matching. No model, no network                   |
| `src/internal/canary`               | Fresh canaries per run, in real formats with valid checksums                                                       |
| `src/internal/verdict`              | The verdict rules: code findings the model can't clear; the model only stricter; error gives review                |
| `src/internal/harness`              | The harness: MCP client, package install, egress proxy, observations                                               |
| `src/internal/checker`              | The fixed checks, the action registry and interpreter, the judge and its investigation loop                        |
| `src/internal/demoproxy`            | The demo Go module proxy's files: each demo version as a module whose default build is that version                |
| `src/cmd/demopublish`               | Writes those files, for the deploy to copy to the bucket (`infra/demo_proxy.ts`) and for `make demo-build`         |
| `src/internal/poller`               | The poll: each approved package's registry asked for its latest version, a re-check started for a new one          |
| `src/internal/store`                | DynamoDB and S3 access shared by the Checker and the web function                                                  |
| `src/internal/web`                  | Handlers and `html/template` pages                                                                                 |
| `src/internal/demoscene`            | What the Checker writes for each demo check, played by `src/cmd/webstub`; a Checker test holds it to the Checker   |
| `src/demo/weather`, `src/demo/mail` | The demo MCP servers, each its own `main`                                                                          |
| `sandbox/Dockerfile`                | The MicroVM image: Go, Node, Python, the harness, a fake developer home                                            |
| `infra/`                            | One CDK app: the Checker (durable), the web function behind the HTTP API, the table, the bucket, the MicroVM image |

## Harness API

The Checker calls the harness over the MicroVM's HTTPS URL, with a
per-run bearer token the Checker passes at launch (see "The MicroVM" below
for how). The token is HMAC-SHA256 of the check's id under a key in Secrets
Manager (`RUN_TOKEN_SECRET_ARN`), so the Checker derives it again on every
invocation and no execution history keeps it. JSON in and out; every response carries
`observations` since the last call.

| Call                | Body                                                                                    | Answers                                                    |
| ------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `POST /install`     | `{"kind":"go"\|"npm"\|"pypi"\|"remote","ref":"name@version or URL","allowHosts":[...]}` | install log, resolved dependency set and its SHA-256       |
| `POST /start`       | `{"command":[...]}` (empty: the kind's default)                                         | the server's `initialize` result                           |
| `POST /list`        | `{}`                                                                                    | tools (whole schemas), resources, prompts, as raw JSON     |
| `POST /call`        | `{"tool":"name","arguments":{...}}`                                                     | the raw result                                             |
| `POST /allow`       | `{"hosts":[...]}`                                                                       | the egress allowlist now in force                          |
| `POST /seal`        | `{}`                                                                                    | `{"hosts":[]}`: egress ended for good                      |
| `POST /clock`       | `{"offset":"720h"}`, a move forward                                                     | the clock now in force: `{"offset","now","applies","why"}` |
| `POST /source`      | `{"path":"dist/index.js"}`, relative to the installed package                           | `{"path","content","truncated"}`, 64 KB at most            |
| `POST /download`    | `{"path":"/home/dev/.cache/x"}`, a file the server wrote                                | `{"path","size","sha256","kind","excerpt"}`                |
| `GET /observations` |                                                                                         | all observations of the run                                |

The resolved dependency set is the resolver's, taken before any code of the
package runs, never what the installed files say of themselves: for npm, the
lockfile of `npm install --package-lock-only --ignore-scripts`, read before
`npm ci` installs exactly it; for PyPI, pip's `--dry-run --report` in a clean
venv, as a requirements file with every file's SHA-256, which
`pip install --no-deps --require-hashes` then installs; for Go, the modules
of `go version -m`. A PyPI set must be all wheels: a dependency only an
sdist ships is built with build dependencies no hash pins, so the install
fails. After every install step the harness kills every process of the
unprivileged account, and a harness not switched to that account fails
the step: it can't kill them. A failed install answers 422 with its log,
whose last line names what failed; the Checker ends the sandbox and the
check at review, decided by code, with an `install-failed` code finding
holding the harness's message, and asks no person: nothing was installed
to approve. Any other error answer to `/install` fails the check.

The investigation's calls (`/call` again, `/source`, `/download`, `/clock`)
and `/allow` are best effort: an error answer is told to the judge, and the
check goes on. `/clock`, `/source` and `/download` work after `/seal` and
change nothing of egress.

- **`/clock`** moves the server's clock forward with libfaketime, which
  the server always runs preloaded with (its monotonic clock untouched),
  reading the offset from a file in `/etc/mcp-customs` on every call for
  the time, so a move applies to a running server. Moves add up: each is
  whole seconds, one to 366 days, all of them at most ten times that (400
  past it); 409 when the harness has no fake clock. `applies` says whether
  the server's runtime sees the move: `no` for a Go or statically linked
  binary, which doesn't ask libc for the time, `yes` for a dynamically
  linked one, a script judged by its interpreter, and `unknown` before an
  install or when the binary can't be read; `why` says which, naming
  only the command's own base name. The command is the server's to point
  anywhere, so the harness reads only a regular file the account could
  read itself (its own, or world-readable), looked at before it is opened,
  so no device or FIFO is opened and nothing of a file the account can't
  read reaches the judge. The Checker
  tells the judge, which then reads nothing into what the server does
  after a move it can't see. It is advice, not a control: a server can
  clear `LD_PRELOAD` or set its own clock, and can tell it is tested (the
  preload is in its environment, the offset file world-readable).
- **`/source`** reads under the installed package's directory: for npm
  `node_modules/<name>`, for Go the main module in the module cache, for
  PyPI the venv's `site-packages`. A path that isn't clean and relative,
  or that leaves the package, a link out of it, a package directory
  reached through a link, a hard link (a link count above one), and
  anything but a regular file the unprivileged account owns, are 400; a
  missing file is 404, and a call before an install 409.
- **`/download`** describes only a path seen as a `file` observation,
  404 otherwise. Its directory is opened at its real path, so one swapped
  for a link is 400; the file is looked up in it without following a
  link (400), the file opened must be the one looked at, and it must be a
  regular file the account owns, never a hard link (400), and is hashed whole up to 256
  MB (413 past it, a file that grows past it while read included); `kind` is its sniffed media type, `excerpt` its first
  4 KB.

The server under test never reaches the stack's own API directly. A host
the server's author controls, or a CloudFront distribution in front of
the API, can still relay to it, and no host or address filter can stop
that: the API's own authorization is the control there. Every layer reads
a host the same way: only a plain ASCII name (letters, digits, inner
hyphens, labels of 1 to 63 characters, no `xn--` label, not an IP
address) is allowed, so no IDNA mapping turns one into the API's. Before
`allow` calls `/allow`, the Checker refuses an allowlist holding any other
host, or any name of its
API (`API_HOST`, and its FIPS, dual-stack and VPC endpoint forms), or a
name that resolves into API Gateway's published address ranges for the
API's region (embedded from `ip-ranges.json`, so the answer is the same
from run to run), or any name when `API_HOST` isn't an execute-api host:
no `/allow` is sent, the `allow` step records an `allow-own-api` code
finding, at least review, and the judge investigates nothing more. The
harness, given the same host as the image's `API_HOST`, refuses to start
without it (the image build fails at `/ready`), answers `/allow`, and
`/install`'s `allowHosts`, 403 when they name the API in any form and 400
for an IP address. Its egress proxy dials each allowed request at an
address it resolved and checked, and refuses any in those ranges or among
the addresses of the API's standard and dual-stack names (IPv4 embedded in
IPv6 read as itself), so rebinding and a custom domain don't reach it
either. The one request it lets reach the API is an install's GET or HEAD
under the demo Go proxy's prefix, which the proxy marks as it admits it;
its connection is never kept for another request.

`/seal` ends egress for good: the allowlist (the registries' too) is
emptied, every new CONNECT is refused (recorded as a refused `connect`,
searched), and a request still being sent on to an allowed host is cut;
`/seal` answers only once every request allowed before it is done,
recorded and cut, so none reaches its host after.
DNS is still answered with fakes and every request still searched and
recorded, so what the server tries after is seen; nothing leaves. Sealing
again answers the same; `/allow` after it answers 409, and a harness
with no egress proxy answers `/seal` 409. Once the investigation ends,
the Checker calls `/seal`, then `GET /observations` a last time, then
ends the MicroVM, and decides the verdict from that last read. A seal or
last read that fails is a `not-sealed` code finding, at least review;
one that works but whose STEP# item can't be written is a
`step-not-recorded` code finding, also at least review.

An observation is `{"at","kind","detail"}`, where `kind` is one of `dns`
(every UDP datagram to port 53, at any address: name, type, answers,
`faked`, the canaries found anywhere in the datagram or in any question's
name, and `unanswered`: why it got no answer, when it isn't a query),
`connect` (a tunnel through the proxy: host, `serverName` (the TLS
SNI), port, `intercepted`, `allowed`, the canaries in the CONNECT
request and the whole TLS handshake as sent, and `unscanned` when the
ClientHello carries an encrypted one; or direct traffic the firewall refused:
`via: "direct"`, `proto` (tcp, udp, icmp, …), address, port, the
canaries in a refused packet's payload or the first 64 KiB a refused TCP
connection sent, `unscanned` when that read was cut short, `more` on the
1000th, after which only traffic holding a canary is recorded, `dropped`
when the kernel lost packets unread, refused ones or datagrams to port
53, and `stopped` when the harness stopped reading refused packets or
DNS),
`http`
(method, host, path, `allowed`, the canaries found in it, as parsed and
as sent, trailer and chunk extensions included, with their encoding, and
`unscanned`: why part of it went unsearched, when it did; bytes the proxy
couldn't read as a request are an `http` observation of their own, with
the canaries in them and `unscanned`; a request not read whole within 30
seconds is recorded as read so far, `unscanned`), `file` (path written), `sampling`, `elicitation`,
`process`, `hook` (a lifecycle hook called after `/run`: method, path,
caller, the status it got). Bodies are not returned, only what was found
in them.

What a run records is capped, so a server can't exhaust the harness or
make an answer larger than the 16 MiB the Checker reads: 5,000
observations of a kind, 100 of `sampling` and of `elicitation`, 2 MiB of
a kind and 8 MiB of all kinds together, each observation counted as
encoded; 64 of the server's requests answered at once (more are dropped
unanswered), and 200,000 files in a look of the file watch. Each is far
above what a real server does. A `sampling` or `elicitation` observation
keeps the request's params whole up to 64 KiB, and past that their start
as a string, with `cut: true`. Reaching a cap stops recording that kind
(`file` for the watch, `request` for the requests dropped), with one
`truncated` observation: `{"kind","why"}`, the kind no longer recorded
and why. Each is an `observations-truncated` code finding, at least
review. Past a cap, an observation that would raise a block finding (a
canary leaving, a write to an agent's config or a shell's startup file)
is still recorded, up to 200 of a kind and 2 MiB in all, so a flood can't
turn a block into a review. Every answer's observations together stay
under 11 MiB. When the run ends, every process of the unprivileged
account is killed, those that left the server's process group or session
included.

## The MicroVM

What Lambda MicroVMs (`sandbox/Dockerfile`, `infra/sandbox.ts`,
`src/internal/checker/sandbox`) force on the harness:

- **One snapshot for every run.** Lambda builds the image, starts the
  harness once, and snapshots it; each check's MicroVM resumes from that
  snapshot. Environment variables are the image's, the same for every
  MicroVM, so the token can't come from `HARNESS_TOKEN`, and nothing
  made before the snapshot (a key, a seed, a planted home) may be per-run.
- **Two ports.** The Harness API listens on `PORT`, 8080, the endpoint's
  default. Lambda's lifecycle hooks are served on `HOOKS_PORT`, 9000. The
  Checker's endpoint tokens open 8080 only, so nobody holding one reaches
  a hook. Lambda forwards by port, never by path.
- **Hooks the harness serves on 9000**, under `/aws/lambda-microvms/runtime/v1/`:
  - `POST .../ready` at image build: 200 once the API listens (503 to be
    asked again). Lambda snapshots after it.
  - `POST .../run` when a MicroVM starts, with
    `{"microvmId":"mvm-...","runHookPayload":"<string>"}`. The payload is
    `{"token":"<run token>","canaries":[{"kind","value"}...]}` as JSON, at
    most 16 KB. The harness keeps the token, plants the home from the
    canaries, then answers 200; Lambda forwards no request before that, and
    gives the hook 30 seconds. Until then every Harness API call answers 503. A second `/run`, which only something inside the MicroVM can send,
    is refused with 409 and observed as a `hook`. The token and canaries are not repeated
    anywhere else: `/install`'s `canaries` field is no longer needed.
- **Headers.** Every request to the endpoint carries Lambda's
  `X-aws-proxy-auth` (a JWE token, an hour at most) and `X-aws-proxy-port`;
  Lambda removes `X-aws-proxy-*` before the harness sees the request, so
  the harness authenticates the `Authorization: Bearer <run token>` header
  only. A 403 or 502 without JSON is Lambda's, not the harness's.
- **Root, and nothing to climb back to it.** The image runs the harness
  as root (its `ENTRYPOINT`, `USER root`); Lambda documents nothing that
  stops that, and runs the container with the standard Linux capabilities,
  which include switching users. The image has no setuid or setgid file.
  Lambda offers no `no-new-privileges` switch for the container, so the
  harness sets it per process: the image ships `setpriv`
  (`setpriv --no-new-privs`). `libfaketime` is at
  `/usr/local/lib/faketime/libfaketime.so.1` for `POST /clock`.
- **No AWS credentials inside.** MicroVMs run with no execution role, so the
  server under test finds none, and Lambda keeps no runtime logs:
  observations come back through the API only.
- **Egress is all or nothing at Lambda's level.** A MicroVM gets the
  internet (`INTERNET_EGRESS`) or a VPC through a network connector; Lambda
  filters no host. Deny-by-default (the egress proxy, #5) is the harness's
  job inside the VM, and stopping a server that ignores the proxy needs the
  harness to own the network: iptables or a network namespace, which takes
  the image's `additionalOsCapabilities: ["ALL"]` (granted to root only,
  never to `dev`). The image asks for them since #5: the harness puts the
  firewall up for `dev`'s user ID before it answers `/ready`, and the
  proxy CA's certificate (never its key) is in `/etc/mcp-customs`.
- **Lifetime.** A MicroVM lives at most 2 hours, running and suspended
  (Lambda allows 8). A check waiting days for a person must have
  terminated its MicroVM first; suspend and resume are for pauses within
  the run.
- **Arm64.** The image is built for `ARM_64`, Lambda's default (x86_64
  exists from base image version 3); the harness binary is built for
  linux/arm64.

## Store

One DynamoDB table (`DYNAMODB_TABLE_NAME`), keys `pk` and `sk`:

| Item      | `pk`            | `sk`            | Holds                                                                                                                                                                                      |
| --------- | --------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A check   | `CHECK#<id>`    | `META`          | the submission, status, verdict, durable execution ARN, callback ID                                                                                                                        |
| A step    | `CHECK#<id>`    | `STEP#<seq>`    | what ran, its findings, a one-line summary (the web page's timeline)                                                                                                                       |
| A verdict | `HASH#<sha256>` | `VERDICT`       | the approved check's ID, its tool-list hash, the install spec                                                                                                                              |
| A package | `APPROVED`      | `<kind>#<name>` | its approved version, that check's ID and tool-list hash, `polled`, the newest version a re-check was started for, and `retry`, a version whose re-check failed and is to be started again |

A check's `status` is `running`, `waiting` (for a person's Approve or
Block, under its `callbackId`), `done` or `failed`. A `STEP#` item's `name`
is the registered action that ran (`resolve`, `lookup`, `install`, `list`,
`scan`, `compare` (a re-check's tool list against the approved one), `probe`, `observe`, `ask_human`, `wait`, the investigation's
`allow`, `call`, `read_source`, `inspect_download`, `clock`, and `seal`
before the last `observe`), or `start`,
`write_probes`, `judge`, `investigate` (one a turn: the move the judge
picked), `verdict` or `failed`. A check that fails ends its sandbox, writes a
`failed` step whose summary names the action that failed (never the
harness's or the SDK's text), and turns `failed`. A check writes its `verdict` step, then its report, its `HASH#` item
and, last, `done`: a `verdict` step that can't be written fails the check
with no `HASH#` item. A `HASH#` item is written only when a check passes by code or a
person approves it; its `installSpec` is the JSON
`{"kind","ref","dependencySha256","toolListSha256"}`.

A check's `META` also keeps `sandboxId`, the MicroVM its `resolve`
launched, written before anything else, so a failure can end it, and, for
a re-check, `recheckOf` and `recheckOfRef`: the check that approved the
earlier version, and that version's ref. An approved check's `META`
keeps `supersededBy`, the re-check of a newer version that ended at
review or block, and `recheckFailed`, the retry of a re-check that failed
twice.

A pass of a package (not a remote server) also puts its `APPROVED` item,
with `polled` set to its version.

No step keeps more than 200 KB. What the install was seen doing, the
server's `initialize` result and its start, a tool list, a probe's answer
or the observations larger than that are kept whole in the bucket as
`observations/<check-id>-<what>.json` (`resolve`, `install`, `list`,
`call-<n>`, `observe`), and the check fails, with an `oversized` code
finding on its `failed` step.

No `STEP#` item is larger than DynamoDB's 400 KB, measured as the store
encodes it (`store.StepSize`, after JSON writes each control character,
`<`, `>`, `&`, U+2028, U+2029 and invalid byte as six bytes): a step keeps
at most 20 findings of each rule and 200 in all, each rule cut to 64 bytes
and its evidence to 512, and fewer when those would
take the item past 400 KB. It adds one finding per rule saying how many
more of that rule it left off past its 20, and one `more-findings` finding
counting the findings of any rule, kept or not, it left off once it had
kept its most (200, or as many as fit). The verdict is decided from every
finding, and the report keeps them all. Findings
name a tool by its place in the listing (`tool 3`, `the result of tool
3`), whichever step made them.

Reports go to the bucket as `reports/<check-id>.json`. Raw observations as
`observations/<check-id>.json`.

## Re-checks of new versions

Package versions can't change, so a rug pull is a new version. An
EventBridge Scheduler schedule runs the poller every few minutes
(`RECHECK_INTERVAL` in `infra/recheck.ts`). It reads every `APPROVED` item
and asks the kind's registry for the latest version: npm's
`<registry>/<name>/latest`, the Go module proxy's `<proxy>/<module>/@latest`,
PyPI's `<index>/pypi/<name>/json`, set by `NPM_REGISTRY_URL`, `GO_PROXY_URL`
and `PYPI_URL` (https; the public ones when unset). `GO_PROXY_URL` is a
GOPROXY-style list, each proxy asked after the one before answered 404 or
410; the stack sets it to its demo proxy, then the public one. A remote server has no
versions and is not polled. A latest version that is neither the approved
one nor `polled` starts the Checker with

`{"checkId":"recheck-<40 hex>","submission":{"kind","ref":"<name>@<latest>"},"recheck":{"checkId","ref","toolListSha256"}}`,

the ID derived from the kind, name and version, so it starts once, and
then sets `polled`. A re-check never passes as seen before: it is
installed, listed, compared with the approved tool list, probed and judged
like a new server, whatever its tool list. Its pass puts the new version's
`APPROVED` item; anything else leaves the earlier approval as it was.

A re-check never ends silently:

- **It fails** (an error, not a verdict): the Checker sets `retry` on the
  package's `APPROVED` item to the version, only while it is still
  `polled` (a re-check overtaken by a newer version is not retried), and
  writes a `retry` step. The next poll starts it once more as
  `recheck-<40 hex>-retry`, with the same `recheck` link plus
  `"retry":true`, then removes `retry`. The poller's grant stays on the
  `APPROVED` partition. The retry's failure is not retried: the Checker
  sets `recheckFailed` on the approved check's `META`, writes a
  `recheck-failed` step and logs `A re-check failed twice.` with
  `"recheckFailedTwice":1`, which a metric filter on its log group counts
  (`MCPCustoms`/`RecheckFailedTwice`) and the `RecheckFailedTwice-Critical`
  alarm watches.
- **Code does not pass it** (review or block): as soon as code decides,
  before the re-check waits for a person, the Checker sets
  `supersededBy` on the approved check's `META`, which the approved
  check's page shows, and puts an event on the account's default
  EventBridge bus (`EVENT_BUS_NAME`): source `mcp-customs`, detail-type
  `Approved check superseded`, detail
  `{"approvedCheckId","approvedRef","recheckId","kind","ref","verdict"}`,
  the verdict code's. The mark is written in one transaction with a
  check that the re-check's version is still the package's `polled`, so
  of two re-checks of one approval only the newest version's sets the
  link and sends the event, whichever ends last. A re-check that passes, by code or a person's approval, always tries
  to lift the mark, which comes off only while it names that re-check or,
  for a retry, the re-check it retries (a mark left by a re-check that
  failed after setting it is lifted by its retry), and a second event goes out: detail-type
  `Approved check no longer superseded`, the same detail with verdict
  `pass`. The `ConditionCheckItem` the transaction needs is granted to the
  Checker on `APPROVED` items only. A user subscribes with a rule on that source and those
  detail-types; a retried step may send an event twice, told apart by
  `recheckId`.

## The demo proxy

The demo servers' versions are served by the stack, so the live rug pull
needs no public registry: a Go module proxy (the GOPROXY protocol's static
files, `<module>/@v/list`, `@v/<version>.info`, `.mod`, `.zip` and
`<module>/@latest`, paths escaped) under the bucket's `goproxy/` prefix,
served read-only by the web function at `GET /goproxy/{proxy+}`, 404 for
anything else. The demos are the modules
`github.com/JairJosafath/mcp-customs/demo/mail` (v1.0.0, v1.0.1) and
`.../demo/weather` (v1.0.0): each version's module holds the demo's
package built for that version, its build line taken off, and
`src/demo/mcp` as `internal/mcp`, so `go install module@version` builds
that version with no tag. A deploy publishes the version
`infra/demo-versions.json`, a committed file, names for each demo, and
every earlier version: synth runs
`src/cmd/demopublish`, and a `BucketDeployment`, whose role alone may
write `goproxy/`, copies the files and prunes the rest. The web function
may list `goproxy/` too, so S3 answers a missing file 404; a read S3 still
denies is answered 404 and logged, since only a 404 or 410 sends the go
command and the poller on to the next proxy. The stack hands `GO_PROXY_URL`,
`<API>/goproxy,https://proxy.golang.org`, to the poller and to the
MicroVM image; the harness gives a Go install `GOPROXY` set to it,
`GONOSUMDB` set to the demo path alone, and, while an install runs, lets
it GET (or HEAD) under each proxy's path that is not a registry's, and
nothing else on that host.

## A person's answer

The web function answers a `waiting` check by sending its `callbackId`
(`SendDurableExecutionCallbackSuccess`) the JSON
`{"decision":"approve"}` or `{"decision":"block"}`. Anything else, or no
answer within 7 days, leaves the verdict code decided.

## The judge

Claude on Amazon Bedrock (`JUDGE_MODEL_ID`, an inference profile the
Checker alone may call), through the Converse API, in three durable steps:
`write-probes`, `judge`, and `investigate-<n>`, one a turn, at most 8. Each
call answers through one tool whose JSON Schema is in
`src/internal/checker/judge_answers.go`; code decodes it with the same
limits and refuses anything else. Server text (the submission, tools,
resources, prompts, results, observations, each turn's outcome) is sent
between a line `<<<EVIDENCE <nonce> BEGIN <name>>>>` and
`<<<EVIDENCE <nonce> END <name>>>>`, the nonce fresh for every call, and the
system prompt names it evidence, never instructions. Model findings are
`purpose-mismatch`, `server-instructs-model`, `judge-concern` and
`judge-asked-for-a-person`, each at least review.

## Verdicts

`pass`, `review` or `block`, with `findings[]`, each
`{"source":"code"|"model","rule","evidence"}`. A `code` finding of a
blocking rule can't be outweighed by any `model` finding.
