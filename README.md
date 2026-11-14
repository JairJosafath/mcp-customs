# MCP Customs

Scanners read what an MCP server says. MCP Customs runs it and watches what
it does, before an AI agent is allowed to use it: a pass, review or block,
with a report that says why.

An entry for the AWS Builder Center weekend challenge "No Pipeline, No
Problem" (deadline Monday 2026-11-16, 13:00 PT). Built with
[theos](https://github.com/JairJosafath/theos).

| Path                                                             | What it is                                                                                 |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| [docs/plan.md](docs/plan.md)                                     | The design and its security review                                                         |
| [docs/c4.html](docs/c4.html)                                     | The C4 views ([published](https://claude.ai/artifact/NLmoPPJJBK9V3KgXNLpLDq))              |
| [docs/contracts.md](docs/contracts.md)                           | How the parts fit: the harness API, the MicroVM, the store, re-checks, the judge, verdicts |
| [docs/results.md](docs/results.md)                               | The write-up: what was built, the security design, the demo, the numbers                   |
| `src/cmd/checker`, `src/internal/checker`                        | The Checker: the fixed checks, the action registry, the judge and its investigation loop   |
| `src/cmd/harness`, `src/internal/harness`, `src/internal/egress` | The sandbox harness and its egress proxy, in the MicroVM image (`sandbox/Dockerfile`)      |
| `src/internal/findings`, `canary`, `verdict`                     | Code-only findings, canaries and the verdict rules                                         |
| `src/cmd/web`, `src/internal/web`                                | The web page and JSON API                                                                  |
| `src/cmd/poller`, `src/internal/poller`                          | The re-check of an approved package's new versions                                         |
| `src/demo`, [demo/](demo/)                                       | Two malicious demo MCP servers, and the demo's recorder and narration                      |
| `infra/`                                                         | The CDK app that deploys all of it                                                         |
| [docs/runbook.md](docs/runbook.md)                               | Restoring the data, rolling a deployment back, what each alarm means                       |

## The functions

| Function         | Code                                      | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The Checker      | `src/cmd/checker`, `src/internal/checker` | A Lambda [durable function](https://docs.aws.amazon.com/lambda/latest/dg/durable-functions.html) on the AWS Durable Execution SDK for Go. Started with `{"checkId":"c1","submission":{"kind":"npm","ref":"weather-mcp@1.0.0"}}`, it runs the whole check: `resolve` (launch the sandbox and install there; a remote server launches nothing and ends at review, decided by code, with a `remote-unsupported` finding, which hashes the whole resolved dependency set), `lookup` (an approved verdict of that hash), and, for a dependency set and tool list approved before, `list` and pass; otherwise `install`, `list`, `scan` (all server text, with `findings.ScanText`), `probe` (each tool once, with arguments the judge wrote), `observe`, the judge and its investigation, `seal` (the sandbox's egress ended for good) and a last `observe`, the sandbox ended, and `verdict.Decide` on what that last read found. The judge is Claude on Amazon Bedrock through the Converse API (`src/internal/checker/bedrock`, model `JUDGE_MODEL_ID`), answering through one JSON Schema tool a question: it writes probe arguments, judges behaviour against the stated purpose and names the hosts that purpose needs (the sandbox's egress allowlist, `allow`), then picks one registered action a turn (`call`, `read_source`, `inspect_download`, `clock`, `ask_human`, or done), at most 8 turns. Server text reaches it only between marker lines unique to the call, named evidence. A call a busy model turns away is tried up to 4 times in all, 2, 4 and 8 seconds apart (a throttle, a 5xx, a model timeout, a connection reset), with the SDK's own retries off; a judge error or running out of turns gives review; its findings only make the verdict stricter. A server the sandbox can't install ends at review with an `install-failed` finding naming what failed. A check that fails ends its sandbox, writes a `failed` step naming the action that failed, and turns `failed`. A verdict short of pass ends the sandbox and waits for a person (`ask_human`): the check's `META` turns `waiting` with its callback ID, and the callback takes `{"decision":"approve"}` or `{"decision":"block"}`. Each action is one durable operation (Step, Map, WaitForCallback or Wait) and writes a `STEP#` item with a one-line summary; the report goes to `reports/<check-id>.json`, the observations to `observations/<check-id>.json`, an approval to `HASH#<sha256>`, in one transaction with the check marked done, so a check that can't be marked done leaves no approval. Its execution may last 8 days, so a check can wait a week for a person's Approve or Block.                               |
| The web function | `src/cmd/web`, `src/internal/web`         | Behind the HTTP API, open to the public. `GET /` is a form that takes a pinned Go module, npm or PyPI package (`name@version`) or an `https://` URL (a remote server isn't checked yet: its check launches no sandbox and ends at review, decided by code, with a `remote-unsupported` finding that says so); it posts to `POST /checks`, which starts the Checker and redirects (`303`) to `GET /checks/<id>`. That page shows the steps as they are written (a small script asks `GET /api/checks/<id>` every two seconds and reloads when something changed), then the verdict and the report; while the check waits for a person it shows Approve and Block, which post the decision and the reviewer key to `POST /checks/<id>/decision` and send the Checker's callback; a check no longer waiting, or a callback already answered, answers `409`. `POST /api/checks` takes `{"kind":"npm","ref":"weather-mcp@1.0.0"}` and answers `202` `{"checkId":"..."}` (an `Idempotency-Key` header makes a retry answer the same check, and the same key with another submission `409`; bad input is `400`, a body that isn't JSON `415`; a remote URL must name a public host: localhost, single-label and numeric names, and loopback, private, link-local, shared and metadata addresses are refused); `GET /api/checks/<id>` answers `{"checkId","status","submission","recheckOf","supersededBy","recheckFailed","verdict","decidedBy","steps","findings","installSpec","bound"}`, with `recheckOf` (`{"checkId","ref"}`, the check that approved the earlier version, linked on the page) for a re-check only, `supersededBy` (the re-check of a newer version that ended at review or block) and `recheckFailed` (the retry of a re-check that failed twice) on an approved check only, each linked on the page and `installSpec` for a pass only, and `404` before the check has started. All text from a check is escaped, with every character a person can't see (controls, format characters, separators, private-use and unassigned code points, variation selectors, default-ignorables) shown as an escape such as `\u200B`, on the page and in the JSON; pages load no inline script or style (a strict `Content-Security-Policy`). `GET /goproxy/<path>` serves the demo Go module proxy, the files a deploy writes to the bucket's `goproxy/` prefix (the versions `infra/demo-versions.json` names, and the versions before them), and `404` for anything else, a file S3 denies included, which sends the go command on to the next proxy. `GET /api/health` answers `200` `{"status":"ok"}`; any other path answers `404` with `{"message":"..."}`, which repeats at most 100 characters of the path. |
| The poller       | `src/cmd/poller`, `src/internal/poller`   | Run every five minutes by an EventBridge Scheduler schedule. For each approved npm, Go or PyPI package (the `APPROVED` items a pass writes) it asks the registry for the latest version (`NPM_REGISTRY_URL`, `GO_PROXY_URL`, `PYPI_URL`, the public ones by default; the stack sets `GO_PROXY_URL` to its own demo proxy, then the public one) and, for a version no check has seen, starts the Checker with `"recheck":{"checkId","ref","toolListSha256"}` naming the approved check. A re-check is probed in full whatever its tool list, so a rug pull that keeps the list is still caught. A re-check that fails is started once more, as `recheck-<40 hex>-retry` with `"retry":true`, when the Checker asks for it on the `APPROVED` item; a retry that fails too is recorded on the approved check and raises the `RecheckFailedTwice-Critical` alarm. A re-check that code does not pass marks the approved check superseded at once, before it waits for a person, and puts an `Approved check superseded` event (source `mcp-customs`) on the default EventBridge bus, which a user's rule can subscribe to; only the newest polled version's re-check sets the mark. A person's later approval lifts it and puts an `Approved check no longer superseded` event.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

All three functions share `src/internal/store`, which keeps a check's `META`, its `STEP#`
items, the `HASH#` verdicts and the `APPROVED` packages in one DynamoDB table, as
[docs/contracts.md](docs/contracts.md) lays out. Reports go to a bucket,
`reports/<check-id>.json`.

## The sandbox

The harness (`src/cmd/harness`, `src/internal/harness`) runs in a Lambda
MicroVM built from `sandbox/Dockerfile`, whose build fails without
anything the harness needs to start (`src/cmd/bumpbase` moves it to a new
base image). It installs the server as an unprivileged account with fresh
canaries in a fake home, speaks MCP to it, and records what it does
through the egress proxy (`src/internal/egress`), DNS and firewall
logging and a file watch. The Checker drives it over HTTPS with a per-run
token ([docs/contracts.md](docs/contracts.md) has the API).

- **Installs fail closed.** The dependency set is the resolver's, read
  before any script runs; PyPI resolves wheels only
  (`--only-binary=:all:`) and installs with `--require-hashes`. Every
  install step, and the run's end, kills every process of the account,
  those that called `setsid` included.
- **Egress.** Denied by default; allowed hosts pass, others get a fake
  answer. The proxy refuses any name that resolves inside a network
  (loopback, link-local, private, shared, metadata, 6to4, Teredo,
  site-local) and the stack's own API, but for an install's `https` GET
  under `/goproxy/`.
- **Caps.** What a run records is capped within the 16 MiB the Checker
  reads. Reaching a cap, or the file watch's limit, stops recording that
  kind with one `truncated` observation, an `observations-truncated` code
  finding (at least review); what would block is still recorded past it.
- **The investigation.** `POST /clock` moves the server's clock forward
  with libfaketime and says whether its runtime sees the move (`applies`:
  not for a Go or static binary), reading only files the account could
  read. `POST /source` answers at most 64 KB of a file of the installed
  package, refusing links and hard links. `POST /download` describes a
  file the server was seen writing: size, SHA-256, kind and a 4 KB
  excerpt, `413` past 256 MB. All three work after the seal and reopen no
  egress.

## Limits

- Remote servers: the form takes an `https://` URL, but remote servers
  aren't checked yet: such a check launches no sandbox and ends at
  review, decided by code, with a `remote-unsupported` code finding.
- Moving the clock shows nothing of a Go or static server, the demo
  servers included; `/clock` says so and the judge is told.
- No runtime gateway pins the approved tool list, and tool arguments are
  not fuzzed.
- What only a real AWS account shows (the MicroVM's firewall and egress,
  the durable Checker's replay and week-long wait, the judge on real
  servers, IAM, cold starts) is listed in
  [docs/results.md](docs/results.md#unverified-until-deploy).

## Develop

You need Go 1.26, Node 22 or later, `uv`, and golangci-lint v2.13.1 or later
built with Go 1.26
(`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1`);
the devcontainer has them.

```sh
make check                 # what CI runs: format, lint, vet, test, synth, cfn-lint
npm ci                     # install the CDK app's exact packages
(cd src && go test ./...)  # the Go tests; the Checker's run on the SDK's local runner
npm test                   # the stacks' assertions, with vitest
npm run synth              # build both functions, write the development templates into cdk.out/
make help                  # every target
```

`make check` must pass before every commit. Nothing here deploys or needs an
AWS account: synth runs offline, builds the functions with the installed Go,
and needs neither Docker nor credentials.

## Tiers and operations

The stacks are built for a tier, `production` or `development`, which is the
place they run, not the code: `make synth` writes both, into
`cdk.out/production/` and `cdk.out/development/`, and a deploy picks one
(`cdk deploy -c tier=production --all`; without `-c tier` it is `development`).
The production stack is `mcp-customs`, the development one
`mcp-customs-development`, so a deploy that names no tier never changes
production.
Production keeps the table and the reports bucket when the stack goes,
protects the table and the stack from deletion, recovers the table to any
second of the last 35 days and keeps the bucket's earlier versions as long,
backs the table up daily with AWS Backup, traces with X-Ray and keeps logs a
year; development throws its data away with the stack, emptying the reports
bucket first, and keeps logs a month. Both tiers alarm and have a dashboard.

What the app promises whatever the tier, the backups' retention and copy
region, the recovery objectives and who the alarms tell, is in
`infra/operations.ts`. The alert email is the stack's `AlertEmail` parameter.
Each stack outputs `EntryPoint`, the API's URL, and `AlarmTopicArn`, the
topic its alarms notify.

The functions log JSON lines with Go's `log/slog`: a request that fails is
logged as `The request failed.` with its `requestId`, `routeKey` and
`error`. The alarms read the API's, the functions' and the table's metrics.

Deploying (`cdk deploy`, after `cdk bootstrap` of the account) is for its
owner, with their own credentials.

## Layout

- `src/` is one Go module (`src/go.mod`); the layout is
  [docs/contracts.md](docs/contracts.md)'s. Each `src/cmd/*/main.go` only
  wires: it creates the logger and AWS clients once and starts the handler.
- `infra/stacks.ts` defines the stacks for a tier; `infra/api_stack.ts` is
  the main one: the table, the reports bucket, the Checker with its durable
  configuration and the web function, each built by `go build` into one
  `bootstrap` binary for arm64 with its own log group and role, the API with
  its access log, the alarms (`infra/alarms.ts`) and, in production, the
  backups (`infra/backups.ts`). Each function's role allows only the calls
  it makes: the Checker puts, gets and updates items (and checks one in a transaction), puts reports and
  observations, reads the key its run tokens are derived from, checkpoints its own executions, runs its sandboxes and puts events on the default event bus; the
  web function gets a check's META and queries its steps, gets reports under
  `reports/` and lists and gets the demo proxy's files under `goproxy/`
  (which only the `DemoProxy` deployment's role may write, on deploy), invokes the Checker at `$LATEST`, sends callbacks to the
  Checker's executions, reads the reviewer key, and writes its logs; the
  poller (`infra/recheck.ts`) queries and updates items and invokes the
  Checker at `$LATEST`, and the schedule may invoke only the poller.
- **Approve and Block** take the reviewer key, a secret the stack makes
  (`ReviewerKey` in Secrets Manager): the owner reads it there and gives it to
  whoever may decide. The check page's form sends it with the decision; the
  web function compares it in constant time and sends the callback only for
  a check that is `waiting`.
- `infra/main.ts` is the CDK app `cdk synth` runs (`cdk.json`), and
  `infra/standard.ts` says what each tier means, tags every stack and adds
  CDK Nag's checks. `docs/runbook.md` says how to restore the data, roll a
  deployment back, and what to do when an alarm fires.

Read `AGENTS.md` before changing anything: it is the rulebook, for people and agents.
