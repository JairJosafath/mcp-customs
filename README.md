# MCP Customs

Scanners read what an MCP server says. MCP Customs runs it and watches what
it does, before an AI agent is allowed to use it: a pass, review or block,
with a report that says why.

An entry for the AWS Builder Center weekend challenge "No Pipeline, No
Problem" (deadline Monday 2026-11-16, 13:00 PT), built by
[theos](https://github.com/JairJosafath/theos) from a Brief.

| Path                                                                             | What it is                                                                                      |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [brief.yaml](brief.yaml)                                                         | The product in plain words, as theos takes it                                                   |
| [docs/plan.md](docs/plan.md)                                                     | The design, the security review, the steps, and the friction log of what theos got wrong        |
| [docs/c4.html](docs/c4.html)                                                     | The C4 views ([published](https://claude.ai/artifact/NLmoPPJJBK9V3KgXNLpLDq))                   |
| [docs/kickoff.md](docs/kickoff.md)                                               | How the build runs: an orchestrator session and the implementer and reviewer sessions it starts |
| `src/`                                                                           | The Go code: the Checker, the web function, the sandbox harness, the demo servers               |
| `infra/`                                                                         | The CDK app that deploys all of it                                                              |
| [AGENTS.md](AGENTS.md), [docs/agents/](docs/agents/), [docs/style/](docs/style/) | theos's aws-standard: the rules every change is checked by                                      |

The repository was scaffolded with theos's `aws-lambda-go` template and its
`aws-standard` rules (`make check`), then grown from issues by Claude Code
sessions.

## The functions

| Function         | Code                                      | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| The Checker      | `src/cmd/checker`, `src/internal/checker` | A Lambda [durable function](https://docs.aws.amazon.com/lambda/latest/dg/durable-functions.html) on the AWS Durable Execution SDK for Go. Started with `{"checkId":"c1","submission":{"kind":"npm","ref":"weather-mcp@1.0.0"}}`, it runs the whole check: `resolve` (launch the sandbox and install there, which hashes the whole resolved dependency set), `lookup` (an approved verdict of that hash), and, for a dependency set and tool list approved before, `list` and pass; otherwise `install`, `list`, `scan` (all server text, with `findings.ScanText`), `probe` (each tool once, with arguments the judge wrote), `observe`, the judge and its investigation, and `verdict.Decide`. The judge is Claude on Amazon Bedrock through the Converse API (`src/internal/checker/bedrock`, model `JUDGE_MODEL_ID`), answering through one JSON Schema tool a question: it writes probe arguments, judges behaviour against the stated purpose and names the hosts that purpose needs (the sandbox's egress allowlist, `allow`), then picks one registered action a turn (`call`, `read_source`, `inspect_download`, `clock`, `ask_human`, or done), at most 8 turns. Server text reaches it only between marker lines unique to the call, named evidence. A judge error or running out of turns gives review; its findings only make the verdict stricter. A check that fails ends its sandbox, writes a `failed` step naming the action that failed, and turns `failed`. A verdict short of pass ends the sandbox and waits for a person (`ask_human`): the check's `META` turns `waiting` with its callback ID, and the callback takes `{"decision":"approve"}` or `{"decision":"block"}`. Each action is one durable operation (Step, Map, WaitForCallback or Wait) and writes a `STEP#` item with a one-line summary; the report goes to `reports/<check-id>.json`, the observations to `observations/<check-id>.json`, an approval to `HASH#<sha256>`. Its execution may last 8 days, so a check can wait a week for a person's Approve or Block.                                                                                                                                                                    |
| The web function | `src/cmd/web`, `src/internal/web`         | Behind the HTTP API, open to the public. `GET /` is a form that takes a pinned Go module, npm or PyPI package (`name@version`) or an `https://` URL; it posts to `POST /checks`, which starts the Checker and redirects (`303`) to `GET /checks/<id>`. That page shows the steps as they are written (a small script asks `GET /api/checks/<id>` every two seconds and reloads when something changed), then the verdict and the report; while the check waits for a person it shows Approve and Block, which post the decision and the reviewer key to `POST /checks/<id>/decision` and send the Checker's callback; a check no longer waiting, or a callback already answered, answers `409`. `POST /api/checks` takes `{"kind":"npm","ref":"weather-mcp@1.0.0"}` and answers `202` `{"checkId":"..."}` (an `Idempotency-Key` header makes a retry answer the same check, and the same key with another submission `409`; bad input is `400`, a body that isn't JSON `415`; a remote URL must name a public host: localhost, single-label and numeric names, and loopback, private, link-local, shared and metadata addresses are refused); `GET /api/checks/<id>` answers `{"checkId","status","submission","recheckOf","verdict","decidedBy","steps","findings","installSpec","bound"}`, with `recheckOf` (`{"checkId","ref"}`, the check that approved the earlier version, linked on the page) for a re-check only and `installSpec` for a pass only, and `404` before the check has started. All text from a check is escaped, with every character a person can't see (controls, format characters, separators, private-use and unassigned code points, variation selectors, default-ignorables) shown as an escape such as `\u200B`, on the page and in the JSON; pages load no inline script or style (a strict `Content-Security-Policy`). `GET /goproxy/<path>` serves the demo Go module proxy, the files `make demo-publish` writes to the bucket's `goproxy/` prefix, and `404` for anything else, which sends the go command on to the next proxy. `GET /api/health` answers `200` `{"status":"ok"}`; any other path answers `404` with `{"message":"..."}`, which repeats at most 100 characters of the path. |
| The poller       | `src/cmd/poller`, `src/internal/poller`   | Run every five minutes by an EventBridge Scheduler schedule. For each approved npm, Go or PyPI package (the `APPROVED` items a pass writes) it asks the registry for the latest version (`NPM_REGISTRY_URL`, `GO_PROXY_URL`, `PYPI_URL`, the public ones by default; the stack sets `GO_PROXY_URL` to its own demo proxy, then the public one) and, for a version no check has seen, starts the Checker with `"recheck":{"checkId","ref","toolListSha256"}` naming the approved check. A re-check is probed in full whatever its tool list, so a rug pull that keeps the list is still caught.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

All three share `src/internal/store`, which keeps a check's `META`, its `STEP#`
items, the `HASH#` verdicts and the `APPROVED` packages in one DynamoDB table, as
[docs/contracts.md](docs/contracts.md) lays out. Reports go to a bucket,
`reports/<check-id>.json`.

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
`infra/operations.ts`, which theos renders from the Container's
`spec.operations`. The alert email is the stack's `AlertEmail` parameter.
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
  it makes: the Checker puts, gets and updates items, puts reports and
  observations, reads the key its run tokens are derived from, checkpoints its own executions and runs its sandboxes; the
  web function gets a check's META and queries its steps, gets reports under
  `reports/` and the demo proxy's files under `goproxy/` (which no role of
  the stack may write: `make demo-publish` does, with the deployer's
  credentials), invokes the Checker at `$LATEST`, sends callbacks to the
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
