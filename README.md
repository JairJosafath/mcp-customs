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

## The two functions

| Function         | Code                                      | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The Checker      | `src/cmd/checker`, `src/internal/checker` | A Lambda [durable function](https://docs.aws.amazon.com/lambda/latest/dg/durable-functions.html) on the AWS Durable Execution SDK for Go. Started with `{"checkId":"c1","submission":{"kind":"npm","ref":"weather-mcp@1.0.0"}}`, it records the check's `META` item as `running` and its first step, `STEP#0001`, each in a durable step, and returns. Its execution may last 8 days, so a check can wait a week for a person's Approve or Block. |
| The web function | `src/cmd/web`, `src/internal/web`         | Behind the HTTP API, open to the public: `GET /` is an HTML page (from `html/template`) saying the service is up; `GET /api/health` answers `200` `{"status":"ok"}`. Any other `/api/` path answers `404` with `{"message":"..."}`.                                                                                                                                                                                                               |

Both share `src/internal/store`, which keeps a check's `META`, its `STEP#`
items and the `HASH#` verdicts in one DynamoDB table, as
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
year; development throws its data away with the stack and keeps logs a
month. Both tiers alarm and have a dashboard.

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
  it makes: the Checker puts items and checkpoints its own executions; the
  web function writes its logs.
- `infra/main.ts` is the CDK app `cdk synth` runs (`cdk.json`), and
  `infra/standard.ts` says what each tier means, tags every stack and adds
  CDK Nag's checks. `docs/runbook.md` says how to restore the data, roll a
  deployment back, and what to do when an alarm fires.

Read `AGENTS.md` before changing anything: it is the rulebook, for people and agents.
