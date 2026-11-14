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

## Develop

Open the repository in its devcontainer, which has Go 1.26 and Node 24.

```sh
npm ci                     # install the CDK app's exact packages
(cd src && go test ./...)  # the function's tests
npm test                   # the stacks' assertions, with vitest
npm run synth              # build the function, write the development templates into cdk.out/
make check                 # what CI runs: format, lint, vet, test, synth, cfn-lint
make help                  # every target
```

Nothing here deploys or needs an AWS account: synth runs offline, builds the
function with the installed Go, and needs neither Docker nor credentials.

## Tiers and operations

The stacks are built for a tier, `production` or `development`, which is the
place they run, not the code: `make synth` writes both, into
`cdk.out/production/` and `cdk.out/development/`, and a deploy picks one
(`cdk deploy -c tier=production --all`; without `-c tier` it is `development`).
The production stack is `mcp-customs`, the development one
`mcp-customs-development`, so a deploy that names no tier never changes
production.
Production keeps the table when the stack goes, protects it and the stack
from deletion, recovers it to any second of the last 35 days, backs it up
daily with AWS Backup, traces with X-Ray and keeps logs a year; development
throws its data away with the stack and keeps logs a month. Both tiers alarm
and have a dashboard. Lambda traces each call itself; the function adds no
subsegments of its own.

What the app promises whatever the tier, the backups' retention and copy
region, the recovery objectives and who the alarms tell, is in
`infra/operations.ts`, which theos renders from the Container's
`spec.operations`: change the block, and the file follows it. The alert
email is the stack's `AlertEmail` parameter, which a deploy can set per
environment. Each stack outputs `EntryPoint`, the API's URL, and
`AlarmTopicArn`, the topic its alarms notify.

The function logs JSON lines with Go's `log/slog`, as there is no Powertools
for Go: a request that fails is logged as `The request failed.` with its
`requestId`, `routeKey` and `error`. It sends no metrics of its own; the
alarms read the API's, the function's and the table's.

Deploying (`cdk deploy`, after `cdk bootstrap` of the account) is for its
owner, with their own credentials.

## Layout

- `src/` is the function, a Go module of its own (`src/go.mod`). `main.go`
  is the Lambda entry point: it loads the AWS configuration and creates the
  DynamoDB client and the `slog` logger once, reads `TABLE_NAME` and hands
  each request to `answer` in `api.go`.
- `api.go` routes a request, checks its input and answers with a status
  code; `items.go` holds the rules, free of AWS; `item_store.go` keeps items
  in DynamoDB behind the `ItemStore` interface tests fake.
- `infra/stacks.ts` defines the stacks for a tier; `infra/api_stack.ts` is
  the main one: the table, the function, built by `go build` into one
  `bootstrap` binary for arm64, with its log group and role, the API with
  its access log, the alarms (`infra/alarms.ts`) and, in production, the
  backups (`infra/backups.ts`). The stack is named after the package.
  `infra/operations.ts` holds what the Container promises.
- `infra/connectors.ts` lists the data stores the Container's Relationships
  connect it to, which theos renders from their Connectors; the stack
  connects each to the function, alarms on it and backs it up. The
  `dynamodb` DataStore's table is made by `infra/connector_dynamodb.ts`, and
  the function reads its name in `DYNAMODB_TABLE_NAME`. New data goes in that
  table: the `Items` table (`TABLE_NAME`) is the starter's example.
- `infra/main.ts` is the CDK app `cdk synth` runs (`cdk.json`), and
  `infra/standard.ts` says what each tier means, tags every stack and adds
  CDK Nag's checks. `docs/runbook.md` says how to restore the data, roll a
  deployment back, and what to do when an alarm fires.

Read `AGENTS.md` before changing anything: it is the rulebook, for people and agents.
