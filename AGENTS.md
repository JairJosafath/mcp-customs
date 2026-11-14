# Agent guide

This repository is MCP Customs, the `mcp-customs` function of shop: an AWS
Lambda function in Go, on the AWS SDK for Go v2, behind an API Gateway HTTP API, keeping its data
in DynamoDB, with its infrastructure as a CDK app in `infra/`, scaffolded by
theos with the `aws-standard` Standard. Build it to the rules below. What
it is for, and what it must never do, is in the issue you were given
and the system's needs: follow those.

## The one rule

`make check` must pass before every commit. It installs the exact packages in
`package-lock.json` and the modules in `src/go.sum`, then checks that
`go mod tidy` changes nothing, runs Prettier and gofumpt (check), ESLint with
`eslint.config.mjs` on the CDK app (typescript-eslint strict, no warnings
allowed), `go vet`, golangci-lint with `.golangci.yml`, `tsc` with the strict
`tsconfig.json`, the function's Go tests (`go test -race`), the stacks'
vitest `Template.fromStack` assertions, `cdk synth` with CDK Nag's AWS Solutions and Serverless
checks, which fail on any finding not acknowledged with a reason, and
`cfn-lint` on the templates synth wrote. CI runs the same command, and nothing
reaches `main` without it passing and a review. Never commit red.

Nothing here deploys. No command, test or script calls AWS, bootstraps an
account or needs credentials: `cdk synth` writes CloudFormation into
`cdk.out/`, offline.

## Workflow

1. Read the issue, its acceptance criteria, and your role guide:
   `docs/agents/implementer.md` or `docs/agents/reviewer.md`.
2. Read the code you are about to change and match it.
3. Write a failing test first: one per acceptance criterion, or one that shows the bug.
4. Make the smallest change that meets every criterion. One concern per commit.
5. `make check`, then commit with a Conventional Commit message
   (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`).
6. `AGENTS.md`, `docs/agents/` and `.theos.yaml` never change. Other protected files
   change only through a Standard change (see your role guide), never in a normal pull
   request. `.devcontainer/`, `.theos.yaml` and `.github/` belong to the platform.
   `Makefile`, `eslint.config.mjs`, `.golangci.yml`, `.prettierrc.json`, `.prettierignore`,
   `.editorconfig`, `AGENTS.md`, `docs/style/`, `docs/agents/`,
   `docs/well-architected.md`, `docs/runbook.md`, `infra/main.ts`, `infra/standard.ts`,
   `infra/standard.test.ts`, `infra/dist.ts` and `infra/dist.test.ts` belong to the Standard. `tsconfig.json`, `vitest.config.mts` and `cdk.json` decide
   what the checks check and which CDK behaviour the app gets: don't loosen them.
   `infra/operations.ts` is the factory's: it renders the file from the
   Container's `spec.operations`. Change it only to what that block says,
   when an issue changes the block, and never delete it; the stacks read it.

## Lints

- Fix every finding; don't silence it. An `eslint-disable-next-line <rule> -- <why>` or a `//nolint:<linter> // <why>`
  is a last resort for a false positive: one rule, one reason. Never
  `@ts-ignore`; never a file-wide disable.
- Fix every CDK Nag finding in the stack. An acknowledgement
  (`Validations.of(construct).acknowledge({ id, reason })`) is a last resort:
  on the construct the finding's path names, for the one finding (`AwsSolutions-IAM5[Resource::...]`,
  never a whole rule on a stack), with a reason a reviewer can check.
- `make fmt` formats; never hand-format.
- The function is its own Go module in `src/`, apart from `node_modules/`.
  Add a module with `go get` in `src/`, then `go mod tidy`, and commit
  `src/go.mod` and `src/go.sum`. `go build` compiles the function into one
  `bootstrap` binary, so nothing else ships. Prefer Go's standard library and
  the AWS SDK for Go v2's service modules (`github.com/aws/aws-sdk-go-v2/service/*`);
  then few, maintained, well-known modules with a licence that fits. The CDK
  app's packages are `devDependencies` in `package.json`: add one with
  `npm install --save-dev --save-exact` and commit `package-lock.json`.

## Review rules (lint can't check these)

1. **Cold start:** the SDK's configuration and clients are created once, in
   `main` in `src/main.go` before `lambda.Start`, and reused by every
   invocation; nothing heavy runs in `init`. The binary imports only the
   service modules it uses.
2. **The boundary:** every request is validated before use (path, query,
   body, headers), with unknown input narrowed from `unknown`. Errors are
   answered with the right HTTP status (400 for bad input, 404, 409, 500 for
   a bug) and a JSON message a client can act on, never a stack trace or the
   SDK's error text.
3. **Idempotency:** a retried request or event changes nothing twice. Writes
   are puts of a whole item, conditional writes, or keyed by an idempotency
   key; never a blind increment.
4. **Limits are set:** every function has its timeout and memory set in the
   stack, the timeout below API Gateway's 30 seconds and above what the work
   needs; SDK calls stay within it. The stage is throttled.
5. **Logs:** structured JSON, one entry per line, through the `*slog.Logger` the
   code is given; an entry names the request id and what failed. Never
   log a secret, a token or a request body with user data.
6. **Least privilege:** permissions come from CDK grants
   (`table.grant(fn, 'dynamodb:GetItem')`, `grantReadData`), narrowed to the
   calls the code makes; never an IAM statement with `*` or `service:*`
   actions, never an AWS managed policy on a role.
7. **Errors and context:** every error is handled or returned, wrapped with
   `%w` and what was being done; the invocation's `ctx`, which carries
   Lambda's deadline, goes to every SDK call. No `panic`, `log.Fatal` or
   `os.Exit` past start-up in `main`; no goroutine left running when the
   handler returns. In the CDK app: no `any`, no `as` to silence the
   compiler, exhaustive switches over unions.
8. **Pure code:** the rules live in files that import neither the AWS SDK
   nor `aws-lambda-go`, tested with plain `go test`; one type wraps each AWS
   service behind an interface of the client methods it calls, which tests
   fake; `src/main.go` only wires them.
9. **Tests:** next to the code (`foo_test.go`), table-driven, names that say
   what is expected; no real timers, network or shared state between tests.
   No test calls AWS: SDK clients are faked behind their interface, and
   stacks are checked with `Template.fromStack` assertions.
10. **Performance:** when the issue or the system's needs state a budget, a test
    or benchmark measures it on realistic input and the pull request gives the
    numbers.
11. **The stack:** data is encrypted at rest, every log group has a retention,
    every stateful resource an explicit removal policy (`RETAIN` for data), and
    every stack the Standard's tags; `infra/standard.test.ts` checks these. No
    secret in an environment variable or the template: secrets are read from
    Secrets Manager or Parameter Store at run time. Nothing in the app needs
    an AWS account to synthesize: no lookups, no `env` from the environment.
    The stacks are built for a tier, `production` or `development`, which a
    deploy names (`-c tier=production`) and `infra/standard.ts`'s
    `TIER_RULES` defines, and keep what `infra/operations.ts` promises: data
    kept, protected and backed up in production; every function, table and
    API with its alarms on the stack's topic; every stack with its
    `EntryPoint` and `AlarmTopicArn` outputs. `infra/standard.test.ts` checks
    both tiers. Nothing at synth reads a context value but `tier`, or an
    environment variable. A change to what the stacks keep, or how, updates
    `docs/runbook.md`, as a Standard change.
12. **Releases:** user-visible changes get a `CHANGELOG.md` entry under
    "Unreleased"; the version in `package.json` changes only in a release issue.
13. **Names:** Go's: `mixedCaps`,
    initialisms in one case (`ID`, `HTTPURL`), files `snake_case.go`. The CDK
    app's TypeScript: `lowerCamelCase` values, `UpperCamelCase` types,
    `CONSTANT_CASE` module constants, files `snake_case.ts`.
14. **No dead code:** no commented-out code, speculative options or "for later"
    features; no TODO without an issue number.

## Style guides

Offline digests (read the one for what you are touching):

- `docs/style/go.md`: Effective Go, Go Code Review Comments and Google's Go
  style, each rule marked [lint] or [review]
- `docs/style/typescript.md`: Google's TypeScript style, the handbook's do's and
  don'ts and typescript-eslint, each rule marked [lint] or [review]
- `docs/style/aws.md`: Lambda handlers, API Gateway HTTP APIs, DynamoDB, the
  AWS SDK for Go v2, the CDK and CDK Nag, and tests
- `docs/well-architected.md`: the AWS Well-Architected Framework and its
  Serverless Applications Lens, pillar by pillar, with the CDK Nag rules that
  enforce each
- `docs/runbook.md`: restoring the data, rolling a deployment back, and what
  each alarm means
- `docs/style/principles.md`: cross-language principles, with sources
- `docs/style/SOURCES.md`: every source URL, with the date it was read

Online (canonical): https://go.dev/doc/effective_go · https://google.github.io/styleguide/tsguide.html ·
https://typescript-eslint.io/rules/ · https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html ·
https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/ ·
https://github.com/cdklabs/cdk-nag/blob/main/RULES.md
