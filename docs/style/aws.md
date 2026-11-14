# AWS serverless digest

Distilled from the Lambda developer guide's best practices and Go
handler pages, API Gateway's HTTP API docs, DynamoDB's developer guide, the
AWS SDK for Go v2 guide, the CDK developer guide and its assertions
module, and CDK Nag's rule list (see `SOURCES.md`). `[lint: x]` = enforced by
`make check`: a golangci-lint linter, an ESLint rule or the compiler; `[nag: x]` = a CDK Nag rule that
fails `cdk synth`; `[test]` = an assertion in `infra/standard.test.ts` or a
stack's own test; `[review]` = check it yourself. `docs/well-architected.md`
says why each rule matters.

## The handler

- `src/main.go`'s `main` builds what every invocation shares, then calls
  `lambda.Start` with a function that takes the context and an
  `*events.APIGatewayV2HTTPRequest` and returns an
  `events.APIGatewayV2HTTPResponse`: a status code, headers and a string
  body. API Gateway's HTTP API sends payload format 2.0. [review]
- Load the SDK's configuration (`config.LoadDefaultConfig`) and create
  clients in `main`, once per execution environment; warm invocations reuse
  them and their connections. Never create a client inside the handler.
  [review]
- Read the environment only in `main`, once, and fail at start-up with a
  message naming the variable when one is missing: log it and `os.Exit(1)`,
  the one place an exit is right. [review]
- Keep `main` to wiring; the work is in functions that take what they need
  (a context, a store, a logger), so tests call them without Lambda. [review]
- Pass the invocation's `ctx` to every SDK call: it carries the function's
  deadline, so a slow call is cancelled before Lambda kills the environment.
  [review]
- No goroutine outlives the handler: work left running after it returns is
  frozen with the environment and may never finish. [review]
- Never `panic`, `log.Fatal` or `os.Exit` once `lambda.Start` runs: return
  an error response instead. [review]
- Don't keep request data in package-level variables: the next invocation in
  the same environment would see it. [review]

## Requests and responses

- Validate every input at the boundary: path parameters, query strings,
  headers and the body, decoded into typed values and checked. API
  Gateway delivers whatever the client sent. [review]
- A body can arrive base64-encoded (`IsBase64Encoded`); decode it before
  parsing. [review]
- Answer expected failures with their status: 400 for bad input, 403, 404,
  409 for a conflict, 413 for too large, and 500 only for a bug or an
  outage. The body is JSON with a `message` a client can act on. [review]
- Never return a stack trace, an SDK error's text or an internal name to a
  client; log it instead, with the request id. [review]
- Set `content-type` on every response. [review]

## Logs

- Log structured JSON, one entry per line, through the `*slog.Logger` the
  code is given (`slog.NewJSONHandler` on stderr, made in `main`); never
  `fmt.Print` or the `log` package. [review]
- There is no Powertools for Go: the logs are `slog`'s, and the function
  sends no metrics of its own; the alarms read what Lambda, API Gateway and
  DynamoDB report. [review]
- Each entry has a `level`, a `message` and the request id; errors say what
  failed and with which input, never a secret, a token or user data. [review]
- The function's log group is created by the stack, with a retention.
  [nag: none; test: log groups keep logs for a set time]
- The function logs in JSON format (`loggingFormat: LoggingFormat.JSON`), so
  Lambda's own entries are structured too. [review]

## DynamoDB

- Model the table for its access patterns: every read on a request path is
  a `GetItem` or a `Query` on a key or an index, never a `Scan`. [review]
- Read and write items as `map[string]types.AttributeValue`, by hand or
  with `feature/dynamodb/attributevalue`; validate what a read returns
  before using it, since another writer may have stored something else.
  [review]
- Writes are idempotent: a `PutItem` of the whole item, or a conditional
  write (`ConditionExpression`) that refuses a second apply. Never a blind
  `ADD` on a retried request. [review]
- Idempotency is by hand, as above: there is no Powertools for Go, and no
  idempotency table. `PUT /items/{id}` replaces the whole item, so a retry
  writes the same item again. [review]
- Tables are on demand (`PAY_PER_REQUEST`) unless the issue states a steady
  load. [review]
- In production, point-in-time recovery on, the table kept when the stack
  goes (`RemovalPolicy.RETAIN`) with deletion protection, and backed up by
  the stack's plan, which names it by ARN in `Backups`' `tables`, never by
  a tag the development stack's tables carry too (Powertools' `Idempotency`
  table, whose records expire, is left out); in development none of
  it, `DESTROY`. Build it with the
  tier's `TIER_RULES`, as the stack's tables are. [test: the removal
  policies, deletion protection, point-in-time recovery, the backup plan and
  vault]
- Encrypted at rest with a KMS key (`TableEncryption.AWS_MANAGED` or
  customer-managed). [test: encrypts every table]
- Every table has its alarms: read and write throttles and system errors,
  from the stack's `Alarms`. [test: the alarms and topic]

## The AWS SDK for Go v2

- Import only the service modules you use
  (`github.com/aws/aws-sdk-go-v2/service/dynamodb`), never a whole SDK; they
  are compiled into the one binary. [review]
- `src/go.sum` pins every module; `make check` fails when `go mod tidy`
  would change `src/go.mod` or `src/go.sum`. [lint: tidy-check]
- A client's region and credentials come from the Lambda environment through
  `config.LoadDefaultConfig`; never pass keys or set a region in code.
  [review]
- Wrap each service in one type that depends on an interface of only the
  client methods it calls (`GetItem`, `PutItem`); tests fake that interface.
  [review]
- The SDK retries throttling and transient errors itself; don't add a retry
  loop around it. Catch what you can answer (a failed condition is a 409,
  found with `errors.As`), wrap the rest with `%w` and let it reach the
  handler's 500. [review]

## API Gateway HTTP API

- Every route is authorized: IAM (`HttpIamAuthorizer`), a JWT authorizer or a
  Lambda authorizer. [nag: AwsSolutions-APIG4]
- The stage writes access logs to a log group with a retention.
  [nag: AwsSolutions-APIG1; test]
- The stage is throttled (`throttle: { rateLimit, burstLimit }`), so a burst
  can't run up the bill or starve other functions. [review]
- Routes name their method and path (`GET /items/{id}`); no `ANY /{proxy+}`
  that hands routing to the function. [review]

## Lambda configuration in the stack

- A `Function` whose code is `Code.fromAsset` of `src/`, built by the
  installed Go through local bundling (`go build` with `GOOS=linux`,
  `GOARCH=arm64`, `CGO_ENABLED=0`, `-tags lambda.norpc`, `-trimpath`) into
  one `bootstrap` binary; never Docker, which CI and agents lack. [review]
- The `provided.al2023` runtime, handler `bootstrap`; `go1.x` is retired.
  [nag: AwsSolutions-L1]
- `arm64` (Graviton): cheaper per millisecond and lower energy. [review]
- Memory and timeout set for the work, the timeout under API Gateway's 30
  seconds. [review]
- Its own role, granted only what the code calls; no AWS managed policies.
  [nag: AwsSolutions-IAM4]
- No wildcard permissions: grants (`table.grant(fn, 'dynamodb:GetItem')`),
  never a hand-written `*`. [nag: AwsSolutions-IAM5; test: no wildcard action]
- No secrets in environment variables: they are visible in the console and
  the template. Read them from Secrets Manager at start-up. [review]

## The CDK app

- `infra/main.ts`, `infra/standard.ts` and `infra/standard.test.ts` belong
  to the Standard; the
  Framework's stacks are in `infra/stacks.ts`, which `defineStacks` returns.
  [review]
- Stacks are environment-agnostic: no `env` from `CDK_DEFAULT_ACCOUNT`, no
  `fromLookup`, so synth needs no account. [review]
- Every stack carries the Standard's tags (`theos:project`,
  `theos:system`, `theos:container`). [test: tags every stack]
- Every stateful resource says its removal policy. [test]
- A CDK Nag finding is fixed in the resource. An acknowledgement
  (`Validations.of(construct).acknowledge({ id, reason })`), on the construct
  the finding's path names or an ancestor of it, names one finding
  on one construct, with a reason specific to this system. [review]
- `cdk.json`'s feature flags are the ones `cdk init` recommends for the
  pinned CDK; a task never turns one off. [review]

## Tests

- No test calls AWS, opens a socket or needs credentials. [review]
- Stacks are tested with `Template.fromStack` from `aws-cdk-lib/assertions`:
  `hasResourceProperties`, `resourceCountIs`, `Match`. Assert what the
  issue needs (a route, a grant, a setting), not the whole template. [review]
- Code that calls AWS is tested through its interface with a fake that
  records the calls and answers from memory. [review]
- Handlers are tested with `go test` by building an
  `events.APIGatewayV2HTTPRequest` and checking the status code and body.
  The stacks' tests build the function with Go, as synth does. [review]
