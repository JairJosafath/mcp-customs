# Well-Architected

A digest of the AWS Well-Architected Framework and its Serverless Applications
Lens, for this repository: one section per pillar, what the pillar asks of a
serverless API, what each tier does about it, what `infra/operations.ts`
changes, the CDK Nag rules (`AwsSolutions` and `Serverless` packs) and the
Standard's checks that enforce it, and what stays by hand, with the reason.
Sources and the date they were read are in `docs/style/SOURCES.md`. This
file belongs to the Standard: a task never changes it.

`make check` synthesizes every stack for both tiers, into
`cdk.out/production/` and `cdk.out/development/`, and runs CDK Nag's
`AwsSolutions` and `Serverless` checks on both (`infra/standard.ts`): a
finding fails synth unless it is acknowledged, on one construct, with a
reason.
`infra/standard.test.ts` checks, for both tiers, what CDK Nag doesn't: tags,
wildcard actions, encryption, log retention, removal policies, and every
promise below. `cfn-lint --include-checks I` lints both, with I3011 (a
stateful resource without a deletion policy) and I3013 (content that expires
without a set retention). The Serverless pack's rules are named where they
apply. The Standard acknowledges, on every stack, the five that check what an
`AwsSolutions` rule checks too (`LambdaLatestVersion`, `LambdaStarPermissions`,
`APIGWAccessLogging`, `SQSRedrivePolicy`, `StepFunctionStateMachineXray`), and
on the one resource those that are wrong for it, each with its reason in
`infra/standard.ts`.

## Tiers and the operations block

The tier is where the stacks run, and a deploy names it:
`cdk deploy -c tier=production`, or `development` when it names none. The
code never picks one, and nothing else is read at synth: a synth of a tier is
the same on every machine. A development stack's name ends in
`-development`, so a deploy that names no tier never changes a production
stack. `infra/standard.ts` (`TIER_RULES`) says what each tier means:

| Every stack                                     | `production`                        | `development`   |
| ----------------------------------------------- | ----------------------------------- | --------------- |
| Data: tables, the backup vault and its key      | kept when the stack goes (`RETAIN`) | deleted with it |
| Deletion protection on tables, and on the stack | on                                  | off             |
| Point-in-time recovery on every table           | on                                  | off             |
| AWS Backup                                      | daily, for `retentionDays`, copied  | none            |
| X-Ray tracing                                   | on                                  | off             |
| Log retention                                   | one year                            | one month       |
| Alarms, their topic and a dashboard             | on                                  | on              |

What the Container promises in either tier is `infra/operations.ts`, which
the factory renders from its `spec.operations`; a change to the block is
written into the file, never the other way.

- `backups.retentionDays`: days AWS Backup keeps each daily backup in
  production; 0 keeps point-in-time recovery only.
- `backups.copyToRegion`: a second region every backup is copied to; empty
  for none.
- `recovery.rpo` and `recovery.rto`: the most data a restore may lose and
  the longest it may take, which `docs/runbook.md` is written to.
- `alerts.email`: the default of each stack's `AlertEmail` parameter, which
  a deploy sets per environment; empty tells nobody.

## Operational excellence

_Run and monitor the system, and improve it in small, reversible changes._

- Everything is code: the stacks in `infra/` are the only way resources are
  made. No change by hand in the console.
- Changes are small, frequent and checked: `make check` synthesizes and
  lints every change for both tiers; nothing here deploys.
- Observe (OPS08, REL06): structured JSON logs through `log/slog`, with the
  request id, the route and the error; a log group per function and an
  access log per API stage; X-Ray traces in production, Lambda's own
  segments. There is no Powertools for Go: the function sends no metrics of
  its own, and the alarms read what Lambda, API Gateway and DynamoDB
  report.
  - `AwsSolutions-APIG1`: the API has access logging.
  - Serverless `APIGWStructuredLogging`: an access log in JSON. The stage
    writes a JSON object per request, with the request id, the route, the
    status, the latencies and the integration's error. A stage scaffolded
    before aws-lambda-ts v1.4.0 or aws-lambda-py and -go v1.3.0 writes the
    Common Log Format, which the Standard acknowledges: it cannot tell a
    repository's Framework version, so it cannot hold an older one to JSON.
  - Serverless `LambdaTracing`: every function traces in production; the
    Standard acknowledges it in development, which traces nothing.
  - Serverless `CloudWatchLogGroupRetentionPeriod`: every log group has a
    retention; `infra/standard.test.ts` checks it is the tier's time.
- Alarms are code (OPS08-BP04, REL06-BP03), the same in both tiers:
  `cdk-monitoring-constructs` builds them on the API's 5xx, the function's
  errors, throttles and p99 duration (over 8 of its 10 seconds), and each
  table's read and write throttles and system errors, each firing on one bad
  five-minute period. Every alarm notifies the stack's one SNS topic,
  encrypted with its own key, and a dashboard per stack shows them
  (OPS08-BP05). `infra/standard.test.ts` checks that every function, table
  and API has its alarms and that every alarm notifies the topic: a new
  resource gets its alarms from the stack's `Alarms`
  (`alarms.monitoring.monitorDynamoTable(...)`).
- Nobody is told without asking: the `AlertEmail` parameter subscribes one
  address to the topic, and an empty one none. The topic's ARN is the
  stack's `AlarmTopicArn` output and its URL `EntryPoint`, so a deploy
  target can subscribe its own channel and find the API.
- A runbook: `docs/runbook.md` says what each alarm means and what to do
  first, how to restore the data and how to roll a deployment back. A
  change to what the stacks keep updates it, as a Standard change.
- Tag everything so cost and ownership are traceable: every stack carries
  `theos:project`, `theos:system` and `theos:container`
  (`infra/standard.ts`, tested).
- By hand, and why: whether the alarms fire for the right reasons, and
  which are missing (REL06-BP06), only a deployed stack's history shows;
  review it after every incident.

## Security

_Protect data, systems and assets: identity, least privilege, encryption,
traceability, and protection at every layer._

- Least privilege: each function has its own role, granted through CDK
  grants (`table.grant(fn, 'dynamodb:GetItem')`) only the calls its code
  makes.
  - `AwsSolutions-IAM4`: no AWS managed policies on a role, but AWS
    Backup's, whose `AWSBackupServiceRolePolicyForBackup` is acknowledged in
    `infra/backups.ts`.
  - `AwsSolutions-IAM5`: no wildcard actions or resources without an
    acknowledgement naming the one finding and why. X-Ray's write actions
    take no resource but `*`: `infra/standard.ts` acknowledges that, in
    production, on a policy where nothing else has it.
  - `infra/standard.test.ts`: no `*` or `service:*` action anywhere, but a
    key's default policy, which hands the key's use to the account's IAM.
- Authenticate every request: every route has an authorizer (IAM, JWT or a
  Lambda authorizer).
  - `AwsSolutions-APIG4`: the API implements authorization.
  - `AwsSolutions-COG4`: a REST API method uses a Cognito authorizer.
- Encrypt at rest and in transit.
  - `AwsSolutions-S10`, `AwsSolutions-SQS4`, `AwsSolutions-SNS3`: requests
    must use TLS; the alarm topic refuses any other.
  - `AwsSolutions-SQS2`, `AwsSolutions-EFS1`: encryption at rest; DynamoDB
    is always encrypted, and `infra/standard.test.ts` requires a KMS key
    (`SSESpecification`) on every table, encryption on every bucket, queue
    and topic.
  - Backups are encrypted with the vault's own key (REL09-BP02); the alarm
    topic with its own, which CloudWatch may use to publish.
  - `AwsSolutions-KMS5`: customer-managed keys rotate.
- Protect data from the public: `AwsSolutions-S2` (bucket public access
  blocked), `AwsSolutions-S5`, `AwsSolutions-EVB1` (no open event bus
  policy). `AwsSolutions-APIG3` and `AwsSolutions-CFR2` warn when a REST API
  or a distribution has no WAF.
- Secrets live in Secrets Manager, rotated (`AwsSolutions-SMG4`), read at
  start-up; never in an environment variable, the template, a log or the
  repository.
- The account's own guards (GuardDuty, Security Hub, CloudTrail, AWS Config)
  are its owner's, not a stack's: `docs/runbook.md` lists them.
- By hand: validate all input at the boundary; never log user data or
  tokens; never return internal errors to a client.

## Reliability

_Recover from failure, scale with demand, and keep working when a part
fails._

- Managed, multi-AZ services: Lambda, API Gateway and DynamoDB spread over
  Availability Zones on their own.
- Recovery objectives (REL13-BP01): `recovery.rpo` and `recovery.rto` say
  what a restore in production may lose and how long it may take;
  `docs/runbook.md` is written to them.
- Back up data (REL09), in production:
  - Point-in-time recovery on every table: any second of the last 35 days,
    up to about five minutes before now, restored to a new table. It meets
    an RPO of minutes.
  - An AWS Backup plan (REL09-BP03): a daily backup at 05:00 UTC of the
    stack's tables that hold data, named by ARN, so a new table is in it
    only when the stack names it, kept `retentionDays` in a vault with its own key (REL09-BP02); with
    `copyToRegion`, each copied to a vault in that region (the
    `<name>-backup-copy` stack), so a lost region loses no more than a day
    (REL13-BP02, backup and restore).
  - No vault lock: in compliance mode it can never be undone, which is the
    account owner's decision.
  - Development backs up nothing: its data goes with its stack.
- Nothing of value is deleted by accident, in production: tables are
  `RETAIN` with deletion protection, and the stack has termination
  protection. A change that replaces a table (a new key) keeps the old one
  but leaves it outside the stack, empty of the new one's data: review
  every change to a table's key as a migration.
  - `AwsSolutions-DDB3`: point-in-time recovery; `infra/standard.ts`
    acknowledges it in development only.
  - `infra/standard.test.ts`: per tier, the removal policies, the
    protections, point-in-time recovery, the backup plan, its vault and its
    copy.
  - cfn-lint I3011: every stateful resource has a deletion policy.
- Restore by a written procedure (REL09-BP04, REL13-BP05):
  `docs/runbook.md` restores the items to a point in time, from the vault,
  from the copy, and a deleted table, and rolls a deployment back.
- Handle failures in asynchronous work: a queue or event source has a
  dead-letter queue.
  - `AwsSolutions-SQS3`: a queue has a DLQ or is one.
  - Serverless `LambdaDLQ`, `LambdaAsyncFailureDestination`, `EventBusDLQ`:
    an asynchronous invocation or an event bus rule a change adds has a
    dead-letter queue. API Gateway's call is synchronous and its client
    retries, so the Standard acknowledges `LambdaDLQ` on a function only
    API Gateway calls.
- Idempotency, by hand: a retried request changes nothing twice. There is
  no Powertools for Go, and no idempotency table: a `PUT` replaces the whole
  item, so repeating one leaves the same item. A new route that changes data
  keeps that true, or makes its write conditional (`ConditionExpression`);
  never a blind increment.
- Limits: timeouts on every function, below the caller's (API Gateway: 30
  seconds); throttling on every API stage, so a burst can't exhaust the
  account's concurrency. Serverless `LambdaDefaultTimeout` and
  `APIGWDefaultThrottling`: every function sets a timeout, every stage its
  throttling.
- By hand, and why: a restore drill (REL09-BP04, REL13-BP03), at least a
  quarter apart, and a game day once a year; only an account shows that a
  restore works and how long it takes, so the RTO is a promise until a drill
  measures it. `docs/runbook.md` says how.

## Performance efficiency

_Use resources efficiently as demand changes and technology evolves._

- The newest runtime: `AwsSolutions-L1`.
- Size memory to the work (Lambda gives CPU in proportion); measure before
  raising it. Serverless `LambdaDefaultMemorySize`: every function sets its
  memory.
- Cold starts: one static binary (`go build`, `CGO_ENABLED=0`,
  `-ldflags '-s -w'`, `-tags lambda.norpc`) named `bootstrap` on
  `provided.al2023` for `arm64`; SDK clients made once in `main` or at
  package scope, before `lambda.Start`, never per request; only the service
  packages used (`service/dynamodb`), and no heavy work in `init`.
- Data access by key: `GetItem` and `Query` on keys and indexes; a `Scan` is
  never on a request path.
- Find where time goes with the production traces and the p99 duration
  alarm.
- By hand: measure a stated budget with a benchmark, and say what only a
  deployed function can show (cold start, latency in AWS).

## Cost optimization

_Deliver value at the lowest price: pay only for what you use, and know
where the money goes._

- Pay per use: on-demand DynamoDB, Lambda and the HTTP API, which costs
  less than a REST API.
- `arm64` (Graviton) functions: cheaper per millisecond than x86.
- What production costs over development: point-in-time recovery on every
  table (by the table's size, per month); AWS Backup's storage (each daily
  backup is a full copy of the table, kept `retentionDays`, so about that
  many times the table's size), and with `copyToRegion` the transfer of each
  copy and its storage there; X-Ray for every trace past the free tier;
  twelve months of logs instead of one; and a KMS key per vault. There are
  no NAT gateways to pay for. The alarms (each per month) and the dashboard
  cost the same in both tiers. Lower `retentionDays` to pay less for
  backups; 0 keeps point-in-time recovery alone.
- Log retention limits what storage costs grow to (`infra/standard.test.ts`,
  cfn-lint I3013).
- Tags attribute every cost to its project, system and container, once the
  account activates them as cost allocation tags.
- Throttling caps what a runaway client can spend.
- By hand, and why: right-size memory and timeouts from measured load,
  which only a deployed function's metrics show; no provisioned concurrency
  or capacity unless the issue states the load that needs it.

## Sustainability

_Minimize the environmental impact of the workload._

- Serverless and managed services run only while there is work, on shared
  infrastructure.
- `arm64` (Graviton) uses less energy for the same work.
- Keep what is needed, no longer: log retention by tier, backups for
  `retentionDays`, development keeping no backups, and no data stored that
  the system's needs don't ask for.
- Efficient code: no polling, no work per request that can be done once at
  start-up, a small static binary.
- No rule enforces these: review them.

## Acknowledging a finding

Fix the resource first. When the fix is wrong for this system, acknowledge
the one finding on the construct the finding's path names (or its nearest
ancestor you own): a finding on `HandlerRole/DefaultPolicy/Resource`
is acknowledged on the role, not on the function beside it.

```ts
Validations.of(role).acknowledge({
  id: 'AwsSolutions-IAM5[Resource::*]',
  reason: 'X-Ray PutTraceSegments and PutTelemetryRecords accept no resource but *.',
});
```

The reason says why this resource needs it, true and specific; the reviewer
checks every one, and a vague reason ("not needed", "for now") is blocking.
