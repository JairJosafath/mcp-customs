# Runbook

What to do when `mcp-customs` goes wrong in AWS: restore its data, roll a
deployment back, and answer an alarm. It is written for the production tier,
which `cdk deploy -c tier=production --all` deploys (every stack, as one
deploy needs `--all` when there are two): a development stack keeps no data worth
restoring, and only its alarms apply. This file belongs to the Standard; a
change to what the stacks keep or how they back it up changes it too,
through a Standard change.

Everything below is done by a person with the account's credentials, in the
stack's region unless it says otherwise. Nothing in this repository calls
AWS, and no agent runs these commands.

## What the Container promises

`infra/operations.ts` holds the Container's `spec.operations`; when it and
this list differ, it is right.

- Recovery point objective (RPO): 1h, the most data a restore may lose.
- Recovery time objective (RTO): 4h, the longest the API may be without its data.
- Backups: daily, kept 35 days.
- Alarms tell: nobody by default; a deploy sets the `AlertEmail` parameter.

Point-in-time recovery restores any second of the last 35 days, up to about
five minutes before now, so it meets an RPO of minutes. The daily backups, kept 35 days, reach back no further than it
does: they are a second copy inside the same window, kept apart from the
table. Damage older than 35 days can't be undone; a
`retentionDays` above 35 keeps backups beyond it. Whether a
restore fits the RTO only a drill shows: see [Drills](#drills).

## What the stack keeps

| Resource                | Holds                                                                                                                         | When the stack is deleted         |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `Table` table           | checks, their steps and verdicts (`pk`, `sk`)                                                                                 | kept; deletion protection is on   |
| `Reports` bucket        | reports and observations, with their earlier versions; the demo Go module proxy under `goproxy/`, which a deploy writes again | kept, with every object in it     |
| backup vault and key    | the daily backups of the table                                                                                                | kept, with every backup in it     |
| log groups              | the Checker's and web function's logs and the API's access logs                                                               | deleted; kept one year until then |
| alarm topic and its key | nothing                                                                                                                       | deleted                           |
| `RecheckDeadLetters`    | polls the re-check schedule could not deliver, 14 days at most                                                                | deleted                           |

The physical names are in the stack:
`aws cloudformation describe-stack-resources --stack-name mcp-customs`.

## Restore the table to a point in time

When: bad writes (a bug, a wrong script) or deleted items, within the last
35 days.

1. Find the last good moment: the deploy or script that did the damage, or
   the first bad request in the functions' logs.
2. Restore to a new table beside the live one:
   `aws dynamodb restore-table-to-point-in-time --source-table-name <table> --target-table-name <table>-restored --restore-date-time <time, ISO 8601>`.
   It takes minutes for a small table, longer for a large one; wait until
   `aws dynamodb describe-table` says `ACTIVE`.
3. Check the restored table holds what you expect (`aws dynamodb get-item`
   on a few known checks, `pk` `CHECK#<id>` and `sk` `META`).
4. Repair the live table from it: write back the items the damage changed,
   with a short script using the SDK, or `aws dynamodb batch-write-item`.
   The live table keeps its name, its alarms, its backups and its place in
   the stack.
5. Delete the restored table (`aws dynamodb delete-table`) and write down
   what happened and when.

A restored table lacks what a restore doesn't carry: auto scaling, IAM
policies, CloudWatch alarms, tags, streams, time to live and point-in-time
recovery. That is why the live table is repaired, not replaced.

## Restore from a backup in the vault

When: point-in-time recovery was off. The backups reach back 35 days, no
further than point-in-time recovery, so damage older than 35 days can't be
undone from them either.

1. List the backups:
   `aws backup list-recovery-points-by-backup-vault --backup-vault-name <the vault, Backups/Vault in the stack>`.
2. Restore the one before the damage to a new table: in the AWS Backup
   console, _Protected resources_, the table, the recovery point, _Restore_,
   with a new table name; or `aws backup start-restore-job` with the
   recovery point's ARN, `--metadata TargetTableName=<new name>` and a role
   that has `AWSBackupServiceRolePolicyForRestores`.
3. Go on from step 3 of the point-in-time restore.

## Restore a report

When: a report or observations object was overwritten or deleted, within
the last 35 days (or `retentionDays`, when longer). The bucket keeps every
earlier version that long.

1. List the versions:
   `aws s3api list-object-versions --bucket <the Reports bucket> --prefix reports/<check-id>.json`.
2. Copy the last good version over the current one:
   `aws s3api copy-object --bucket <bucket> --key reports/<check-id>.json --copy-source "<bucket>/reports/<check-id>.json?versionId=<version>"`.
   A deleted object has a delete marker as its current version; deleting
   the marker (`aws s3api delete-object ... --version-id <marker's id>`)
   brings the object back.

The bucket is not in the backup plan: its versions are its recovery, and a
report can be written again from its check.

## The table is gone

The stack refers to its table by name. If a table was deleted by hand
(after deletion protection was turned off), restore it under its own name:
point-in-time recovery from the deleted table's system backup
(`<name>$DeletedTableBackup`, kept 35 days) or a backup from the vault,
with `--target-table-name` the old name. Then set again what a restore
doesn't carry: point-in-time recovery
(`aws dynamodb update-continuous-backups`), deletion protection, and the three
`theos:` tags. The backup plan names each table that holds data by its ARN, which a
table restored under the same name in the same account and region keeps,
so it is backed up again from the next day. Deploy the stack again
(`cdk deploy -c tier=production --all`) and check it reports no drift.

## Roll a deployment back

- A deploy that fails rolls back by itself: CloudFormation returns the
  stack to its last good state (`UPDATE_ROLLBACK_COMPLETE`). If it stops in
  `UPDATE_ROLLBACK_FAILED`, fix what it names and run
  `aws cloudformation continue-update-rollback --stack-name mcp-customs`.
- A deploy that succeeded but misbehaves: deploy the last good commit.
  Check out its tag or commit, run `make check`, then
  `cdk deploy -c tier=production --all`. The functions, the API and the alarms go
  back; the data does not. If the bad version wrote bad data, restore the
  table as above to the moment it was deployed.
- Never deploy a change that replaces a table (a new key, a new name): the
  deploy makes a new, empty table and keeps the old one outside the stack,
  its data unreachable by the functions. Moving data to a new table is a
  migration, planned and run by a person; if it happened by mistake, deploy
  the last good commit and bring the old table back as in
  [The table is gone](#the-table-is-gone).
- Termination protection refuses `cdk destroy` in production. Turning it
  off is the account owner's decision; the tables and the vault stay anyway.

## Alarms

Every alarm notifies the stack's alarm topic (the output `AlarmTopicArn`);
the `AlertEmail` parameter subscribes an address, which must confirm the
email AWS sends it. The dashboard `mcp-customs` shows each alarm's metric. Each
alarm fires on one bad five-minute period and clears itself when the next
one is good. An alarm's name is the stack's, `mcp-customs-`, then the name below.

| Alarm                                                   | Means                                                                                          | First                                                                                                                                                                                                             |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Api-Fault-Count-Critical`                              | the API answered 5xx: the web function failed or timed out                                     | read the web function's logs for `The request failed.` and the request id; roll back if a deploy just went out                                                                                                    |
| `Web-Fault-Count-Critical`                              | the web function failed or timed out, outside `web.Answer`'s handling                          | read its logs around the time; an error at start-up means a broken deploy                                                                                                                                         |
| `Checker-Fault-Count-Critical`                          | a Checker invocation failed or timed out                                                       | read the Checker's logs, then the execution (`aws lambda get-durable-execution --durable-execution-arn <the check's executionArn>`); an error at start-up (a missing `DYNAMODB_TABLE_NAME`) means a broken deploy |
| `Web-Throttled-Count-Critical`, `Checker-`, `Poller-`   | Lambda refused calls: the account's or function's concurrency is used up                       | check the account's concurrent executions; a burst from one client is the stage's throttle's to stop                                                                                                              |
| `Web-Latency-P99-Warning`                               | the slowest web calls take over 8 of their 10 seconds                                          | check DynamoDB's latency on the dashboard and the function's duration in its logs; a timeout is next                                                                                                              |
| `Checker-Latency-P99-Warning`                           | the slowest Checker invocations take over 240 of their 300 seconds                             | read which step ran long in its logs; a timeout is next, which the durable execution retries from its last checkpoint                                                                                             |
| `Table-Read-Throttled-Events-Critical`, `-Write-`       | DynamoDB throttled reads or writes: a hot key or a burst past on-demand's limits               | find the key in the logs; on-demand adapts within minutes, a hot key needs a change to the key design                                                                                                             |
| `Table-SystemError-Count-Critical`                      | DynamoDB failed requests on its side                                                           | check the AWS Health Dashboard for DynamoDB in the region; the SDK retries, so watch whether clients see errors                                                                                                   |
| `Poller-Fault-Count-Critical`                           | a poll for new versions of approved packages failed: a registry, the table or the Checker      | read the poller's logs for `A package could not be polled.`, which names the package; the next poll, minutes later, tries again, and a re-check is started once whatever the retries                              |
| `Poller-Latency-P99-Warning`                            | the slowest polls take over 48 of their 60 seconds                                             | a registry is slow, or there are many approved packages: the poller polls them concurrently (at most 8 at once), so one slow registry does not block the rest, and each slow package is logged with its error     |
| `RecheckDeadLetters-Queue-Message-Count-Max-Critical`   | the Scheduler could not invoke the poller, after its retries                                   | read a message in `RecheckDeadLetters` for its error (often the poller's permission or a deleted function); the poll needs no replay: purge the queue once the next one runs                                      |
| `RecheckSchedule-Dropped-Critical`, `-NotDeadLettered-` | the Scheduler dropped a poll, or could not put it in the dead-letter queue                     | check the schedule (`aws scheduler get-schedule`) and its role; the next poll runs on time                                                                                                                        |
| `RecheckFailedTwice-Critical`                           | a re-check of a newer version failed, and its one retry failed too: the version is not checked | read the Checker's logs for `A re-check failed twice.`, which names the retry and the approved check, then that check's page and the execution; once the cause is fixed, submit the version by hand               |

When an alarm fires, note the time, what you saw and what you did; when it
has fired before for the same cause, that cause needs a fix, not another
note.

## The demo proxy

The stack serves the demo servers' versions itself, as a Go module proxy:
the files under the `Reports` bucket's `goproxy/` prefix, read by the web
function at `<EntryPoint>/goproxy/` and by nothing else. The poller and
the sandbox's `go install` ask it first and the public proxy after it
(`GO_PROXY_URL`); the sandbox skips the checksum database for the demo
modules, `github.com/JairJosafath/mcp-customs/demo/...`, alone, and may
only GET under `/goproxy/` of the stack's API while an install runs. Only
the deploy writes the prefix: the `DemoProxy` deployment copies the files
synth built, and prunes the ones it no longer publishes. A missing file
answers 404, which sends the go command on to the public proxy.

What a deploy publishes is what `infra/demo-versions.json`, a committed
file, names for each demo, with every earlier version: `mail` v1.0.0 and
v1.0.1, `weather` v1.0.0, each a module whose default build is that
version. Synth reads the file; no context value or variable changes it.
`make demo-build` writes the same files into `cdk.out/demo-proxy` to look
at, without AWS.

The live rug pull:

1. Deploy as usual (`cdk deploy -c tier=<tier>`). The committed file names
   `"mail": "v1.0.0"`, so the proxy serves v1.0.0.
2. Check it is served:
   `curl '<EntryPoint>/goproxy/github.com/!jair!josafath/mcp-customs/demo/mail/@v/list'`
   answers `v1.0.0`.
3. Submit `github.com/JairJosafath/mcp-customs/demo/mail@v1.0.0` as a Go
   module, and let it pass (or Approve it).
4. Publish the rug pull: a one-line commit to `infra/demo-versions.json`,
   `"mail": "v1.0.1"`, merged and deployed. Within five minutes
   (`RECHECK_INTERVAL`) the poller sees v1.0.1 and starts its re-check,
   linked to the v1.0.0 check, which ends in block.

Setting the file back to `v1.0.0` and deploying takes v1.0.1 off the
proxy. A re-check of v1.0.1 starts once per stack, since its ID comes from
the version, so to show the rug pull again, use a fresh development stack.

## What the account provides

What the factory itself needs in the account to ship this Container (the
CDK bootstrap and its credential's policy) is in the `aws-standard`
Standard's README, under _Deploying_.

The stacks hold only this Container's resources. These are set once per
account, by its owner, and never by a stack here:

- GuardDuty, for threat detection in the account.
- Security Hub, for the account's security findings in one place.
- CloudTrail, recording every API call to an S3 bucket kept apart.
- AWS Config, recording how resources change.
- AWS Budgets, with an alert on what the account spends.
- The cost allocation tags' activation: `theos:project`,
  `theos:system` and `theos:container` attribute costs only once the
  account activates them in Billing.

A vault lock on the backup vault is the account owner's call too: in
compliance mode it can never be undone.

## Drills

Only a drill shows that a restore works and fits the RTO (4h). At least
once a quarter, and after a change to the tables: restore the table to a
point in time into a new table, check a few checks, time it, and delete the
table; write down how long it took. Once a year, a game day: break the
development stack the way an incident would, and answer it with this
runbook alone.
