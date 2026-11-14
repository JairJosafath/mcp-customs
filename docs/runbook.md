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

| Resource                | Holds                                         | When the stack is deleted         |
| ----------------------- | --------------------------------------------- | --------------------------------- |
| `Items` table           | the items                                     | kept; deletion protection is on   |
| backup vault and key    | the daily backups                             | kept, with every backup in it     |
| log groups              | the function's logs and the API's access logs | deleted; kept one year until then |
| alarm topic and its key | nothing                                       | deleted                           |

The physical names are in the stack:
`aws cloudformation describe-stack-resources --stack-name mcp-customs`.

## Restore the items to a point in time

When: bad writes (a bug, a wrong script) or deleted items, within the last
35 days.

1. Find the last good moment: the deploy or script that did the damage, or
   the first bad request in the function's logs.
2. Restore to a new table beside the live one:
   `aws dynamodb restore-table-to-point-in-time --source-table-name <items table> --target-table-name <items table>-restored --restore-date-time <time, ISO 8601>`.
   It takes minutes for a small table, longer for a large one; wait until
   `aws dynamodb describe-table` says `ACTIVE`.
3. Check the restored table holds what you expect (`aws dynamodb get-item`
   on a few known ids).
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
  `cdk deploy -c tier=production --all`. The function, the API and the alarms go
  back; the data does not. If the bad version wrote bad data, restore the
  items as above to the moment it was deployed.
- Never deploy a change that replaces a table (a new key, a new name): the
  deploy makes a new, empty table and keeps the old one outside the stack,
  its data unreachable by the function. Moving data to a new table is a
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

| Alarm                                             | Means                                                                            | First                                                                                                           |
| ------------------------------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `Api-Fault-Count-Critical`                        | the API answered 5xx: the function failed or timed out                           | read the function's logs for `The request failed.` and the request id; roll back if a deploy just went out      |
| `Handler-Fault-Count-Critical`                    | the function failed or timed out, outside `answer`'s handling                    | read the function's logs around the time; an error at start-up (a missing variable) means a broken deploy       |
| `Handler-Throttled-Count-Critical`                | Lambda refused calls: the account's or function's concurrency is used up         | check the account's concurrent executions; a burst from one client is the stage's throttle's to stop            |
| `Handler-Latency-P99-Warning`                     | the slowest calls take over 8 of their 10 seconds                                | check DynamoDB's latency on the dashboard and the function's duration in its logs; a timeout is next            |
| `Items-Read-Throttled-Events-Critical`, `-Write-` | DynamoDB throttled reads or writes: a hot key or a burst past on-demand's limits | find the key in the logs; on-demand adapts within minutes, a hot key needs a change to the key design           |
| `Items-SystemError-Count-Critical`                | DynamoDB failed requests on its side                                             | check the AWS Health Dashboard for DynamoDB in the region; the SDK retries, so watch whether clients see errors |

When an alarm fires, note the time, what you saw and what you did; when it
has fired before for the same cause, that cause needs a fix, not another
note.

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
once a quarter, and after a change to the tables: restore the items to a
point in time into a new table, check a few items, time it, and delete the
table; write down how long it took. Once a year, a game day: break the
development stack the way an incident would, and answer it with this
runbook alone.
