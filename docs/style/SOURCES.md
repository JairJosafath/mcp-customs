# Sources

Every source read to write `docs/style/` and `docs/well-architected.md`. This
Standard was copied from ts-standard v1.5.0: its TypeScript rules
(`typescript.md`, the ESLint config, Prettier) and `principles.md` are
ts-standard's, and a test in theos keeps them equal. The TypeScript
sources were read on 2026-10-02 for ts-standard. Of the AWS sources, the
Well-Architected Framework, its Serverless Applications Lens and Lambda's best
practices were read on 2026-10-13, and CDK Nag's rules from the installed
package; the other AWS pages are the references the digests follow, not
fetched again for them: check one before relying on a detail it alone gives.
The cross-language sources were read on 2026-09-30 for another
Standard, whose `principles.md` ts-standard adapts; they were not read again.
Version or date as shown on the page; "live" when the page shows none.

For the Go function, `go.md` and `.golangci.yml` are go-standard's, copied
from go-standard v1.6.0, and a test in theos keeps them equal; its Go
sources were read on 2026-10-02 for go-standard and are listed in its own
`SOURCES.md`. The Go pages of the AWS docs below are the references the
digests follow, not fetched for them: check one before relying on a detail
it alone gives.

## TypeScript

| Source                                                                                                                     | Version / date                                                             |
| -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Google TypeScript Style Guide — https://google.github.io/styleguide/tsguide.html                                           | live                                                                       |
| TypeScript handbook, Do's and Don'ts — https://www.typescriptlang.org/docs/handbook/declaration-files/do-s-and-don-ts.html | live                                                                       |
| typescript-eslint shared configs — https://typescript-eslint.io/users/configs/                                             | live; `strict-type-checked` is not semver-stable, so the version is pinned |

## AWS

| Source                                                                                                                                                           | Version / date                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| AWS Well-Architected Framework — https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html                                                       | November 6, 2024                     |
| Serverless Applications Lens — https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/welcome.html                                      | July 14, 2022                        |
| Lambda, best practices — https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html                                                                        | live                                 |
| Lambda, Node.js handler and its best practices — https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html                                                | live                                 |
| Lambda, JSON log format — https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-logformat.html                                                  | live                                 |
| API Gateway, HTTP API Lambda integrations (payload 2.0) — https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html | live                                 |
| API Gateway, HTTP API access control and logging — https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control.html                     | live                                 |
| DynamoDB, best practices — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html                                                  | live                                 |
| AWS SDK for JavaScript v3, developer guide — https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/                                                  | live                                 |
| AWS CDK v2 developer guide, best practices — https://docs.aws.amazon.com/cdk/v2/guide/best-practices.html                                                        | live                                 |
| AWS CDK assertions module — https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.assertions-readme.html                                                       | aws-cdk-lib 2.273.0                  |
| CDK Nag README and RULES.md (AwsSolutions and Serverless packs) — https://github.com/cdklabs/cdk-nag/blob/main/RULES.md                                          | cdk-nag 3.0.2, read from the package |
| cfn-lint — https://github.com/aws-cloudformation/cfn-lint                                                                                                        | 1.57.2 (PyPI, 2026-10-13)            |

## Go on AWS

| Source                                                                                                                | Version / date |
| --------------------------------------------------------------------------------------------------------------------- | -------------- |
| Building Lambda functions with Go — https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html                   | live           |
| Lambda Go handler — https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html                                  | live           |
| Deploy Go Lambda functions with .zip file archives — https://docs.aws.amazon.com/lambda/latest/dg/golang-package.html | live           |
| AWS SDK for Go v2, developer guide — https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/                       | live           |
| aws-lambda-go — https://github.com/aws/aws-lambda-go                                                                  | v1.55.1        |

## Tools

The versions pinned in the Framework's `package.json` and `package-lock.json`:
TypeScript 6.0.3 (typescript-eslint 8.71.0 supports `<6.1.0`, so not 7.x),
ESLint 10.11.0, @eslint/js 10.0.1, typescript-eslint 8.71.0, Prettier 3.9.9,
vitest 5.0.3, @types/node 24.19.1, aws-cdk-lib 2.273.0, constructs 10.8.1,
aws-cdk (the CLI) 2.1145.0, cdk-nag 3.0.2, tsx 4.23.15, and for the alarms
cdk-monitoring-constructs 10.3.2. In `src/go.mod` and `src/go.sum`: Go 1.26,
github.com/aws/aws-lambda-go 1.55.1, github.com/aws/aws-sdk-go-v2 1.47.3, its
`config` 1.33.9 and `service/dynamodb` 1.70.3. golangci-lint is the runner's
(v2.14). The `Makefile` runs cfn-lint 1.57.2 with uv. The CDK Nag rules these
docs name were read from cdk-nag 3.0.2's `RULES.md`, and `cdk.json`'s feature
flags are the ones `cdk init` of aws-cdk 2.1145.0 writes.

## Operations (read 2026-10-16)

Read for the tiers, the backups, the alarms and `docs/runbook.md`. The
pricing pages were read for what costs more, not for figures: the digests
give none.

| Source                                                                                                                                                                                                                          | Version / date |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| Reliability pillar, REL09 Back up data — https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/back-up-data.html                                                                                                | live           |
| Reliability pillar, REL13 Plan for disaster recovery — https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/plan-for-disaster-recovery-dr.html                                                                 | live           |
| Reliability pillar, REL06 Monitor workload resources — https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/monitor-workload-resources.html                                                                    | live           |
| Operational excellence pillar, OPS08 workload observability (BP04 alerts, BP05 dashboards) — https://docs.aws.amazon.com/wellarchitected/latest/operational-excellence-pillar/ops_workload_observability_create_alerts.html     | live           |
| Serverless Applications Lens, structured logging — https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/opex-logging.html                                                                            | July 14, 2022  |
| AWS Backup, advanced DynamoDB backup — https://docs.aws.amazon.com/aws-backup/latest/devguide/advanced-ddb-backup.html                                                                                                          | live           |
| AWS Backup, restoring a DynamoDB table — https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-dynamodb.html                                                                                                         | live           |
| AWS Backup, vault lock — https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html                                                                                                                                 | live           |
| DynamoDB, point-in-time recovery — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Point-in-time-recovery.html                                                                                                 | live           |
| DynamoDB, restoring a table to a point in time — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.Tutorial.html                                                                             | live           |
| cdk-monitoring-constructs README — https://github.com/cdklabs/cdk-monitoring-constructs/blob/v10.3.2/README.md                                                                                                                  | 10.3.2         |
| cfn-lint rules, I3011 and I3013 — https://github.com/aws-cloudformation/cfn-lint/blob/main/docs/rules.md                                                                                                                        | 1.57.2         |
| Pricing: DynamoDB, AWS Backup, CloudWatch, X-Ray — https://aws.amazon.com/dynamodb/pricing/on-demand/, https://aws.amazon.com/backup/pricing/, https://aws.amazon.com/cloudwatch/pricing/, https://aws.amazon.com/xray/pricing/ | live           |

## Cross-language (read 2026-09-30)

| Source                                                                                                             | Version / date |
| ------------------------------------------------------------------------------------------------------------------ | -------------- |
| LLVM Coding Standards — https://llvm.org/docs/CodingStandards.html                                                 | live           |
| Chromium style guide index — https://chromium.googlesource.com/chromium/src/+/HEAD/styleguide/styleguide.md        | HEAD           |
| Google style guides index — https://google.github.io/styleguide/                                                   | live           |
| Mozilla C++ coding style — https://firefox-source-docs.mozilla.org/code-quality/coding-style/coding_style_cpp.html | live           |
| Linux kernel coding style — https://docs.kernel.org/process/coding-style.html                                      | live           |
| C++ Core Guidelines — https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines                                 | Jun 14, 2026   |
| Rust API Guidelines, naming — https://rust-lang.github.io/api-guidelines/naming.html                               | live           |
| GNU Coding Standards — https://www.gnu.org/prep/standards/standards.html                                           | April 27, 2026 |
