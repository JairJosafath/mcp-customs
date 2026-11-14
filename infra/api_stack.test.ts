import { App } from 'aws-cdk-lib';
import { Capture, Match, Template } from 'aws-cdk-lib/assertions';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  ApiStack,
  CALLBACK_ACTION,
  DURABLE_EXECUTION_ACTIONS,
  JUDGE_INFERENCE_PROFILE,
  JUDGE_MODEL,
  JUDGE_MODEL_REGIONS,
  REPORT_PREFIXES,
  WEB_ROUTES,
} from './api_stack';
import { copyVaultName } from './backups';
import { PASS_CONNECTOR_ACTION, SANDBOX_ACTIONS } from './sandbox';
import type { Operations, Tier } from './standard';

const OPERATIONS: Operations = {
  backups: { retentionDays: 35, copyToRegion: '' },
  recovery: { rpo: '1h', rto: '4h' },
  alerts: { email: '' },
};

/** The stack's app and template for `tier`, with `operations` changed as given. */
function build(
  tier: Tier,
  backups: Partial<Operations['backups']> = {},
  alerts: Partial<Operations['alerts']> = {},
): { app: App; template: Template } {
  const operations: Operations = {
    ...OPERATIONS,
    backups: { ...OPERATIONS.backups, ...backups },
    alerts: { ...OPERATIONS.alerts, ...alerts },
  };
  const app = new App();
  const template = Template.fromStack(new ApiStack(app, 'test', { tier, operations }));
  return { app, template };
}

/** The stack's template for `tier`, with `operations` changed as given. */
function synth(
  tier: Tier,
  backups: Partial<Operations['backups']> = {},
  alerts: Partial<Operations['alerts']> = {},
): Template {
  return build(tier, backups, alerts).template;
}

/** The logical ID of the one resource of `type` whose ID starts with `prefix`. */
function idOf(template: Template, type: string, prefix: string): string {
  const ids = Object.keys(template.findResources(type)).filter((id) => id.startsWith(prefix));
  expect(ids, `${type} ${prefix}`).toHaveLength(1);
  return ids[0] ?? '';
}

/** The IAM actions the policies attached to the role `roleId` allow, sorted. */
function actionsOf(template: Template, roleId: string): string[] {
  return Object.values(template.findResources('AWS::IAM::Policy'))
    .filter((policy: unknown) => JSON.stringify(policy).includes(`{"Ref":"${roleId}"}`))
    .flatMap((policy: unknown) => {
      const document = JSON.stringify(policy).split('"Roles"')[0] ?? '';
      // Not a condition key, such as "s3:prefix", which is a JSON object's key.
      return document.match(/"[a-z0-9]+:[A-Za-z]+"(?!:)/g) ?? [];
    })
    .sort();
}

let outdir: string;
let production: Template;
let development: Template;

beforeAll(() => {
  const built = build('production');
  outdir = built.app.outdir;
  production = built.template;
  development = synth('development');
});

describe('ApiStack', () => {
  it('keeps checks in one on-demand table keyed by pk and sk, kept and recoverable in production', () => {
    production.resourceCountIs('AWS::DynamoDB::Table', 1);
    production.hasResource('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
      Properties: {
        KeySchema: [
          { AttributeName: 'pk', KeyType: 'HASH' },
          { AttributeName: 'sk', KeyType: 'RANGE' },
        ],
        BillingMode: 'PAY_PER_REQUEST',
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
        DeletionProtectionEnabled: true,
      },
    });
  });

  it('throws the table away with the stack in development', () => {
    development.resourceCountIs('AWS::DynamoDB::Table', 1);
    development.allResources('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Delete',
      Properties: {
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: false },
        DeletionProtectionEnabled: false,
      },
    });
  });

  it('keeps reports in a private, encrypted, versioned bucket, kept in production', () => {
    production.resourceCountIs('AWS::S3::Bucket', 1);
    production.hasResource('AWS::S3::Bucket', {
      DeletionPolicy: 'Retain',
      Properties: {
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            { ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } },
          ],
        },
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
        VersioningConfiguration: { Status: 'Enabled' },
        LifecycleConfiguration: {
          Rules: [{ Status: 'Enabled', NoncurrentVersionExpiration: { NoncurrentDays: 35 } }],
        },
      },
    });
    // Only over TLS.
    production.hasResourceProperties('AWS::S3::BucketPolicy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Deny',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          }),
        ]),
      },
    });
    development.hasResource('AWS::S3::Bucket', { DeletionPolicy: 'Delete' });
  });

  it('empties and deletes the reports bucket with the stack in development, never in production', () => {
    production.resourceCountIs('Custom::S3AutoDeleteObjects', 0);
    // The Checker, the web function, the poller and the demo proxy's copy.
    production.resourceCountIs('AWS::Lambda::Function', 4);
    const bucket = idOf(development, 'AWS::S3::Bucket', 'Reports');
    development.resourceCountIs('Custom::S3AutoDeleteObjects', 1);
    development.hasResource('Custom::S3AutoDeleteObjects', {
      DeletionPolicy: 'Delete',
      Properties: { BucketName: { Ref: bucket } },
    });
    // The function that empties it logs as JSON to its own log group, kept
    // for the tier's time, and its role may only write that log group and
    // empty the bucket.
    const emptier = idOf(development, 'AWS::Lambda::Function', 'CustomS3AutoDeleteObjects');
    const logs = idOf(development, 'AWS::Logs::LogGroup', 'ReportsAutoDeleteLogs');
    development.hasResourceProperties('AWS::Lambda::Function', {
      Description: Match.anyValue(),
      LoggingConfig: { LogFormat: 'JSON', LogGroup: { Ref: logs } },
    });
    development.hasResourceProperties('AWS::Logs::LogGroup', {
      RetentionInDays: Match.anyValue(),
    });
    const role = idOf(development, 'AWS::IAM::Role', 'CustomS3AutoDeleteObjects');
    expect(development.findResources('AWS::IAM::Role')[role]).not.toHaveProperty(
      'Properties.ManagedPolicyArns',
    );
    expect(actionsOf(development, role)).toEqual(['"logs:CreateLogStream"', '"logs:PutLogEvents"']);
    expect(JSON.stringify(development.findResources('AWS::Lambda::Function')[emptier])).toContain(
      'ReportsAutoDeleteLogsPolicy',
    );
  });

  it('runs the Checker as a durable function whose execution outlasts a week of waiting', () => {
    const checker = idOf(production, 'AWS::Lambda::Function', 'Checker');
    const table = idOf(production, 'AWS::DynamoDB::Table', 'Table');
    const bucket = idOf(production, 'AWS::S3::Bucket', 'Reports');
    const key = idOf(production, 'AWS::SecretsManager::Secret', 'RunTokenKey');
    expect(production.findResources('AWS::Lambda::Function')[checker]).toMatchObject({
      Properties: {
        Handler: 'bootstrap',
        Runtime: 'provided.al2023',
        Architectures: ['arm64'],
        MemorySize: 256,
        Timeout: 300,
        DurableConfig: { ExecutionTimeout: 8 * 24 * 60 * 60, RetentionPeriodInDays: 30 },
        Environment: {
          Variables: {
            DYNAMODB_TABLE_NAME: { Ref: table },
            REPORTS_BUCKET_NAME: { Ref: bucket },
            RUN_TOKEN_SECRET_ARN: { Ref: key },
            JUDGE_MODEL_ID: JUDGE_INFERENCE_PROFILE,
          },
        },
      },
    });
    // It reads its run token key, and only that secret.
    production.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          { Action: 'secretsmanager:GetSecretValue', Effect: 'Allow', Resource: { Ref: key } },
        ]),
      },
    });
    // Its reports and observations, and nothing else in the bucket.
    production.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          {
            Action: 's3:PutObject',
            Effect: 'Allow',
            Resource: REPORT_PREFIXES.map((prefix) => ({
              'Fn::Join': ['', [{ 'Fn::GetAtt': [bucket, 'Arn'] }, `/${prefix}*`]],
            })),
          },
        ]),
      },
    });
    const config = new Capture();
    development.hasResourceProperties('AWS::Lambda::Function', { DurableConfig: config });
    expect(config.asObject()['ExecutionTimeout']).toBeGreaterThanOrEqual(7 * 24 * 60 * 60);
  });

  it('runs the web function within API Gateway’s 30 seconds, not durable', () => {
    const web = idOf(production, 'AWS::Lambda::Function', 'Web');
    expect(production.findResources('AWS::Lambda::Function')[web]).toMatchObject({
      Properties: {
        Handler: 'bootstrap',
        Runtime: 'provided.al2023',
        Architectures: ['arm64'],
        MemorySize: 256,
        Timeout: 10,
      },
    });
    expect(
      production.findResources('AWS::Lambda::Function')[web]?.['Properties'],
    ).not.toHaveProperty('DurableConfig');
    production.resourceCountIs('AWS::Lambda::Function', 4);
  });

  it('builds each function from its own package into one bootstrap binary for arm64 Linux', () => {
    // The Go functions: CDK's own copy of the demo proxy runs its Python.
    const keys = Object.values(production.findResources('AWS::Lambda::Function'))
      .map((fn: unknown) => JSON.stringify(fn))
      .filter((fn) => fn.includes('"provided.al2023"'))
      .map((fn) => /"S3Key":"([0-9a-f]{64}\.zip)"/.exec(fn)?.[1] ?? '');
    // Three programs, so three different binaries.
    expect(new Set(keys).size).toBe(3);
    for (const key of keys) {
      const dir = path.join(outdir, `asset.${key.replace(/\.zip$/, '')}`);
      expect(readdirSync(dir)).toEqual(['bootstrap']);
      // An ELF executable for AArch64: e_machine 183 at offset 18.
      const binary = readFileSync(path.join(dir, 'bootstrap'));
      expect(binary.subarray(0, 4).toString('latin1')).toBe('\x7fELF');
      expect(binary.readUInt16LE(18)).toBe(183);
    }
  });

  it('traces with X-Ray in production only', () => {
    production.allResourcesProperties('AWS::Lambda::Function', {
      TracingConfig: { Mode: 'Active' },
    });
    development.allResourcesProperties('AWS::Lambda::Function', {
      TracingConfig: Match.absent(),
    });
  });

  it('lets the Checker only put, get and update items, put reports, checkpoint its own executions, run its sandboxes, put events and write its logs', () => {
    const role = idOf(development, 'AWS::IAM::Role', 'CheckerRole');
    expect(actionsOf(development, role)).toEqual(
      [
        '"dynamodb:ConditionCheckItem"',
        '"dynamodb:GetItem"',
        '"dynamodb:PutItem"',
        '"dynamodb:UpdateItem"',
        '"s3:PutObject"',
        '"secretsmanager:GetSecretValue"',
        '"bedrock:InvokeModel"',
        '"events:PutEvents"',
        ...DURABLE_EXECUTION_ACTIONS.map((action) => `"${action}"`),
        ...[...SANDBOX_ACTIONS, PASS_CONNECTOR_ACTION].map((action) => `"${action}"`),
        '"logs:CreateLogStream"',
        '"logs:PutLogEvents"',
      ].sort(),
    );
    // Its executions only: ARNs under its own.
    const checker = idOf(development, 'AWS::Lambda::Function', 'Checker');
    development.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: [
          {
            Action: [...DURABLE_EXECUTION_ACTIONS],
            Effect: 'Allow',
            Resource: { 'Fn::Join': ['', [{ 'Fn::GetAtt': [checker, 'Arn'] }, ':*']] },
          },
        ],
      },
    });
  });

  it('lets the Checker call the judge’s model only, through its inference profile', () => {
    const role = idOf(development, 'AWS::IAM::Role', 'CheckerRole');
    expect(actionsOf(development, role).filter((action) => action.includes('bedrock:'))).toEqual([
      '"bedrock:InvokeModel"',
    ]);
    development.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          {
            Action: 'bedrock:InvokeModel',
            Effect: 'Allow',
            Resource: [
              {
                'Fn::Join': [
                  '',
                  [
                    'arn:',
                    { Ref: 'AWS::Partition' },
                    ':bedrock:',
                    { Ref: 'AWS::Region' },
                    ':',
                    { Ref: 'AWS::AccountId' },
                    `:inference-profile/${JUDGE_INFERENCE_PROFILE}`,
                  ],
                ],
              },
              ...JUDGE_MODEL_REGIONS.map((region) => ({
                'Fn::Join': [
                  '',
                  [
                    'arn:',
                    { Ref: 'AWS::Partition' },
                    `:bedrock:${region}::foundation-model/${JUDGE_MODEL}`,
                  ],
                ],
              })),
            ],
          },
        ]),
      },
    });
  });

  it('lets the web function only read checks, steps, reports and the demo proxy, start the Checker, answer its callbacks, read the reviewer key and write its logs', () => {
    const webActions = [
      '"dynamodb:GetItem"',
      '"dynamodb:Query"',
      '"s3:GetObject"',
      '"s3:ListBucket"',
      '"lambda:InvokeFunction"',
      `"${CALLBACK_ACTION}"`,
      '"secretsmanager:GetSecretValue"',
      '"logs:CreateLogStream"',
      '"logs:PutLogEvents"',
    ];
    const role = idOf(development, 'AWS::IAM::Role', 'WebRole');
    expect(actionsOf(development, role)).toEqual([...webActions].sort());
    expect(actionsOf(production, idOf(production, 'AWS::IAM::Role', 'WebRole'))).toEqual(
      [...webActions, '"xray:PutTelemetryRecords"', '"xray:PutTraceSegments"'].sort(),
    );
    // Each on the one resource it needs: the reports, the Checker at
    // $LATEST, the Checker's own executions, the reviewer key.
    const checker = idOf(development, 'AWS::Lambda::Function', 'Checker');
    const bucket = idOf(development, 'AWS::S3::Bucket', 'Reports');
    const key = idOf(development, 'AWS::SecretsManager::Secret', 'ReviewerKey');
    development.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: [
          {
            Action: 's3:GetObject',
            Effect: 'Allow',
            Resource: [
              { 'Fn::Join': ['', [{ 'Fn::GetAtt': [bucket, 'Arn'] }, '/reports/*']] },
              { 'Fn::Join': ['', [{ 'Fn::GetAtt': [bucket, 'Arn'] }, '/goproxy/*']] },
            ],
          },
          {
            Action: 's3:ListBucket',
            Effect: 'Allow',
            Resource: { 'Fn::GetAtt': [bucket, 'Arn'] },
            Condition: { StringLike: { 's3:prefix': ['goproxy/*'] } },
          },
          {
            Action: 'lambda:InvokeFunction',
            Effect: 'Allow',
            Resource: { 'Fn::Join': ['', [{ 'Fn::GetAtt': [checker, 'Arn'] }, ':$LATEST']] },
          },
          {
            Action: CALLBACK_ACTION,
            Effect: 'Allow',
            Resource: { 'Fn::Join': ['', [{ 'Fn::GetAtt': [checker, 'Arn'] }, ':*']] },
          },
          { Action: 'secretsmanager:GetSecretValue', Effect: 'Allow', Resource: { Ref: key } },
        ],
      },
    });
    const web = idOf(development, 'AWS::Lambda::Function', 'Web');
    development.hasResourceProperties('AWS::Lambda::Function', {
      Environment: {
        Variables: {
          CHECKER_FUNCTION_ARN: {
            'Fn::Join': ['', [{ 'Fn::GetAtt': [checker, 'Arn'] }, ':$LATEST']],
          },
          REVIEWER_KEY_SECRET_ARN: { Ref: key },
          DYNAMODB_TABLE_NAME: Match.anyValue(),
          REPORTS_BUCKET_NAME: Match.anyValue(),
        },
      },
    });
    expect(development.findResources('AWS::Lambda::Function')[web]).toBeDefined();
  });

  it('gives no function role a managed policy, in either tier', () => {
    for (const template of [production, development]) {
      template.resourcePropertiesCountIs(
        'AWS::IAM::Role',
        {
          AssumeRolePolicyDocument: Match.objectLike({
            Statement: [Match.objectLike({ Principal: { Service: 'lambda.amazonaws.com' } })],
          }),
          ManagedPolicyArns: Match.anyValue(),
        },
        0,
      );
    }
  });

  it('routes the pages, the form, Approve and Block, the JSON API and the demo proxy to the web function, open to the public', () => {
    const web = idOf(production, 'AWS::Lambda::Function', 'Web');
    const routeKeys = WEB_ROUTES.map(([method, routePath]) => `${method} ${routePath}`);
    expect(routeKeys).toEqual([
      'GET /',
      'POST /checks',
      'GET /checks/{id}',
      'POST /checks/{id}/decision',
      'GET /static/{file}',
      'GET /api/{proxy+}',
      'POST /api/checks',
      'GET /goproxy/{proxy+}',
    ]);
    for (const routeKey of routeKeys) {
      production.hasResourceProperties('AWS::ApiGatewayV2::Route', {
        RouteKey: routeKey,
        AuthorizationType: 'NONE',
      });
    }
    production.resourceCountIs('AWS::ApiGatewayV2::Route', WEB_ROUTES.length);
    production.resourceCountIs('AWS::ApiGatewayV2::Integration', 1);
    production.hasResourceProperties('AWS::ApiGatewayV2::Integration', {
      IntegrationUri: { 'Fn::GetAtt': [web, 'Arn'] },
      PayloadFormatVersion: '2.0',
    });
  });

  it('logs every request as JSON and throttles the stage', () => {
    production.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
      StageName: '$default',
      AutoDeploy: true,
      // A JSON object per request, which Logs Insights queries by field.
      AccessLogSettings: {
        DestinationArn: Match.anyValue(),
        Format: Match.serializedJson(
          Match.objectLike({
            requestId: '$context.requestId',
            routeKey: '$context.routeKey',
            status: '$context.status',
            responseLatency: '$context.responseLatency',
            integrationError: '$context.integrationErrorMessage',
          }),
        ),
      },
      DefaultRouteSettings: { ThrottlingRateLimit: 50, ThrottlingBurstLimit: 100 },
    });
  });

  it('alarms on the API, every function and the table, in either tier', () => {
    // 5xx; errors, throttles and duration of each function (the fourth
    // copies the demo proxy's files, and development's fifth empties the bucket); the table's read and write throttles and
    // system errors; the re-check's dead letters, and its schedule group's
    // dropped and undelivered polls; a re-check that failed twice.
    production.resourceCountIs('AWS::CloudWatch::Alarm', 1 + 4 * 3 + 3 + 3 + 1);
    development.resourceCountIs('AWS::CloudWatch::Alarm', 1 + 5 * 3 + 3 + 3 + 1);
    for (const template of [production, development]) {
      template.resourceCountIs('AWS::CloudWatch::Dashboard', 1);
      // The p99 duration alarms fire at 8 of the web function's 10 seconds
      // and 240 of the Checker's 300.
      for (const threshold of [8000, 240000]) {
        template.hasResourceProperties('AWS::CloudWatch::Alarm', {
          Metrics: [
            Match.objectLike({
              MetricStat: Match.objectLike({
                Metric: Match.objectLike({ MetricName: 'Duration' }),
                Stat: 'p99',
              }),
            }),
          ],
          Threshold: threshold,
        });
      }
      template.hasOutput('AlarmTopicArn', { Value: { Ref: Match.anyValue() } });
      template.hasOutput('EntryPoint', {
        Value: { 'Fn::GetAtt': [Match.anyValue(), 'ApiEndpoint'] },
      });
    }
  });

  it('defaults the alert email to alerts.email', () => {
    synth('development', {}, { email: 'ops@example.com' }).hasParameter('AlertEmail', {
      Default: 'ops@example.com',
    });
  });

  it('backs up the table daily for retentionDays in production, and not at all in development', () => {
    production.hasResourceProperties('AWS::Backup::BackupPlan', {
      BackupPlan: {
        BackupPlanRule: [Match.objectLike({ Lifecycle: { DeleteAfterDays: 35 }, CopyActions: [] })],
      },
    });
    // The data table by ARN, never the Container's tag, which a development
    // stack in the same account carries too (#1267).
    const table = idOf(production, 'AWS::DynamoDB::Table', 'Table');
    production.resourceCountIs('AWS::Backup::BackupSelection', 1);
    production.hasResourceProperties('AWS::Backup::BackupSelection', {
      BackupSelection: Match.objectLike({
        Resources: [{ 'Fn::GetAtt': [table, 'Arn'] }],
        ListOfTags: Match.absent(),
        Conditions: Match.absent(),
      }),
    });
    development.resourceCountIs('AWS::Backup::BackupPlan', 0);
    development.resourceCountIs('AWS::Backup::BackupVault', 0);
  });

  it('keeps only point-in-time recovery when retentionDays is 0', () => {
    const template = synth('production', { retentionDays: 0 });
    template.resourceCountIs('AWS::Backup::BackupPlan', 0);
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
    });
  });

  it('keeps earlier report versions as long as the backups when they outlast 35 days', () => {
    synth('production', { retentionDays: 90 }).hasResourceProperties('AWS::S3::Bucket', {
      LifecycleConfiguration: {
        Rules: [{ Status: 'Enabled', NoncurrentVersionExpiration: { NoncurrentDays: 90 } }],
      },
    });
  });

  it('copies the backups to the vault in copyToRegion', () => {
    synth('production', { copyToRegion: 'eu-west-1' }).hasResourceProperties(
      'AWS::Backup::BackupPlan',
      {
        BackupPlan: {
          BackupPlanRule: [
            Match.objectLike({
              CopyActions: [
                {
                  DestinationBackupVaultArn: Match.objectLike({
                    'Fn::Join': ['', Match.arrayWith([':backup:eu-west-1:'])],
                  }),
                  Lifecycle: { DeleteAfterDays: 35 },
                },
              ],
            }),
          ],
        },
      },
    );
  });
});

describe('copyVaultName', () => {
  it('names the copy vault after the stack', () => {
    expect(copyVaultName('orders')).toBe('orders-copies');
  });

  it('keeps a long name within 50 characters, and two long names apart', () => {
    const long = `${'a'.repeat(40)}-one`;
    const other = `${'a'.repeat(40)}-two`;
    expect(copyVaultName(long)).toHaveLength(50);
    expect(copyVaultName(long)).not.toBe(copyVaultName(other));
  });
});
