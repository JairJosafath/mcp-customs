import { App } from 'aws-cdk-lib';
import { Capture, Match, Template } from 'aws-cdk-lib/assertions';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

import { ApiStack, DURABLE_EXECUTION_ACTIONS } from './api_stack';
import { copyVaultName } from './backups';
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
      return document.match(/"[a-z0-9]+:[A-Za-z]+"/g) ?? [];
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
    production.resourceCountIs('AWS::Lambda::Function', 2);
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
    expect(production.findResources('AWS::Lambda::Function')[checker]).toMatchObject({
      Properties: {
        Handler: 'bootstrap',
        Runtime: 'provided.al2023',
        Architectures: ['arm64'],
        MemorySize: 256,
        Timeout: 300,
        DurableConfig: { ExecutionTimeout: 8 * 24 * 60 * 60, RetentionPeriodInDays: 30 },
        Environment: { Variables: { DYNAMODB_TABLE_NAME: { Ref: table } } },
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
    production.resourceCountIs('AWS::Lambda::Function', 2);
  });

  it('builds each function from its own package into one bootstrap binary for arm64 Linux', () => {
    const key = new Capture();
    production.allResourcesProperties('AWS::Lambda::Function', { Code: { S3Key: key } });
    const keys = [key.asString()];
    while (key.next()) {
      keys.push(key.asString());
    }
    // Two programs, so two different binaries.
    expect(new Set(keys).size).toBe(2);
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

  it('lets the Checker only put and get items, checkpoint its own executions and write its logs', () => {
    const role = idOf(development, 'AWS::IAM::Role', 'CheckerRole');
    expect(actionsOf(development, role)).toEqual(
      [
        '"dynamodb:GetItem"',
        '"dynamodb:PutItem"',
        ...DURABLE_EXECUTION_ACTIONS.map((action) => `"${action}"`),
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

  it('lets the web function only write its logs', () => {
    const role = idOf(development, 'AWS::IAM::Role', 'WebRole');
    expect(actionsOf(development, role)).toEqual(['"logs:CreateLogStream"', '"logs:PutLogEvents"']);
    expect(actionsOf(production, idOf(production, 'AWS::IAM::Role', 'WebRole'))).toEqual(
      [
        '"logs:CreateLogStream"',
        '"logs:PutLogEvents"',
        '"xray:PutTelemetryRecords"',
        '"xray:PutTraceSegments"',
      ].sort(),
    );
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

  it('routes GET / and GET /api/* to the web function, open to the public', () => {
    const web = idOf(production, 'AWS::Lambda::Function', 'Web');
    for (const routeKey of ['GET /', 'GET /api/{proxy+}']) {
      production.hasResourceProperties('AWS::ApiGatewayV2::Route', {
        RouteKey: routeKey,
        AuthorizationType: 'NONE',
      });
    }
    production.resourceCountIs('AWS::ApiGatewayV2::Route', 2);
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
    // 5xx; errors, throttles and duration of each function (development's
    // third empties the bucket); the table's read and write throttles and
    // system errors.
    production.resourceCountIs('AWS::CloudWatch::Alarm', 1 + 2 * 3 + 3);
    development.resourceCountIs('AWS::CloudWatch::Alarm', 1 + 3 * 3 + 3);
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
