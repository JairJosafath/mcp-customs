import { App } from 'aws-cdk-lib';
import { Capture, Match, Template } from 'aws-cdk-lib/assertions';
import { beforeAll, describe, expect, it } from 'vitest';

import { ApiStack } from './api_stack';
import { DEAD_LETTER_RETENTION, POLLER_TIMEOUT, RECHECK_INTERVAL } from './recheck';
import type { Operations } from './standard';

const OPERATIONS: Operations = {
  backups: { retentionDays: 35, copyToRegion: '' },
  recovery: { rpo: '1h', rto: '4h' },
  alerts: { email: '' },
};

/** The logical ID of the one resource of `type` whose ID starts with `prefix`. */
function idOf(template: Template, type: string, prefix: string): string {
  const ids = Object.keys(template.findResources(type)).filter((id) => id.startsWith(prefix));
  expect(ids, `${type} ${prefix}`).toHaveLength(1);
  return ids[0] ?? '';
}

/** The policy statements attached to the role `roleId`, as JSON. */
function statementsOf(template: Template, roleId: string): string {
  return JSON.stringify(
    Object.values(template.findResources('AWS::IAM::Policy')).filter((policy: unknown) =>
      JSON.stringify(policy).includes(`{"Ref":"${roleId}"}`),
    ),
  );
}

let template: Template;

beforeAll(() => {
  template = Template.fromStack(
    new ApiStack(new App(), 'test', { tier: 'production', operations: OPERATIONS }),
  );
});

describe('Recheck', () => {
  it('runs the poller on a schedule, a few minutes apart, at $LATEST, in its own group', () => {
    const poller = idOf(template, 'AWS::Lambda::Function', 'RecheckPoller');
    idOf(template, 'AWS::Scheduler::ScheduleGroup', 'RecheckGroup');
    const group = new Capture();
    template.hasResourceProperties('AWS::Scheduler::ScheduleGroup', { Name: group });
    const queue = idOf(template, 'AWS::SQS::Queue', 'RecheckDeadLetters');
    template.hasResourceProperties('AWS::Scheduler::Schedule', {
      ScheduleExpression: `rate(${String(RECHECK_INTERVAL.toMinutes())} minutes)`,
      GroupName: group.asString(),
      State: 'ENABLED',
      Target: {
        Arn: { 'Fn::Join': ['', [{ 'Fn::GetAtt': [poller, 'Arn'] }, ':$LATEST']] },
        RetryPolicy: {
          MaximumRetryAttempts: 2,
          MaximumEventAgeInSeconds: RECHECK_INTERVAL.toSeconds(),
        },
        DeadLetterConfig: { Arn: { 'Fn::GetAtt': [queue, 'Arn'] } },
      },
    });
    expect(RECHECK_INTERVAL.toMinutes()).toBeLessThanOrEqual(10);
  });

  it('lets the schedule invoke only the poller at $LATEST', () => {
    const role = idOf(template, 'AWS::IAM::Role', 'SchedulerRoleForTarget');
    const poller = idOf(template, 'AWS::Lambda::Function', 'RecheckPoller');
    const statements = statementsOf(template, role);
    expect(statements).toContain('"Action":"lambda:InvokeFunction"');
    expect(statements).toContain(
      JSON.stringify({ 'Fn::Join': ['', [{ 'Fn::GetAtt': [poller, 'Arn'] }, ':$LATEST']] }),
    );
    expect(statements).not.toContain(':*');
  });

  it('gives the poller its time limit, the table and the Checker at $LATEST to start re-checks on', () => {
    const poller = idOf(template, 'AWS::Lambda::Function', 'RecheckPoller');
    const table = idOf(template, 'AWS::DynamoDB::Table', 'Table');
    const checker = idOf(template, 'AWS::Lambda::Function', 'Checker');
    const checkerLatest = { 'Fn::Join': ['', [{ 'Fn::GetAtt': [checker, 'Arn'] }, ':$LATEST']] };
    template.hasResourceProperties('AWS::Lambda::Function', {
      Handler: 'bootstrap',
      Runtime: 'provided.al2023',
      Architectures: ['arm64'],
      Timeout: POLLER_TIMEOUT.toSeconds(),
      Environment: {
        Variables: { DYNAMODB_TABLE_NAME: { Ref: table }, CHECKER_FUNCTION_ARN: checkerLatest },
      },
    });
    const role = idOf(template, 'AWS::IAM::Role', 'RecheckPollerRole');
    const statements = statementsOf(template, role);
    expect(statements).toContain(
      JSON.stringify({
        Action: ['dynamodb:Query', 'dynamodb:UpdateItem'],
        Effect: 'Allow',
        Resource: [{ 'Fn::GetAtt': [table, 'Arn'] }],
      }),
    );
    expect(statements).toContain(
      JSON.stringify({ Action: 'lambda:InvokeFunction', Effect: 'Allow', Resource: checkerLatest }),
    );
    expect(statements).not.toContain('dynamodb:PutItem');
    expect(poller).not.toBe('');
  });

  it('keeps an undelivered poll encrypted for a set time, and alarms on it and on dropped polls', () => {
    template.hasResource('AWS::SQS::Queue', {
      DeletionPolicy: 'Delete',
      Properties: {
        SqsManagedSseEnabled: true,
        MessageRetentionPeriod: DEAD_LETTER_RETENTION.toSeconds(),
      },
    });
    for (const metric of ['InvocationDroppedCount', 'InvocationsFailedToBeSentToDeadLetterCount']) {
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        MetricName: metric,
        Namespace: 'AWS/Scheduler',
        Threshold: 0,
        ComparisonOperator: 'GreaterThanThreshold',
        AlarmActions: [{ Ref: Match.anyValue() }],
      });
    }
  });
});
