import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { beforeAll, describe, expect, it } from 'vitest';

import { ApiStack } from './api_stack';
import {
  EVENT_BUS,
  FAILED_TWICE_KEY,
  FAILED_TWICE_METRIC,
  LIFT_FAILED_KEY,
  LIFT_FAILED_METRIC,
} from './recheck_outcomes';
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

let template: Template;

beforeAll(() => {
  template = Template.fromStack(
    new ApiStack(new App(), 'test', { tier: 'production', operations: OPERATIONS }),
  );
});

describe('RecheckOutcomes', () => {
  it('names the default bus to the Checker and lets it put events on that bus alone', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: Match.objectLike({ EVENT_BUS_NAME: EVENT_BUS }) },
    });
    const role = idOf(template, 'AWS::IAM::Role', 'CheckerRole');
    const policies = JSON.stringify(
      Object.values(template.findResources('AWS::IAM::Policy')).filter((policy: unknown) =>
        JSON.stringify(policy).includes(`{"Ref":"${role}"}`),
      ),
    );
    // One grant of one action on one bus: a second bus, in its own
    // statement or the same one, or a wildcard fails.
    expect(policies.split('"events:').length - 1).toBe(1);
    expect(policies).toContain('"Action":"events:PutEvents"');
    expect(policies.split(':event-bus/').length - 1).toBe(1);
    expect(policies).toContain(`:event-bus/${EVENT_BUS}"]]}`);
  });

  it('lets the Checker check a condition only on APPROVED items', () => {
    const role = idOf(template, 'AWS::IAM::Role', 'CheckerRole');
    const table = idOf(template, 'AWS::DynamoDB::Table', 'Table');
    const policies = JSON.stringify(
      Object.values(template.findResources('AWS::IAM::Policy')).filter((policy: unknown) =>
        JSON.stringify(policy).includes(`{"Ref":"${role}"}`),
      ),
    );
    expect(policies.split('dynamodb:ConditionCheckItem').length - 1).toBe(1);
    expect(policies).toContain(
      JSON.stringify({
        Action: 'dynamodb:ConditionCheckItem',
        Condition: { 'ForAllValues:StringEquals': { 'dynamodb:LeadingKeys': ['APPROVED'] } },
        Effect: 'Allow',
        Resource: { 'Fn::GetAtt': [table, 'Arn'] },
      }),
    );
  });

  it.each([
    [
      'each re-check that failed twice',
      FAILED_TWICE_KEY,
      FAILED_TWICE_METRIC,
      'RecheckFailedTwice-Critical',
    ],
    [
      'each pass whose superseded mark was not lifted',
      LIFT_FAILED_KEY,
      LIFT_FAILED_METRIC,
      'LiftFailedAfterPass-Warning',
    ],
  ])('counts %s from the Checker’s logs, and alarms on the first', (_, key, metric, alarm) => {
    const logs = idOf(template, 'AWS::Logs::LogGroup', 'CheckerLogs');
    template.hasResourceProperties('AWS::Logs::MetricFilter', {
      LogGroupName: { Ref: logs },
      FilterPattern: `"${key}"`,
      MetricTransformations: [
        { MetricNamespace: metric.namespace, MetricName: metric.name, MetricValue: '1' },
      ],
    });
    template.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmName: Match.stringLikeRegexp(`-${alarm}$`),
      MetricName: metric.name,
      Namespace: metric.namespace,
      Statistic: 'Sum',
      Threshold: 0,
      ComparisonOperator: 'GreaterThanThreshold',
      AlarmActions: [{ Ref: Match.anyValue() }],
    });
  });
});
