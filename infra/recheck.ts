import { Duration, RemovalPolicy, Stack, Validations } from 'aws-cdk-lib';
import { Alarm, ComparisonOperator, TreatMissingData } from 'aws-cdk-lib/aws-cloudwatch';
import type { Metric } from 'aws-cdk-lib/aws-cloudwatch';
import { SnsAction } from 'aws-cdk-lib/aws-cloudwatch-actions';
import type { Table } from 'aws-cdk-lib/aws-dynamodb';
import { Policy, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import type { Function as LambdaFunction } from 'aws-cdk-lib/aws-lambda';
import { Schedule, ScheduleExpression, ScheduleGroup } from 'aws-cdk-lib/aws-scheduler';
import { LambdaInvoke } from 'aws-cdk-lib/aws-scheduler-targets';
import { Queue, QueueEncryption } from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';

import type { Alarms } from './alarms';
import { goFunction } from './go_function';
import { GO_PROXY_URL } from './sandbox';
import type { TierRules } from './standard';

/**
 * How often the poller asks each approved package's registry for a newer
 * version. A few minutes apart for the demo; a package's versions change
 * far less often, so a longer interval only delays a re-check.
 */
export const RECHECK_INTERVAL = Duration.minutes(5);

/** The poller's time limit: a registry request at a time, each 10 seconds at most. */
export const POLLER_TIMEOUT = Duration.minutes(1);

/** The environment variables that hand the poller what it works with. */
export const POLLER_ENVIRONMENT = {
  table: 'DYNAMODB_TABLE_NAME',
  checker: 'CHECKER_FUNCTION_ARN',
} as const;

/** The table calls the poller makes: it reads every APPROVED item and marks one polled. */
export const POLLER_TABLE_ACTIONS = ['dynamodb:Query', 'dynamodb:UpdateItem'] as const;

/** The one partition the poller touches: the approved packages (docs/contracts.md, "Store"). */
export const APPROVED_PARTITION = 'APPROVED';

/** What the re-check of new versions works with. */
export interface RecheckProps {
  /** The table of checks, verdicts and approved packages. */
  readonly table: Table;
  /** The Checker, which the poller starts a re-check on. */
  readonly checker: LambdaFunction;
  readonly rules: TierRules;
  /** The GOPROXY-style list the poller asks a Go module's latest version of. */
  readonly goProxy: string;
}

/** How long the dead-letter queue keeps a poll the Scheduler could not deliver. */
export const DEAD_LETTER_RETENTION = Duration.days(14);

/**
 * The re-check of new versions (docs/plan.md, "Security review"): an
 * EventBridge Scheduler schedule runs the poller every `RECHECK_INTERVAL`;
 * the poller asks each approved package's registry for its latest version
 * and starts a check of a new one on the Checker, linked to the approved
 * check. Package versions can't change, so a rug pull is a new version.
 */
export class Recheck extends Construct {
  /** The poller, for its alarms. */
  readonly poller: LambdaFunction;
  /** The schedule's own group, so its metrics are its alone. */
  private readonly group: ScheduleGroup;
  /** Where the Scheduler puts a poll it could not deliver. */
  private readonly deadLetters: Queue;

  constructor(scope: Construct, id: string, props: RecheckProps) {
    super(scope, id);
    const { table, checker, rules } = props;
    this.poller = goFunction(this, 'Poller', {
      pkg: './cmd/poller',
      timeout: POLLER_TIMEOUT,
      memorySize: 128,
      rules,
    });
    this.poller.addEnvironment(POLLER_ENVIRONMENT.table, table.tableName);
    this.poller.addEnvironment(POLLER_ENVIRONMENT.checker, `${checker.functionArn}:$LATEST`);
    this.poller.addEnvironment(GO_PROXY_URL, props.goProxy);
    // Only the APPROVED partition: a bug in the poller can't reach a check
    // or a verdict. dynamodb:LeadingKeys holds every Query and UpdateItem to
    // items whose partition key is APPROVED.
    this.poller.role?.attachInlinePolicy(
      new Policy(this, 'ReadApproved', {
        statements: [
          new PolicyStatement({
            actions: [...POLLER_TABLE_ACTIONS],
            resources: [table.tableArn],
            conditions: {
              'ForAllValues:StringEquals': { 'dynamodb:LeadingKeys': [APPROVED_PARTITION] },
            },
          }),
        ],
      }),
    );
    this.poller.role?.attachInlinePolicy(
      new Policy(this, 'StartChecks', {
        statements: [
          new PolicyStatement({
            actions: ['lambda:InvokeFunction'],
            resources: [`${checker.functionArn}:$LATEST`],
          }),
        ],
      }),
    );
    // A poll changes nothing twice and the next one comes soon: a failed
    // one is not retried, and its error is the poller's alarm.
    Validations.of(this.poller).acknowledge({
      id: 'Serverless-LambdaDLQ',
      reason:
        'The poller is invoked on a schedule with no event to keep: a failed poll would leave a dead-letter queue nothing to replay, and the next poll, minutes later, does the same work.',
    });

    // A poll holds no data: the next one does the same work.
    this.deadLetters = new Queue(this, 'DeadLetters', {
      encryption: QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: DEAD_LETTER_RETENTION,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    Validations.of(this.deadLetters).acknowledge({
      id: 'AwsSolutions-SQS3',
      reason:
        'The queue is the dead-letter queue of the re-check schedule: it holds the polls the Scheduler could not deliver, and a dead-letter queue needs none of its own.',
    });
    this.group = new ScheduleGroup(this, 'Group', { removalPolicy: RemovalPolicy.DESTROY });
    // The schedule invokes the poller at $LATEST, so its role may invoke
    // that one ARN, not every version and alias of the function. A poll
    // not delivered within an interval is overtaken by the next one.
    new Schedule(this, 'Schedule', {
      description: 'Polls the registries of approved packages for a new version to re-check.',
      scheduleGroup: this.group,
      schedule: ScheduleExpression.rate(RECHECK_INTERVAL),
      target: new LambdaInvoke(this.poller.latestVersion, {
        retryAttempts: 2,
        maxEventAge: RECHECK_INTERVAL,
        deadLetterQueue: this.deadLetters,
      }),
    });
  }

  /**
   * Alarms, to `alarms`' topic, on the first poll the Scheduler dropped or
   * could not put in the dead-letter queue, and on the first one in it.
   */
  addAlarms(alarms: Alarms): void {
    alarms.monitoring.monitorSqsQueue({
      queue: this.deadLetters,
      alarmFriendlyName: 'RecheckDeadLetters',
      addQueueMaxSizeAlarm: { Critical: { maxMessageCount: 0 } },
    });
    const action = new SnsAction(alarms.topic);
    const watched: [string, Metric][] = [
      ['Dropped', this.group.metricDropped({ period: Duration.minutes(5) })],
      [
        'NotDeadLettered',
        this.group.metricFailedToBeSentToDLQ(undefined, { period: Duration.minutes(5) }),
      ],
    ];
    for (const [name, metric] of watched) {
      new Alarm(this, `${name}Alarm`, {
        alarmName: `${Stack.of(this).stackName}-RecheckSchedule-${name}-Critical`,
        metric,
        threshold: 0,
        comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        treatMissingData: TreatMissingData.NOT_BREACHING,
        alarmDescription: `The re-check schedule: ${metric.metricName} above 0.`,
      }).addAlarmAction(action);
    }
  }
}
