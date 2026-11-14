import { Duration, Stack } from 'aws-cdk-lib';
import { Alarm, ComparisonOperator, TreatMissingData } from 'aws-cdk-lib/aws-cloudwatch';
import { SnsAction } from 'aws-cdk-lib/aws-cloudwatch-actions';
import { EventBus } from 'aws-cdk-lib/aws-events';
import type { Function as LambdaFunction } from 'aws-cdk-lib/aws-lambda';
import { FilterPattern, MetricFilter } from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

import type { Alarms } from './alarms';

/** The environment variable that names the event bus the Checker announces a superseded approval on. */
export const EVENT_BUS_NAME = 'EVENT_BUS_NAME';

/** The bus the events go to: the account's default one, which a user's rule subscribes to. */
export const EVENT_BUS = 'default';

/**
 * The attribute of the Checker's log entry that a re-check's retry failed
 * (`FailedTwiceKey` in `src/internal/checker`): the metric filter counts it.
 */
export const FAILED_TWICE_KEY = 'recheckFailedTwice';

/** The metric the filter puts. */
export const FAILED_TWICE_METRIC = { namespace: 'MCPCustoms', name: 'RecheckFailedTwice' } as const;

/**
 * The attribute of the Checker's log entry that a re-check passed but its
 * approved check's superseded mark, or the event saying so, could not be
 * lifted (`LiftFailedKey` in `src/internal/checker`): the metric filter
 * counts it.
 */
export const LIFT_FAILED_KEY = 'liftFailedAfterPass';

/** The metric that filter puts. */
export const LIFT_FAILED_METRIC = { namespace: 'MCPCustoms', name: 'LiftFailedAfterPass' } as const;

/** What the outcomes of re-checks need: the Checker. */
export interface RecheckOutcomesProps {
  readonly checker: LambdaFunction;
}

/** A log entry the Checker writes, counted for an alarm. */
interface Counted {
  readonly filter: MetricFilter;
  readonly alarmName: string;
  readonly description: string;
}

/**
 * How a re-check that doesn't end in a pass is surfaced (docs/contracts.md,
 * "Re-checks of new versions"): the Checker announces a superseded approval
 * on the default event bus, and metric filters on its logs count each
 * retry that failed again, and each pass whose superseded mark could not
 * be lifted, for an alarm.
 */
export class RecheckOutcomes extends Construct {
  private readonly counted: readonly Counted[];

  constructor(scope: Construct, id: string, props: RecheckOutcomesProps) {
    super(scope, id);
    const { checker } = props;
    const bus = EventBus.fromEventBusName(this, 'Bus', EVENT_BUS);
    checker.addEnvironment(EVENT_BUS_NAME, bus.eventBusName);
    bus.grantPutEventsTo(checker);
    // A term, not a JSON selector: it matches the entry whether Lambda
    // keeps the function's JSON line as it is or wraps it.
    const count = (
      id: string,
      key: string,
      metric: { namespace: string; name: string },
    ): MetricFilter =>
      new MetricFilter(this, id, {
        logGroup: checker.logGroup,
        filterPattern: FilterPattern.allTerms(key),
        metricNamespace: metric.namespace,
        metricName: metric.name,
        metricValue: '1',
      });
    this.counted = [
      {
        filter: count('FailedTwice', FAILED_TWICE_KEY, FAILED_TWICE_METRIC),
        alarmName: 'RecheckFailedTwice-Critical',
        description:
          'A re-check of a newer version of an approved package failed, and its one retry failed too: the newer version is not checked.',
      },
      {
        filter: count('LiftFailed', LIFT_FAILED_KEY, LIFT_FAILED_METRIC),
        alarmName: 'LiftFailedAfterPass-Warning',
        description:
          'A re-check of a newer version passed, but its approved check still reads superseded, or the event saying it no longer is was not sent: see docs/contracts.md, Re-checks of new versions.',
      },
    ];
  }

  /** An alarm, to `alarms`' topic, on the first entry of each counted log line. */
  addAlarms(alarms: Alarms): void {
    for (const { filter, alarmName, description } of this.counted) {
      new Alarm(this, `${filter.node.id}Alarm`, {
        alarmName: `${Stack.of(this).stackName}-${alarmName}`,
        metric: filter.metric({ period: Duration.minutes(5), statistic: 'Sum' }),
        threshold: 0,
        comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        datapointsToAlarm: 1,
        treatMissingData: TreatMissingData.NOT_BREACHING,
        alarmDescription: description,
      }).addAlarmAction(new SnsAction(alarms.topic));
    }
  }
}
