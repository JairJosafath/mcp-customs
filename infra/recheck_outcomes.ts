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

/** What the outcomes of re-checks need: the Checker. */
export interface RecheckOutcomesProps {
  readonly checker: LambdaFunction;
}

/**
 * How a re-check that doesn't end in a pass is surfaced (docs/contracts.md,
 * "Re-checks of new versions"): the Checker announces a superseded approval
 * on the default event bus, and a metric filter on its logs counts each
 * retry that failed again, for an alarm.
 */
export class RecheckOutcomes extends Construct {
  private readonly filter: MetricFilter;

  constructor(scope: Construct, id: string, props: RecheckOutcomesProps) {
    super(scope, id);
    const { checker } = props;
    const bus = EventBus.fromEventBusName(this, 'Bus', EVENT_BUS);
    checker.addEnvironment(EVENT_BUS_NAME, bus.eventBusName);
    bus.grantPutEventsTo(checker);
    // A term, not a JSON selector: it matches the entry whether Lambda
    // keeps the function's JSON line as it is or wraps it.
    this.filter = new MetricFilter(this, 'FailedTwice', {
      logGroup: checker.logGroup,
      filterPattern: FilterPattern.allTerms(FAILED_TWICE_KEY),
      metricNamespace: FAILED_TWICE_METRIC.namespace,
      metricName: FAILED_TWICE_METRIC.name,
      metricValue: '1',
    });
  }

  /** An alarm, to `alarms`' topic, on the first re-check that failed twice. */
  addAlarms(alarms: Alarms): void {
    new Alarm(this, 'FailedTwiceAlarm', {
      alarmName: `${Stack.of(this).stackName}-RecheckFailedTwice-Critical`,
      metric: this.filter.metric({ period: Duration.minutes(5), statistic: 'Sum' }),
      threshold: 0,
      comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      datapointsToAlarm: 1,
      treatMissingData: TreatMissingData.NOT_BREACHING,
      alarmDescription:
        'A re-check of a newer version of an approved package failed, and its one retry failed too: the newer version is not checked.',
    }).addAlarmAction(new SnsAction(alarms.topic));
  }
}
