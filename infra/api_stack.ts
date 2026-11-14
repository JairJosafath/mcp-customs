import {
  AssetHashType,
  CfnOutput,
  DockerImage,
  Duration,
  RemovalPolicy,
  Stack,
  Validations,
} from 'aws-cdk-lib';
import type { StackProps } from 'aws-cdk-lib';
import { AccessLogFormat } from 'aws-cdk-lib/aws-apigateway';
import {
  HttpApi,
  HttpMethod,
  HttpNoneAuthorizer,
  LogGroupLogDestination,
} from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpIamAuthorizer } from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import { AttributeType, BillingMode, Table, TableEncryption } from 'aws-cdk-lib/aws-dynamodb';
import { Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import {
  Architecture,
  CfnFunction,
  Code,
  Function as LambdaFunction,
  LoggingFormat,
  Runtime,
  Tracing,
} from 'aws-cdk-lib/aws-lambda';
import type { DurableConfig } from 'aws-cdk-lib/aws-lambda';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import { BlockPublicAccess, Bucket, BucketEncryption } from 'aws-cdk-lib/aws-s3';
import type { Construct } from 'constructs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

import { Alarms } from './alarms';
import { Backups } from './backups';
import { Sandbox } from './sandbox';
import { TIER_RULES } from './standard';
import type { Operations, Tier, TierRules } from './standard';

// The functions' Go module: its own go.mod, apart from node_modules/, whose
// stray .go files would otherwise be part of it.
const SRC = path.join(import.meta.dirname, '..', 'src');

/** The environment variable that hands a function the table's name, as docs/contracts.md names it. */
export const DYNAMODB_TABLE_NAME = 'DYNAMODB_TABLE_NAME';

/** The web function's time limit: under API Gateway's 30 seconds. */
export const WEB_TIMEOUT = Duration.seconds(10);

/**
 * The Checker's time limit for one invocation. A durable execution spans many
 * invocations; each runs until the handler suspends or its work is checkpointed.
 */
export const CHECKER_TIMEOUT = Duration.minutes(5);

/**
 * The Checker's durable execution: up to 8 days, so a check waiting a week
 * for a person's Approve or Block still finishes, and its history kept 30
 * days after it ends.
 */
export const CHECKER_DURABLE_CONFIG: DurableConfig = {
  executionTimeout: Duration.days(8),
  retentionPeriod: Duration.days(30),
};

/** The Lambda API calls the durable execution SDK makes on the function's own executions. */
export const DURABLE_EXECUTION_ACTIONS = [
  'lambda:CheckpointDurableExecution',
  'lambda:GetDurableExecutionState',
] as const;

/**
 * The stage's access log: a JSON object per request with the request id,
 * the route, the status, the latencies and the integration's error, in
 * HTTP API context variables.
 */
export const ACCESS_LOG_FIELDS = {
  requestId: '$context.requestId',
  requestTime: '$context.requestTime',
  sourceIp: '$context.identity.sourceIp',
  caller: '$context.identity.caller',
  routeKey: '$context.routeKey',
  protocol: '$context.protocol',
  status: '$context.status',
  responseLength: '$context.responseLength',
  responseLatency: '$context.responseLatency',
  integrationLatency: '$context.integrationLatency',
  integrationStatus: '$context.integrationStatus',
  integrationError: '$context.integrationErrorMessage',
};

/**
 * A function's code: the Go package `pkg` of `src/` (`./cmd/checker`) built
 * by the installed Go for Lambda's arm64 Linux into one `bootstrap` binary,
 * the file the provided.al2023 runtime runs. Never Docker, which CI doesn't
 * have: a failed build fails synth.
 */
function goFunctionCode(pkg: string): Code {
  // The build's environment, in the bundling options too: CDK keys an
  // asset's staging on them, not on the local build, so without the package
  // every function would get the first one's binary.
  const environment = { GOOS: 'linux', GOARCH: 'arm64', CGO_ENABLED: '0', GO_PACKAGE: pkg };
  return Code.fromAsset(SRC, {
    // The hash of the binary, what the source builds to: -trimpath and
    // -buildvcs=false keep it the same from one build to the next.
    assetHashType: AssetHashType.OUTPUT,
    bundling: {
      // Required by the type, never pulled: local bundling always succeeds or throws.
      image: DockerImage.fromRegistry('public.ecr.aws/docker/library/golang'),
      environment,
      local: {
        tryBundle(outputDir: string): boolean {
          execFileSync(
            'go',
            [
              'build',
              '-trimpath',
              '-buildvcs=false',
              '-tags',
              'lambda.norpc',
              '-ldflags',
              '-s -w',
              '-o',
              path.join(outputDir, 'bootstrap'),
              pkg,
            ],
            {
              cwd: SRC,
              env: { ...process.env, ...environment },
              stdio: ['ignore', 'inherit', 'inherit'],
            },
          );
          return true;
        },
      },
    },
  });
}

/** What makes one of the stack's Go functions. */
interface GoFunctionProps {
  /** The Go package it runs, relative to `src/`. */
  readonly pkg: string;
  readonly timeout: Duration;
  readonly memorySize: number;
  readonly rules: TierRules;
  readonly durableConfig?: DurableConfig;
}

/**
 * A Go function on arm64 and Amazon Linux 2023, with its own log group and
 * its own role, allowed only to write that log group: the default role would
 * carry an AWS managed policy (AWSLambdaBasicExecutionRole, or
 * AWSLambdaBasicDurableExecutionRolePolicy for a durable function), which may
 * write to every log group in the account.
 */
function goFunction(scope: Construct, id: string, props: GoFunctionProps): LambdaFunction {
  const logGroup = new LogGroup(scope, `${id}Logs`, {
    retention: props.rules.logRetention,
    removalPolicy: RemovalPolicy.DESTROY,
  });
  const role = new Role(scope, `${id}Role`, {
    assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
  });
  logGroup.grantWrite(role);
  return new LambdaFunction(scope, id, {
    role,
    code: goFunctionCode(props.pkg),
    handler: 'bootstrap',
    runtime: Runtime.PROVIDED_AL2023,
    architecture: Architecture.ARM_64,
    memorySize: props.memorySize,
    timeout: props.timeout,
    logGroup,
    loggingFormat: LoggingFormat.JSON,
    // Lambda traces each call itself; the functions add no subsegments.
    tracing: props.rules.tracing ? Tracing.ACTIVE : Tracing.DISABLED,
    ...(props.durableConfig === undefined ? {} : { durableConfig: props.durableConfig }),
  });
}

/**
 * The days a bucket keeps the earlier versions of an object: as long as a
 * table recovers (point-in-time recovery's 35 days) or the backups last.
 */
export function noncurrentVersionDays(operations: Operations): number {
  return Math.max(35, operations.backups.retentionDays);
}

/** What the stack is built for. */
export interface ApiStackProps extends StackProps {
  /** Where it runs, which decides what it keeps, backs up and traces. */
  readonly tier: Tier;
  /** What the Container promises whatever the tier: `OPERATIONS`. */
  readonly operations: Operations;
}

/**
 * MCP Customs' one stack: the Checker, a Lambda durable function; the web
 * function behind an HTTP API whose pages and `/api/` routes are public; one
 * DynamoDB table of checks, steps and verdicts (docs/contracts.md, "Store");
 * and a bucket for reports. Every part has alarms, to a topic the stack
 * outputs with its URL; production keeps and backs up the data.
 */
export class ApiStack extends Stack {
  /** The API's URL, `https://<id>.execute-api.<region>.amazonaws.com/`. */
  readonly url: string;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);
    const rules = TIER_RULES[props.tier];
    const { backups, alerts } = props.operations;

    // The table holds data: kept, protected and recoverable where the tier
    // keeps data, thrown away with the stack where it doesn't.
    const table = new Table(this, 'Table', {
      partitionKey: { name: 'pk', type: AttributeType.STRING },
      sortKey: { name: 'sk', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: rules.pointInTimeRecovery,
      },
      deletionProtection: rules.keepData,
      removalPolicy: rules.keepData ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
    });

    // Reports and raw observations, `reports/<check-id>.json`: data, kept
    // with its earlier versions where the tier keeps data.
    const reports = new Bucket(this, 'Reports', {
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      lifecycleRules: [
        { noncurrentVersionExpiration: Duration.days(noncurrentVersionDays(props.operations)) },
      ],
      removalPolicy: rules.keepData ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
    });
    Validations.of(reports).acknowledge({
      id: 'AwsSolutions-S1',
      reason:
        'Only the stack’s own functions read and write the reports bucket, and their logs name each check they work on; server access logs would need a second bucket, itself unlogged, for no reader.',
    });

    const checker = goFunction(this, 'Checker', {
      pkg: './cmd/checker',
      timeout: CHECKER_TIMEOUT,
      memorySize: 256,
      rules,
      durableConfig: CHECKER_DURABLE_CONFIG,
    });
    checker.addEnvironment(DYNAMODB_TABLE_NAME, table.tableName);
    // Only the calls the Checker makes: it records a check and its steps.
    table.grant(checker, 'dynamodb:PutItem');
    this.grantDurableExecution(checker);
    // One MicroVM per check, from the harness image.
    new Sandbox(this, 'Sandbox', { logRetention: rules.logRetention }).grantLaunch(checker);
    // Nothing invokes the Checker yet: the web function starts checks in a
    // later issue, and a durable execution keeps its own failures.
    Validations.of(checker).acknowledge({
      id: 'Serverless-LambdaDLQ',
      reason:
        'The Checker is a durable function: Lambda records each execution’s failure, with its error, in the execution (GetDurableExecution), so a dead-letter queue would hold a second copy of what the execution already keeps.',
    });

    const web = goFunction(this, 'Web', {
      pkg: './cmd/web',
      timeout: WEB_TIMEOUT,
      memorySize: 256,
      rules,
    });

    const api = this.httpApi(web, rules);
    this.url = api.apiEndpoint;

    this.addAlarms(alerts.email, api, [
      ['Checker', checker, CHECKER_TIMEOUT],
      ['Web', web, WEB_TIMEOUT],
    ]).monitorDynamoTable({
      table: Table.fromTableName(this, 'MonitoredTable', table.tableName),
      alarmFriendlyName: 'Table',
      billingMode: BillingMode.PAY_PER_REQUEST,
      addSystemErrorCountAlarm: { Critical: { maxErrorCount: 0 } },
      addReadThrottledEventsCountAlarm: { Critical: { maxThrottledEventsThreshold: 0 } },
      addWriteThrottledEventsCountAlarm: { Critical: { maxThrottledEventsThreshold: 0 } },
    });

    if (rules.backups && backups.retentionDays > 0) {
      new Backups(this, 'Backups', {
        retentionDays: backups.retentionDays,
        copyToRegion: backups.copyToRegion,
        tables: [table],
      });
    }

    new CfnOutput(this, 'EntryPoint', {
      value: this.url,
      description: 'The URL of the HTTP API.',
    });
  }

  /**
   * Lets `fn` checkpoint and read its own durable executions, whose ARNs
   * start with its own, qualified: `<function ARN>:<version>/durable-execution/...`.
   * A policy apart from the role's default one: the function depends on that
   * one, and this one names the function.
   */
  private grantDurableExecution(fn: LambdaFunction): void {
    const policy = new Policy(this, `${fn.node.id}DurableExecution`, {
      statements: [
        new PolicyStatement({
          actions: [...DURABLE_EXECUTION_ACTIONS],
          resources: [`${fn.functionArn}:*`],
        }),
      ],
    });
    fn.role?.attachInlinePolicy(policy);
    const cfnFunction = fn.node.defaultChild;
    if (!(cfnFunction instanceof CfnFunction)) {
      throw new Error(`${fn.node.path} has no CfnFunction to name in its acknowledgement.`);
    }
    Validations.of(policy).acknowledge({
      id: `AwsSolutions-IAM5[Resource::<${this.getLogicalId(cfnFunction)}.Arn>:*]`,
      reason:
        'A durable execution’s ARN is the function’s qualified ARN followed by its own path, unknown until it starts; the wildcard reaches only this function’s own executions.',
    });
  }

  /**
   * The HTTP API: `GET /` and `GET /api/{proxy+}` call `web`, open to the
   * public. Any other route is signed with IAM (SigV4), the scaffold's
   * default, and the stage logs and throttles every request.
   */
  private httpApi(web: LambdaFunction, rules: TierRules): HttpApi {
    const accessLogs = new LogGroup(this, 'ApiAccessLogs', {
      retention: rules.logRetention,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const api = new HttpApi(this, 'Api', {
      defaultAuthorizer: new HttpIamAuthorizer(),
      createDefaultStage: false,
    });
    api.addStage('DefaultStage', {
      stageName: '$default',
      autoDeploy: true,
      throttle: { rateLimit: 50, burstLimit: 100 },
      // One JSON object per request, so Logs Insights queries it by field.
      accessLogSettings: {
        destination: new LogGroupLogDestination(accessLogs),
        format: AccessLogFormat.custom(JSON.stringify(ACCESS_LOG_FIELDS)),
      },
    });
    const integration = new HttpLambdaIntegration('Web', web);
    for (const routePath of ['/', '/api/{proxy+}']) {
      for (const route of api.addRoutes({
        path: routePath,
        methods: [HttpMethod.GET],
        integration,
        authorizer: new HttpNoneAuthorizer(),
      })) {
        Validations.of(route).acknowledge({
          id: 'AwsSolutions-APIG4',
          reason:
            'MCP Customs is a public service: anyone may read its pages and its JSON API, as the demo and the judges do, without an AWS identity. The stage is throttled; routes that change state come later, with their own authorization.',
        });
      }
    }
    return api;
  }

  /**
   * The stack's alarms, each firing on the first bad five minutes: a server
   * error, a failed or throttled call, or calls near their time limit.
   * docs/runbook.md says what each means and what to do first. tsconfig's
   * exactOptionalPropertyTypes keeps a HttpApi or Table from passing as the
   * IHttpApi or ITable the monitoring takes, so it gets a reference by id or
   * name.
   */
  private addAlarms(
    email: string,
    api: HttpApi,
    functions: readonly (readonly [string, LambdaFunction, Duration])[],
  ): Alarms['monitoring'] {
    const alarms = new Alarms(this, 'Alarms', email);
    alarms.monitoring.monitorApiGatewayV2HttpApi({
      api: HttpApi.fromHttpApiAttributes(this, 'MonitoredApi', { httpApiId: api.apiId }),
      alarmFriendlyName: 'Api',
      add5xxCountAlarm: { Critical: { maxErrorCount: 0 } },
    });
    for (const [name, fn, timeout] of functions) {
      alarms.monitoring.monitorLambdaFunction({
        lambdaFunction: fn,
        alarmFriendlyName: name,
        addFaultCountAlarm: { Critical: { maxErrorCount: 0 } },
        addThrottlesCountAlarm: { Critical: { maxErrorCount: 0 } },
        addLatencyP99Alarm: {
          Warning: { maxLatency: Duration.millis(timeout.toMilliseconds() * 0.8) },
        },
      });
    }
    return alarms.monitoring;
  }
}
