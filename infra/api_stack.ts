import { CfnOutput, CfnResource, Duration, RemovalPolicy, Stack, Validations } from 'aws-cdk-lib';
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
import { Policy, PolicyStatement, Role } from 'aws-cdk-lib/aws-iam';
import { CfnFunction, Function as LambdaFunction } from 'aws-cdk-lib/aws-lambda';
import type { DurableConfig, IFunction } from 'aws-cdk-lib/aws-lambda';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import { BlockPublicAccess, Bucket, BucketEncryption, CfnBucket } from 'aws-cdk-lib/aws-s3';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import type { Construct } from 'constructs';

import { Alarms } from './alarms';
import { Backups } from './backups';
import { DEMO_VERSIONS_FILE, DemoProxy, GO_PROXY_PREFIX } from './demo_proxy';
import { goFunction } from './go_function';
import { Recheck, POLLER_TIMEOUT } from './recheck';
import { Sandbox } from './sandbox';
import { TIER_RULES } from './standard';
import type { Operations, Tier, TierRules } from './standard';

/** The environment variable that hands a function the table's name, as docs/contracts.md names it. */
export const DYNAMODB_TABLE_NAME = 'DYNAMODB_TABLE_NAME';

/** The environment variable that hands the Checker the reports bucket's name. */
export const REPORTS_BUCKET_NAME = 'REPORTS_BUCKET_NAME';

/** The environment variable that hands the Checker the ARN of the key its run tokens are derived from. */
export const RUN_TOKEN_SECRET_ARN = 'RUN_TOKEN_SECRET_ARN';

/** The environment variable that hands the web function the Checker's qualified ARN, to start checks. */
export const CHECKER_FUNCTION_ARN = 'CHECKER_FUNCTION_ARN';

/** The environment variable that hands the web function the ARN of the reviewer key. */
export const REVIEWER_KEY_SECRET_ARN = 'REVIEWER_KEY_SECRET_ARN';

/** The Lambda API call the web function makes to answer a check waiting for a person. */
export const CALLBACK_ACTION = 'lambda:SendDurableExecutionCallbackSuccess';

/**
 * The web function's routes, open to the public. Approve and Block (`POST
 * /checks/{id}/decision`) take the reviewer key, which the function checks.
 */
export const WEB_ROUTES = [
  ['GET', '/'],
  ['POST', '/checks'],
  ['GET', '/checks/{id}'],
  ['POST', '/checks/{id}/decision'],
  ['GET', '/static/{file}'],
  ['GET', '/api/{proxy+}'],
  ['POST', '/api/checks'],
  ['GET', '/goproxy/{proxy+}'],
] as const;

/** The time limit CDK sets on the function that copies the demo proxy's files. */
export const DEMO_PROXY_TIMEOUT = Duration.minutes(15);

/** The public Go module proxy, asked after the demo proxy answers 404. */
export const PUBLIC_GO_PROXY = 'https://proxy.golang.org';

/** The environment variable that names the judge's model to the Checker. */
export const JUDGE_MODEL_ID = 'JUDGE_MODEL_ID';

/** The judge's model on Amazon Bedrock. */
export const JUDGE_MODEL = 'anthropic.claude-opus-5-5';

/** The cross-region inference profile the Checker calls the judge's model through. */
export const JUDGE_INFERENCE_PROFILE = `us.${JUDGE_MODEL}`;

/** The regions that profile routes a call to, each of which must allow the model. */
export const JUDGE_MODEL_REGIONS = ['us-east-1', 'us-east-2', 'us-west-2'] as const;

/** The prefixes the Checker writes under, as docs/contracts.md names them. */
export const REPORT_PREFIXES = ['reports/', 'observations/'] as const;

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
 * The days a bucket keeps the earlier versions of an object: as long as a
 * table recovers (point-in-time recovery's 35 days) or the backups last.
 */
export function noncurrentVersionDays(operations: Operations): number {
  return Math.max(35, operations.backups.retentionDays);
}

/** The construct id CDK gives, once per stack, the provider that empties buckets with `autoDeleteObjects`. */
export const AUTO_DELETE_PROVIDER_ID = 'Custom::S3AutoDeleteObjectsCustomResourceProvider';

/** The time limit CDK sets on that provider's function: CloudFormation's own wait for a custom resource. */
export const AUTO_DELETE_TIMEOUT = Duration.minutes(15);

/** What the stack is built for. */
export interface ApiStackProps extends StackProps {
  /** Where it runs, which decides what it keeps, backs up and traces. */
  readonly tier: Tier;
  /** What the Container promises whatever the tier: `OPERATIONS`. */
  readonly operations: Operations;
  /** The file of the demo versions the demo Go module proxy serves; `DEMO_VERSIONS_FILE` when unset. */
  readonly demoVersionsFile?: string;
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
    // with its earlier versions where the tier keeps data, emptied and
    // deleted with the stack where it doesn't.
    const reports = new Bucket(this, 'Reports', {
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      lifecycleRules: [
        { noncurrentVersionExpiration: Duration.days(noncurrentVersionDays(props.operations)) },
      ],
      removalPolicy: rules.keepData ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      // Where the tier keeps no data, the stack empties the bucket, every
      // version, before deleting it: CloudFormation can't delete a bucket
      // that holds objects.
      autoDeleteObjects: !rules.keepData,
    });
    Validations.of(reports).acknowledge({
      id: 'AwsSolutions-S1',
      reason:
        'Only the stack’s own functions read and write the reports bucket, and their logs name each check they work on; server access logs would need a second bucket, itself unlogged, for no reader.',
    });

    const emptier = rules.keepData ? undefined : this.conformAutoDeleteProvider(rules);

    const checker = goFunction(this, 'Checker', {
      pkg: './cmd/checker',
      timeout: CHECKER_TIMEOUT,
      memorySize: 256,
      rules,
      durableConfig: CHECKER_DURABLE_CONFIG,
    });
    checker.addEnvironment(DYNAMODB_TABLE_NAME, table.tableName);
    checker.addEnvironment(REPORTS_BUCKET_NAME, reports.bucketName);
    // Only the calls the Checker makes: it records a check and its steps,
    // reads a check it finds already made when a step is retried and an
    // earlier verdict, writes a verdict and a package's approval, and
    // updates the check's status.
    table.grant(checker, 'dynamodb:PutItem', 'dynamodb:GetItem', 'dynamodb:UpdateItem');
    this.grantReportWrites(checker, reports);
    this.grantRunTokenKey(checker, rules);
    this.grantDurableExecution(checker);
    this.grantJudge(checker);
    // The web function starts checks asynchronously, and a durable
    // execution keeps its own failures.
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
    this.grantWeb(web, { table, reports, checker });

    const api = this.httpApi(web, rules);
    this.url = api.apiEndpoint;
    // The demo servers' versions, served by the stack itself, then every
    // other Go module from the public proxy (docs/contracts.md, "The demo proxy").
    const goProxy = `${api.apiEndpoint}/goproxy,${PUBLIC_GO_PROXY}`;

    // One MicroVM per check, from the harness image.
    new Sandbox(this, 'Sandbox', { logRetention: rules.logRetention, goProxy }).grantLaunch(
      checker,
    );

    const recheck = new Recheck(this, 'Recheck', { table, checker, rules, goProxy });
    const demoProxy = new DemoProxy(this, 'DemoProxy', {
      bucket: reports,
      versionsFile: props.demoVersionsFile ?? DEMO_VERSIONS_FILE,
      rules,
    });

    const alarms = this.addAlarms(alerts.email, api, [
      ['Checker', checker, CHECKER_TIMEOUT],
      ['Web', web, WEB_TIMEOUT],
      ['Poller', recheck.poller, POLLER_TIMEOUT],
      ['DemoProxyDeployment', demoProxy.handler, DEMO_PROXY_TIMEOUT],
      ...(emptier === undefined
        ? []
        : [['ReportsAutoDelete', emptier, AUTO_DELETE_TIMEOUT] as const]),
    ]);
    recheck.addAlarms(alarms);
    alarms.monitoring.monitorDynamoTable({
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
   * Holds the function CDK adds to empty the reports bucket on delete to
   * what every function of the stack keeps: logs to its own log group, kept
   * for the tier's time, and a role allowed only that log group and the
   * bucket, without the AWS managed policy CDK gives it, which may write to
   * every log group in the account. Answers the function, for its alarms.
   */
  private conformAutoDeleteProvider(rules: TierRules): IFunction {
    const provider = this.node.findChild(AUTO_DELETE_PROVIDER_ID);
    const handler = provider.node.findChild('Handler');
    const role = provider.node.findChild('Role');
    if (!(handler instanceof CfnResource) || !(role instanceof CfnResource)) {
      throw new Error(`${provider.node.path} has no Handler and Role to hold to the Standard.`);
    }
    const logGroup = new LogGroup(this, 'ReportsAutoDeleteLogs', {
      retention: rules.logRetention,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    handler.addPropertyOverride('LoggingConfig', {
      LogFormat: 'JSON',
      LogGroup: logGroup.logGroupName,
    });
    role.addPropertyDeletionOverride('ManagedPolicyArns');
    const logs = new Policy(this, 'ReportsAutoDeleteLogsPolicy', {
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [logGroup.logGroupArn],
        }),
      ],
    });
    logs.attachToRole(Role.fromRoleName(this, 'ReportsAutoDeleteRole', role.ref));
    // The function logs from its first call, when the stack is deleted.
    const logsPolicy = logs.node.defaultChild;
    if (!(logsPolicy instanceof CfnResource)) {
      throw new Error(`${logs.node.path} has no CfnPolicy for the function to depend on.`);
    }
    handler.addResourceDependency(logsPolicy);
    return LambdaFunction.fromFunctionAttributes(this, 'ReportsAutoDeleteFunction', {
      functionArn: handler.getAtt('Arn').toString(),
      sameEnvironment: true,
    });
  }

  /**
   * Lets `web` do only what it does: read a check's META (GetItem) and its
   * steps (Query), read a check's report under `reports/` and the demo
   * proxy's files under `GO_PROXY_PREFIX`, start the Checker
   * at `$LATEST` asynchronously, send a waiting check's callback, and read
   * the reviewer key a person enters to Approve or Block, once at start.
   */
  private grantWeb(
    web: LambdaFunction,
    { table, reports, checker }: { table: Table; reports: Bucket; checker: LambdaFunction },
  ): void {
    web.addEnvironment(DYNAMODB_TABLE_NAME, table.tableName);
    web.addEnvironment(REPORTS_BUCKET_NAME, reports.bucketName);
    web.addEnvironment(CHECKER_FUNCTION_ARN, `${checker.functionArn}:$LATEST`);
    table.grant(web, 'dynamodb:GetItem', 'dynamodb:Query');

    const key = new Secret(this, 'ReviewerKey', {
      description: 'The key a person enters on a check’s page to Approve or Block it.',
      generateSecretString: { passwordLength: 40, excludePunctuation: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    Validations.of(key).acknowledge({
      id: 'AwsSolutions-SMG4',
      reason:
        'The reviewer key is a password the owner reads from Secrets Manager and types in; there is no system to rotate it with, and changing it is a manual step that takes effect on the web function’s next cold start.',
    });
    web.addEnvironment(REVIEWER_KEY_SECRET_ARN, key.secretArn);

    const policy = new Policy(this, 'WebAccess', {
      statements: [
        new PolicyStatement({
          actions: ['s3:GetObject'],
          resources: [
            reports.arnForObjects('reports/*'),
            reports.arnForObjects(`${GO_PROXY_PREFIX}*`),
          ],
        }),
        // Without it, S3 answers a missing proxy file 403, not 404, and a
        // 404 is what sends the go command on to the public proxy.
        new PolicyStatement({
          actions: ['s3:ListBucket'],
          resources: [reports.bucketArn],
          conditions: { StringLike: { 's3:prefix': [`${GO_PROXY_PREFIX}*`] } },
        }),
        new PolicyStatement({
          actions: ['lambda:InvokeFunction'],
          resources: [`${checker.functionArn}:$LATEST`],
        }),
        // Lambda authorizes a callback against the ARN of the durable
        // execution that made it: the Checker's qualified ARN and its path.
        new PolicyStatement({
          actions: [CALLBACK_ACTION],
          resources: [`${checker.functionArn}:*`],
        }),
        new PolicyStatement({
          actions: ['secretsmanager:GetSecretValue'],
          resources: [key.secretArn],
        }),
      ],
    });
    web.role?.attachInlinePolicy(policy);
    const cfnBucket = reports.node.defaultChild;
    const cfnChecker = checker.node.defaultChild;
    if (!(cfnBucket instanceof CfnBucket) || !(cfnChecker instanceof CfnFunction)) {
      throw new Error(`${web.node.path}'s access names a bucket and a function it can't find.`);
    }
    Validations.of(policy).acknowledge({
      id: `AwsSolutions-IAM5[Resource::<${this.getLogicalId(cfnBucket)}.Arn>/reports/*]`,
      reason:
        'The web function reads the report of the check a page shows, reports/<check-id>.json, a key known only per request; the wildcard reaches only that prefix of the reports bucket, and only to get.',
    });
    Validations.of(policy).acknowledge({
      id: `AwsSolutions-IAM5[Resource::<${this.getLogicalId(cfnBucket)}.Arn>/${GO_PROXY_PREFIX}*]`,
      reason:
        'The web function serves the demo Go module proxy, goproxy/<module>/@v/<version>.zip and its kin, whose keys are the module paths and versions a request names; the wildcard reaches only that prefix of the reports bucket, and only to get. Nothing in the stack writes it.',
    });
    Validations.of(policy).acknowledge({
      id: `AwsSolutions-IAM5[Resource::<${this.getLogicalId(cfnChecker)}.Arn>:*]`,
      reason:
        'Lambda authorizes a callback against the ARN of the durable execution that made it, the Checker’s qualified ARN followed by the execution’s own path, unknown until it starts; the wildcard reaches only the Checker’s own executions, and only to send a callback’s success.',
    });
  }

  /**
   * Makes the key the Checker derives each check's sandbox run token from,
   * so no token is kept in an execution's history, and lets `fn` read it,
   * and only read it. The key holds no data: losing it ends only the
   * sandboxes alive at the time, which live two hours at most.
   */
  private grantRunTokenKey(fn: LambdaFunction, rules: TierRules): void {
    const key = new Secret(this, 'RunTokenKey', {
      description: 'The key the Checker derives each check’s sandbox run token from.',
      generateSecretString: { passwordLength: 64, excludePunctuation: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    if (rules.keepData) {
      Validations.of(key).acknowledge({
        id: 'AwsSolutions-SMG4',
        reason:
          'Rotating the key would change the token of every sandbox alive at the time, breaking its check; a token lives only as long as its sandbox, two hours at most, and the key never leaves the Checker.',
      });
    }
    fn.addEnvironment(RUN_TOKEN_SECRET_ARN, key.secretArn);
    fn.addToRolePolicy(
      new PolicyStatement({
        actions: ['secretsmanager:GetSecretValue'],
        resources: [key.secretArn],
      }),
    );
  }

  /**
   * Lets `fn` put each check's report and observations, under
   * `REPORT_PREFIXES`, and nothing else in `bucket`: it reads nothing back.
   */
  private grantReportWrites(fn: LambdaFunction, bucket: Bucket): void {
    const policy = new Policy(this, `${fn.node.id}Reports`, {
      statements: [
        new PolicyStatement({
          actions: ['s3:PutObject'],
          resources: REPORT_PREFIXES.map((prefix) => bucket.arnForObjects(`${prefix}*`)),
        }),
      ],
    });
    fn.role?.attachInlinePolicy(policy);
    const cfnBucket = bucket.node.defaultChild;
    if (!(cfnBucket instanceof CfnBucket)) {
      throw new Error(`${bucket.node.path} has no CfnBucket to name in its acknowledgement.`);
    }
    for (const prefix of REPORT_PREFIXES) {
      Validations.of(policy).acknowledge({
        id: `AwsSolutions-IAM5[Resource::<${this.getLogicalId(cfnBucket)}.Arn>/${prefix}*]`,
        reason: `Each check writes its own ${prefix}<check-id>.json, a key unknown until the check starts; the wildcard reaches only that prefix of the reports bucket, and only to put.`,
      });
    }
  }

  /**
   * Lets `fn` call the judge's model, and no other: through its inference
   * profile in the stack's region, which routes the call to the model in
   * one of `JUDGE_MODEL_REGIONS`. The Converse API is `bedrock:InvokeModel`.
   */
  private grantJudge(fn: LambdaFunction): void {
    fn.addEnvironment(JUDGE_MODEL_ID, JUDGE_INFERENCE_PROFILE);
    fn.addToRolePolicy(
      new PolicyStatement({
        actions: ['bedrock:InvokeModel'],
        resources: [
          `arn:${this.partition}:bedrock:${this.region}:${this.account}:inference-profile/${JUDGE_INFERENCE_PROFILE}`,
          ...JUDGE_MODEL_REGIONS.map(
            (region) => `arn:${this.partition}:bedrock:${region}::foundation-model/${JUDGE_MODEL}`,
          ),
        ],
      }),
    );
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
   * The HTTP API: `WEB_ROUTES` call `web`, open to the public. Any other
   * route is signed with IAM (SigV4), the scaffold's default, and the stage
   * logs and throttles every request.
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
    for (const [method, routePath] of WEB_ROUTES) {
      for (const route of api.addRoutes({
        path: routePath,
        methods: [HttpMethod[method]],
        integration,
        authorizer: new HttpNoneAuthorizer(),
      })) {
        Validations.of(route).acknowledge({
          id: 'AwsSolutions-APIG4',
          reason:
            'MCP Customs is a public service: anyone may submit a server and read its check, as the demo, the judges and agent platforms do, without an AWS identity. The stage is throttled; Approve and Block take the reviewer key, which the web function checks before it sends a callback. The demo Go module proxy under /goproxy/ is read-only, and read by the go command in the sandbox and the poller, neither of which signs a request.',
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
    functions: readonly (readonly [string, IFunction, Duration])[],
  ): Alarms {
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
    return alarms;
  }
}
