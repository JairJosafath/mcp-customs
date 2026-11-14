import {
  AssetHashType,
  CfnResource,
  DockerImage,
  RemovalPolicy,
  Stack,
  Validations,
} from 'aws-cdk-lib';
import { Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { CfnFunction, Function as LambdaFunction } from 'aws-cdk-lib/aws-lambda';
import type { IFunction } from 'aws-cdk-lib/aws-lambda';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Asset } from 'aws-cdk-lib/aws-s3-assets';
import { BucketDeployment, Source } from 'aws-cdk-lib/aws-s3-deployment';
import { Construct } from 'constructs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

import type { TierRules } from './standard';

const SRC = path.join(import.meta.dirname, '..', 'src');

/**
 * Where the reports bucket keeps the demo Go module proxy's files, which
 * the web function serves read-only under `/goproxy/`. Only the deploy
 * writes them.
 */
export const GO_PROXY_PREFIX = 'goproxy/';

/** The context value that names the newest demo version a deploy publishes. */
export const DEMO_VERSION_CONTEXT = 'demoVersion';

/** The demo version a deploy publishes when it names none: before the rug pull. */
export const DEFAULT_DEMO_VERSION = 'v1.0.0';

/** A demo version as `src/internal/demoproxy` names one. */
const DEMO_VERSION = /^v\d+\.\d+\.\d+$/;

/**
 * The demo version a deploy publishes: the `demoVersion` context value
 * (`cdk deploy -c demoVersion=v1.0.1`), `DEFAULT_DEMO_VERSION` without it.
 */
export function demoVersionOf(value: unknown): string {
  if (value === undefined) {
    return DEFAULT_DEMO_VERSION;
  }
  if (typeof value !== 'string' || !DEMO_VERSION.test(value)) {
    throw new Error(`${DEMO_VERSION_CONTEXT} must be a demo version such as v1.0.1.`);
  }
  return value;
}

/** What the demo proxy is made from. */
export interface DemoProxyProps {
  /** The bucket that holds the proxy's files under `GO_PROXY_PREFIX`. */
  readonly bucket: Bucket;
  /** The newest demo version it publishes; every earlier one comes too. */
  readonly version: string;
  readonly rules: TierRules;
}

/**
 * The demo Go module proxy's files (docs/contracts.md, "The demo proxy"),
 * written by `go run ./cmd/demopublish` at synth and copied to the bucket's
 * `GO_PROXY_PREFIX` on deploy, the earlier files there pruned: a deploy
 * with another `demoVersion` publishes, or takes back, the rug pull.
 *
 * CDK's copying function is held to what the stack's own functions keep:
 * its own log group, kept for the tier's time; X-Ray where the tier traces;
 * and a role allowed only to read the files' zip, write under the prefix
 * and write its logs, where CDK would grant it every object of the bucket.
 */
export class DemoProxy extends Construct {
  /** The function that copies the files, for its alarms. */
  readonly handler: IFunction;

  constructor(scope: Construct, id: string, props: DemoProxyProps) {
    super(scope, id);
    const { bucket, version, rules } = props;
    const files = demoProxyFiles(this, version);
    const logGroup = new LogGroup(this, 'Logs', {
      retention: rules.logRetention,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const role = new Role(this, 'Role', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: `Copies the demo Go module proxy's files to ${GO_PROXY_PREFIX} of the reports bucket.`,
    });
    const access = new Policy(this, 'Access', {
      statements: [
        new PolicyStatement({
          actions: ['s3:GetObject'],
          resources: [files.bucket.arnForObjects(files.s3ObjectKey)],
        }),
        new PolicyStatement({
          actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
          resources: [bucket.arnForObjects(`${GO_PROXY_PREFIX}*`)],
        }),
        new PolicyStatement({
          actions: ['s3:ListBucket'],
          resources: [bucket.bucketArn],
          conditions: { StringLike: { 's3:prefix': [`${GO_PROXY_PREFIX}*`] } },
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [logGroup.logGroupArn],
        }),
        ...(rules.tracing
          ? [
              new PolicyStatement({
                actions: ['xray:PutTraceSegments', 'xray:PutTelemetryRecords'],
                resources: ['*'],
              }),
            ]
          : []),
      ],
    });
    access.attachToRole(role);

    const deployment = new BucketDeployment(this, 'Deployment', {
      sources: [Source.bucket(files.bucket, files.s3ObjectKey)],
      // By reference: the deployment then tags, and grants on, nothing of the bucket itself.
      destinationBucket: Bucket.fromBucketName(this, 'Destination', bucket.bucketName),
      destinationKeyPrefix: GO_PROXY_PREFIX,
      prune: true,
      memoryLimit: 256,
      logGroup,
      // CDK's own grants, of every object of the bucket, are left out:
      // the policy above holds the role to the prefix.
      role: role.withoutPolicyUpdates(),
    });
    const fn = singletonOf(Stack.of(this), deployment);
    if (rules.tracing) {
      fn.tracingConfig = { mode: 'Active' };
    }
    fn.loggingConfig = { logGroup: logGroup.logGroupName, logFormat: 'JSON' };
    Validations.of(fn).acknowledge({
      id: 'AwsSolutions-L1',
      reason:
        'CDK chooses the runtime of its BucketDeployment function to match the handler code it ships, and moves it forward with aws-cdk-lib; another runtime could break the copy.',
    });
    // The function copies as soon as it is made: its role must hold the policy by then.
    const cfnAccess = access.node.defaultChild;
    if (!(cfnAccess instanceof CfnResource)) {
      throw new Error(`${access.node.path} has no CfnPolicy for the function to depend on.`);
    }
    fn.addResourceDependency(cfnAccess);
    const cfnBucket = bucket.node.defaultChild;
    if (!(cfnBucket instanceof CfnResource)) {
      throw new Error(`${bucket.node.path} has no CfnBucket to name in its acknowledgement.`);
    }
    Validations.of(access).acknowledge({
      id: `AwsSolutions-IAM5[Resource::<${Stack.of(this).getLogicalId(cfnBucket)}.Arn>/${GO_PROXY_PREFIX}*]`,
      reason:
        'The deployment writes the proxy files, whose keys are the demo modules’ paths and versions, and prunes the ones a deploy no longer publishes; the wildcard reaches only that prefix of the reports bucket.',
    });
    this.handler = LambdaFunction.fromFunctionAttributes(this, 'Handler', {
      functionArn: fn.attrArn,
      sameEnvironment: true,
    });
  }
}

/** The CfnFunction of CDK's copying function, which it makes once per stack. */
function singletonOf(stack: Stack, deployment: BucketDeployment): CfnFunction {
  const found = stack.node
    .findAll()
    .filter(
      (c): c is CfnFunction =>
        c instanceof CfnFunction && c.node.path.includes('Custom::CDKBucketDeployment'),
    );
  const fn = found[0];
  if (found.length !== 1 || fn === undefined) {
    throw new Error(
      `${deployment.node.path}: found ${String(found.length)} copying functions, not one.`,
    );
  }
  return fn;
}

/**
 * The proxy's files for `version`, written by `go run ./cmd/demopublish`
 * with the installed Go. Never Docker, which CI doesn't have: a failed
 * build fails synth.
 */
function demoProxyFiles(scope: Construct, version: string): Asset {
  // In the bundling options too: CDK keys an asset's staging on them, so
  // two versions get two assets.
  const environment = { DEMO_VERSION: version };
  return new Asset(scope, 'Files', {
    path: path.join(SRC, 'demo'),
    // The hash of the files written, the same from one build to the next.
    assetHashType: AssetHashType.OUTPUT,
    bundling: {
      // Required by the type, never pulled: local bundling always succeeds or throws.
      image: DockerImage.fromRegistry('public.ecr.aws/docker/library/golang'),
      environment,
      local: {
        tryBundle(outputDir: string): boolean {
          execFileSync('go', ['run', './cmd/demopublish', '-version', version, '-out', outputDir], {
            cwd: SRC,
            env: { ...process.env, ...environment },
            stdio: ['ignore', 'inherit', 'inherit'],
          });
          return true;
        },
      },
    },
  });
}
