import { ArnFormat, AssetHashType, DockerImage, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { CfnMicrovmImage } from 'aws-cdk-lib/aws-lambda';
import type { Function as LambdaFunction } from 'aws-cdk-lib/aws-lambda';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import type { RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Asset } from 'aws-cdk-lib/aws-s3-assets';
import { Construct } from 'constructs';
import { copyFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const ROOT = path.join(import.meta.dirname, '..');
const SRC = path.join(ROOT, 'src');
const SANDBOX = path.join(ROOT, 'sandbox');

/** The ports the harness listens on, as docs/contracts.md and sandbox/Dockerfile have them. */
export const HARNESS_PORT = 8080;
export const HOOKS_PORT = 9000;

/** The memory a sandbox starts with, in MiB: 2 GB and 1 vCPU, up to four times that at peak. */
export const SANDBOX_MEMORY_MIB = 2048;

/** The environment variable that names the Go proxies to the harness and the poller. */
export const GO_PROXY_URL = 'GO_PROXY_URL';

/**
 * The stack's own API host, which the server under test may never reach:
 * the Checker refuses it in an allowlist, and the harness refuses it again.
 */
export const API_HOST = 'API_HOST';

/** The Lambda-managed base image the harness image is built on, and its pinned version. */
export const BASE_IMAGE = 'al2023-1';
export const BASE_IMAGE_VERSION = '3';

/** The environment variables that hand the Checker what it launches. */
export const SANDBOX_ENVIRONMENT = {
  imageArn: 'SANDBOX_IMAGE_ARN',
  ingressConnectorArn: 'SANDBOX_INGRESS_CONNECTOR_ARN',
  egressConnectorArn: 'SANDBOX_EGRESS_CONNECTOR_ARN',
} as const;

/**
 * The Lambda MicroVMs calls the Checker makes on sandboxes of the image: the
 * Service Authorization Reference authorizes each on the image's ARN.
 */
export const SANDBOX_ACTIONS = [
  'lambda:RunMicrovm',
  'lambda:GetMicrovm',
  'lambda:CreateMicrovmAuthToken',
  'lambda:SuspendMicrovm',
  'lambda:ResumeMicrovm',
  'lambda:TerminateMicrovm',
] as const;

/** What RunMicrovm needs to attach Lambda's network connectors. */
export const PASS_CONNECTOR_ACTION = 'lambda:PassNetworkConnector';

/** What makes the sandbox image. */
export interface SandboxProps {
  /** How long the image's build logs are kept, as the tier keeps logs. */
  readonly logRetention: RetentionDays;
  /** The GOPROXY-style list Go installs resolve through, the harness's `GO_PROXY_URL`. */
  readonly goProxy: string;
  /** The stack's own API host, the harness's `API_HOST`. */
  readonly apiHost: string;
}

/**
 * The harness's MicroVM image: `sandbox/Dockerfile` and the harness binary,
 * zipped as an asset that Lambda builds and snapshots. Its build role reads
 * only that zip and writes only the image's build logs. `grantLaunch` lets a
 * function launch, call, suspend, resume and terminate MicroVMs of it.
 */
export class Sandbox extends Construct {
  /** The image's ARN, `arn:...:microvm-image:<name>`. */
  readonly imageArn: string;
  readonly ingressConnectorArn: string;
  readonly egressConnectorArn: string;

  constructor(scope: Construct, id: string, props: SandboxProps) {
    super(scope, id);
    const stack = Stack.of(this);
    const imageName = `${stack.stackName}-harness`.slice(0, 64);
    const connector = (name: string): string =>
      `arn:${stack.partition}:lambda:${stack.region}:aws:network-connector:aws-network-connector:${name}`;
    this.ingressConnectorArn = connector('HTTP_INGRESS');
    this.egressConnectorArn = connector('INTERNET_EGRESS');

    const code = harnessCode(this);
    // Lambda writes an image's build logs to this group; made here, it has
    // a retention and goes with the stack.
    const buildLogs = new LogGroup(this, 'BuildLogs', {
      logGroupName: `/aws/lambda-microvms/${imageName}`,
      retention: props.logRetention,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    // Only Lambda building this account's image may assume the build role.
    // Lambda documents neither source key for it: the account is required,
    // and the image's ARN is held to whenever Lambda names one.
    const imageArn = stack.formatArn({
      service: 'lambda',
      resource: 'microvm-image',
      resourceName: imageName,
      arnFormat: ArnFormat.COLON_RESOURCE_NAME,
    });
    const buildRole = new Role(this, 'BuildRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': stack.account },
          ArnLikeIfExists: { 'aws:SourceArn': [imageArn, `${imageArn}:*`] },
        },
      }),
      description: `Builds the ${imageName} MicroVM image: reads its code zip and writes its build logs.`,
    });
    buildRole.addToPolicy(
      new PolicyStatement({
        actions: ['s3:GetObject'],
        resources: [
          stack.formatArn({
            service: 's3',
            region: '',
            account: '',
            resource: code.s3BucketName,
            resourceName: code.s3ObjectKey,
          }),
        ],
      }),
    );
    buildLogs.grantWrite(buildRole);

    const image = new CfnMicrovmImage(this, 'Image', {
      name: imageName,
      description:
        'The MCP Customs harness: Go, Node and Python with uv, and the harness as root, serving the Harness API.',
      baseImageArn: `arn:${stack.partition}:lambda:${stack.region}:aws:microvm-image:${BASE_IMAGE}`,
      baseImageVersion: BASE_IMAGE_VERSION,
      buildRoleArn: buildRole.roleArn,
      codeArtifact: { uri: code.s3ObjectUrl },
      cpuConfigurations: [{ architecture: 'ARM_64' }],
      // The build downloads the toolchains; at run time the Checker names
      // the connectors each MicroVM gets.
      egressNetworkConnectors: [this.egressConnectorArn],
      // The same for every MicroVM, so nothing per run: the Go proxies
      // installs resolve through, the stack's demo proxy first,
      // and the stack's own API host, which no allowlist may hold.
      environmentVariables: [
        { key: GO_PROXY_URL, value: props.goProxy },
        { key: API_HOST, value: props.apiHost },
      ],
      // Lambda filters no hosts, so the harness enforces deny-by-default
      // itself with iptables rules on the server's user (src/internal/egress),
      // which need CAP_NET_ADMIN; Lambda grants that only with ALL.
      additionalOsCapabilities: ['ALL'],
      hooks: {
        port: HOOKS_PORT,
        microvmImageHooks: { ready: 'ENABLED', readyTimeoutInSeconds: 120 },
        microvmHooks: {
          run: 'ENABLED',
          runTimeoutInSeconds: 30,
          resume: 'DISABLED',
          suspend: 'DISABLED',
          terminate: 'DISABLED',
        },
      },
      logging: { cloudWatch: { logGroup: buildLogs.logGroupName } },
      resources: [{ minimumMemoryInMiB: SANDBOX_MEMORY_MIB }],
    });
    image.applyRemovalPolicy(RemovalPolicy.DESTROY);
    // The build reads the zip and writes the logs as soon as the image is made.
    image.node.addDependency(buildRole);
    this.imageArn = image.attrImageArn;
  }

  /**
   * Lets `fn` run MicroVMs of the image with Lambda's HTTP ingress and
   * internet egress connectors, call them, suspend, resume and terminate
   * them, and hands it their ARNs in `SANDBOX_ENVIRONMENT`.
   */
  grantLaunch(fn: LambdaFunction): void {
    const policy = new Policy(this, `${fn.node.id}Launch`, {
      statements: [
        new PolicyStatement({ actions: [...SANDBOX_ACTIONS], resources: [this.imageArn] }),
        new PolicyStatement({
          actions: [PASS_CONNECTOR_ACTION],
          resources: [this.ingressConnectorArn, this.egressConnectorArn],
        }),
      ],
    });
    fn.role?.attachInlinePolicy(policy);
    fn.addEnvironment(SANDBOX_ENVIRONMENT.imageArn, this.imageArn);
    fn.addEnvironment(SANDBOX_ENVIRONMENT.ingressConnectorArn, this.ingressConnectorArn);
    fn.addEnvironment(SANDBOX_ENVIRONMENT.egressConnectorArn, this.egressConnectorArn);
  }
}

/**
 * The image's code zip: `sandbox/Dockerfile`, and `harness`, src/cmd/harness
 * built by the installed Go for the image's arm64 Linux. Never Docker, which
 * CI doesn't have: a failed build fails synth.
 */
function harnessCode(scope: Construct): Asset {
  const environment = { GOOS: 'linux', GOARCH: 'arm64', CGO_ENABLED: '0' };
  return new Asset(scope, 'Code', {
    path: SANDBOX,
    // The hash of what the source builds to, the same from one build to the next.
    assetHashType: AssetHashType.OUTPUT,
    bundling: {
      // Required by the type, never pulled: local bundling always succeeds or throws.
      image: DockerImage.fromRegistry('public.ecr.aws/docker/library/golang'),
      environment,
      local: {
        tryBundle(outputDir: string): boolean {
          copyFileSync(path.join(SANDBOX, 'Dockerfile'), path.join(outputDir, 'Dockerfile'));
          execFileSync(
            'go',
            [
              'build',
              '-trimpath',
              '-buildvcs=false',
              '-ldflags',
              '-s -w',
              '-o',
              path.join(outputDir, 'harness'),
              './cmd/harness',
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
