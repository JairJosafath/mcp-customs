import { AssetHashType, DockerImage, RemovalPolicy } from 'aws-cdk-lib';
import type { Duration } from 'aws-cdk-lib';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import {
  Architecture,
  Code,
  Function as LambdaFunction,
  LoggingFormat,
  Runtime,
  Tracing,
} from 'aws-cdk-lib/aws-lambda';
import type { DurableConfig } from 'aws-cdk-lib/aws-lambda';
import { LogGroup } from 'aws-cdk-lib/aws-logs';
import type { Construct } from 'constructs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

import type { TierRules } from './standard';

// The functions' Go module: its own go.mod, apart from node_modules/, whose
// stray .go files would otherwise be part of it.
const SRC = path.join(import.meta.dirname, '..', 'src');

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
export interface GoFunctionProps {
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
export function goFunction(scope: Construct, id: string, props: GoFunctionProps): LambdaFunction {
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
