import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

import { ApiStack } from './api_stack';
import {
  API_HOST,
  HOOKS_PORT,
  PASS_CONNECTOR_ACTION,
  SANDBOX_ACTIONS,
  SANDBOX_ENVIRONMENT,
  SANDBOX_MEMORY_MIB,
} from './sandbox';
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

/** `Fn::Join` of an AWS-managed network connector's ARN, as the stack writes it. */
function connectorArn(name: string): unknown {
  return {
    'Fn::Join': [
      '',
      [
        'arn:',
        { Ref: 'AWS::Partition' },
        ':lambda:',
        { Ref: 'AWS::Region' },
        `:aws:network-connector:aws-network-connector:${name}`,
      ],
    ],
  };
}

/** The directory synth zipped as the image's code. */
function assetDir(): string {
  const uri = JSON.stringify(
    template.findResources('AWS::Lambda::MicrovmImage')[image]?.['Properties'],
  );
  const hash = /([0-9a-f]{64})\.zip/.exec(uri)?.[1] ?? '';
  return path.join(outdir, `asset.${hash}`);
}

let outdir: string;
let template: Template;
let image: string;

beforeAll(() => {
  const app = new App();
  template = Template.fromStack(
    new ApiStack(app, 'test', { tier: 'development', operations: OPERATIONS }),
  );
  outdir = app.outdir;
  image = idOf(template, 'AWS::Lambda::MicrovmImage', 'Sandbox');
});

describe('Sandbox', () => {
  it('builds one ARM64 MicroVM image from the Dockerfile zip on Lambda’s base image', () => {
    template.resourceCountIs('AWS::Lambda::MicrovmImage', 1);
    template.hasResource('AWS::Lambda::MicrovmImage', {
      DeletionPolicy: 'Delete',
      Properties: {
        Name: 'test-harness',
        BaseImageArn: {
          'Fn::Join': [
            '',
            [
              'arn:',
              { Ref: 'AWS::Partition' },
              ':lambda:',
              { Ref: 'AWS::Region' },
              ':aws:microvm-image:al2023-1',
            ],
          ],
        },
        BaseImageVersion: '3',
        CpuConfigurations: [{ Architecture: 'ARM_64' }],
        CodeArtifact: {
          Uri: { 'Fn::Sub': Match.stringLikeRegexp('^s3://.+/[0-9a-f]{64}\\.zip$') },
        },
        BuildRoleArn: {
          'Fn::GetAtt': [idOf(template, 'AWS::IAM::Role', 'SandboxBuildRole'), 'Arn'],
        },
        Resources: [{ MinimumMemoryInMiB: SANDBOX_MEMORY_MIB }],
        AdditionalOsCapabilities: ['ALL'],
        EgressNetworkConnectors: [connectorArn('INTERNET_EGRESS')],
      },
    });
  });

  it('snapshots once the harness is ready and hands each MicroVM its run through the /run hook, on the hooks port', () => {
    template.hasResourceProperties('AWS::Lambda::MicrovmImage', {
      Hooks: {
        Port: HOOKS_PORT,
        MicrovmImageHooks: { Ready: 'ENABLED' },
        MicrovmHooks: {
          Run: 'ENABLED',
          Resume: 'DISABLED',
          Suspend: 'DISABLED',
          Terminate: 'DISABLED',
        },
      },
    });
  });

  it('zips the Dockerfile and the harness built for arm64 Linux', () => {
    const dir = assetDir();
    expect(readdirSync(dir).sort()).toEqual(['Dockerfile', 'harness']);
    // An ELF executable for AArch64: e_machine 183 at offset 18.
    const binary = readFileSync(path.join(dir, 'harness'));
    expect(binary.subarray(0, 4).toString('latin1')).toBe('\x7fELF');
    expect(binary.readUInt16LE(18)).toBe(183);
    const dockerfile = readFileSync(path.join(dir, 'Dockerfile'), 'utf8');
    expect(dockerfile).toContain('ENTRYPOINT ["/usr/local/sbin/harness"]');
    expect(dockerfile).toMatch(/useradd .* dev/);
    expect(dockerfile).toMatch(/^USER root$/m);
    // No setuid binaries, setpriv for no_new_privs, libfaketime for the clock.
    expect(dockerfile).toContain('-perm /6000 -exec chmod ug-s');
    expect(dockerfile).toContain('util-linux');
    expect(dockerfile).toContain('/usr/local/lib/faketime/libfaketime.so.1');
  });

  describe('the zipped Dockerfile', () => {
    let dockerfile: string;
    beforeAll(() => {
      dockerfile = readFileSync(path.join(assetDir(), 'Dockerfile'), 'utf8');
    });

    it('pins the base image by digest, and dnf to the base’s release and versions', () => {
      expect(dockerfile).toMatch(
        /^FROM public\.ecr\.aws\/lambda\/microvms:al2023-minimal\.[0-9.]+@sha256:[0-9a-f]{64}$/m,
      );
      const release = /^ARG AL2023_RELEASE=(2023\.\d+\.\d{8})$/m.exec(dockerfile)?.[1];
      expect(release).toBeDefined();
      expect(dockerfile).toContain('echo "${AL2023_RELEASE}" > /etc/dnf/vars/releasever');
      // Every package dnf installs names its version and release.
      const installs = [...dockerfile.matchAll(/dnf install -y ([^&]*)/g)].map((m) => m[1] ?? '');
      expect(installs).toHaveLength(2);
      for (const install of installs) {
        const packages = install.split(/\s+/).filter((word) => /^[a-z]/.test(word));
        expect(packages.length).toBeGreaterThan(1);
        for (const name of packages) {
          expect(name).toMatch(/-(\d+:)?[0-9.]+-[0-9.]+amzn2023[0-9.]*$/);
        }
      }
    });

    it('pins Python’s patch version, and checks the one it installed', () => {
      expect(dockerfile).toMatch(/^ARG PYTHON_VERSION=\d+\.\d+\.\d+$/m);
      expect(dockerfile).toContain('uv python install --default "${PYTHON_VERSION}"');
      expect(dockerfile).toContain('print(platform.python_version())\')" = "${PYTHON_VERSION}"');
    });

    it.each([
      ['setpriv, for no_new_privs', 'test -x /usr/bin/setpriv'],
      ['iptables on nf_tables', 'iptables --version | grep -q nf_tables'],
      ['ip6tables on nf_tables', 'ip6tables --version | grep -q nf_tables'],
      ['the NFLOG target', 'test -f /usr/lib64/xtables/libxt_NFLOG.so'],
      ['libfaketime', 'test -f /usr/local/lib/faketime/libfaketime.so.1'],
      ['Go and npm', 'go version && npm --version'],
    ])('fails its build without %s', (_, check) => {
      expect(dockerfile).toContain(check);
    });

    it('finds iptables, in /usr/sbin, on the harness’s PATH but not the server’s', () => {
      const imagePath = /^ENV PATH=(\S+)$/m.exec(dockerfile)?.[1]?.split(':') ?? [];
      expect(imagePath).toContain('/usr/sbin');
      expect(dockerfile).toMatch(/dnf install[^&]*iptables-nft-/);
    });
  });

  it('lets the build role read only the zip and write only the image’s build logs, kept a set time', () => {
    const role = idOf(template, 'AWS::IAM::Role', 'SandboxBuildRole');
    expect(template.findResources('AWS::IAM::Role')[role]?.['Properties']).not.toHaveProperty(
      'ManagedPolicyArns',
    );
    const logs = idOf(template, 'AWS::Logs::LogGroup', 'SandboxBuildLogs');
    template.hasResourceProperties('AWS::Logs::LogGroup', {
      LogGroupName: '/aws/lambda-microvms/test-harness',
      RetentionInDays: 30,
    });
    template.hasResourceProperties('AWS::IAM::Policy', {
      Roles: [{ Ref: role }],
      PolicyDocument: {
        Statement: [
          {
            Action: 's3:GetObject',
            Effect: 'Allow',
            Resource: {
              'Fn::Join': ['', Match.arrayWith([Match.stringLikeRegexp('[0-9a-f]{64}\\.zip$')])],
            },
          },
          {
            Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
            Effect: 'Allow',
            Resource: { 'Fn::GetAtt': [logs, 'Arn'] },
          },
        ],
      },
    });
  });

  it('lets only Lambda, building this account’s image, assume the build role', () => {
    const role = idOf(template, 'AWS::IAM::Role', 'SandboxBuildRole');
    const imageArn = (suffix: string): unknown => ({
      'Fn::Join': [
        '',
        [
          'arn:',
          { Ref: 'AWS::Partition' },
          ':lambda:',
          { Ref: 'AWS::Region' },
          ':',
          { Ref: 'AWS::AccountId' },
          `:microvm-image:test-harness${suffix}`,
        ],
      ],
    });
    expect(template.findResources('AWS::IAM::Role')[role]).toHaveProperty(
      ['Properties', 'AssumeRolePolicyDocument'],
      {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'sts:AssumeRole',
            Effect: 'Allow',
            Principal: { Service: 'lambda.amazonaws.com' },
            Condition: {
              StringEquals: { 'aws:SourceAccount': { Ref: 'AWS::AccountId' } },
              ArnLikeIfExists: { 'aws:SourceArn': [imageArn(''), imageArn(':*')] },
            },
          },
        ],
      },
    );
  });

  it('grants the Checker exactly the launch, call, suspend, resume and terminate calls on the image, and the two connectors', () => {
    const role = idOf(template, 'AWS::IAM::Role', 'CheckerRole');
    template.hasResourceProperties('AWS::IAM::Policy', {
      Roles: [{ Ref: role }],
      PolicyDocument: {
        Statement: [
          {
            Action: [...SANDBOX_ACTIONS],
            Effect: 'Allow',
            Resource: { 'Fn::GetAtt': [image, 'ImageArn'] },
          },
          {
            Action: PASS_CONNECTOR_ACTION,
            Effect: 'Allow',
            Resource: [connectorArn('HTTP_INGRESS'), connectorArn('INTERNET_EGRESS')],
          },
        ],
      },
    });
    expect([...SANDBOX_ACTIONS].sort()).toEqual(
      [
        'lambda:CreateMicrovmAuthToken',
        'lambda:GetMicrovm',
        'lambda:ResumeMicrovm',
        'lambda:RunMicrovm',
        'lambda:SuspendMicrovm',
        'lambda:TerminateMicrovm',
      ].sort(),
    );
  });

  it('hands the Checker the image and connector ARNs', () => {
    const checker = idOf(template, 'AWS::Lambda::Function', 'Checker');
    expect(template.findResources('AWS::Lambda::Function')[checker]).toMatchObject({
      Properties: {
        Environment: {
          Variables: {
            [SANDBOX_ENVIRONMENT.imageArn]: { 'Fn::GetAtt': [image, 'ImageArn'] },
            [SANDBOX_ENVIRONMENT.ingressConnectorArn]: connectorArn('HTTP_INGRESS'),
            [SANDBOX_ENVIRONMENT.egressConnectorArn]: connectorArn('INTERNET_EGRESS'),
          },
        },
      },
    });
  });

  it('hands the Checker and the harness the API’s own host, which neither lets an allowlist hold', () => {
    const api = Object.keys(template.findResources('AWS::ApiGatewayV2::Api'))[0] ?? '';
    const host = {
      'Fn::Join': [
        '',
        [{ Ref: api }, '.execute-api.', { Ref: 'AWS::Region' }, '.', { Ref: 'AWS::URLSuffix' }],
      ],
    };
    const checker = idOf(template, 'AWS::Lambda::Function', 'Checker');
    expect(template.findResources('AWS::Lambda::Function')[checker]).toMatchObject({
      Properties: { Environment: { Variables: { [API_HOST]: host } } },
    });
    template.hasResourceProperties('AWS::Lambda::MicrovmImage', {
      EnvironmentVariables: Match.arrayWith([{ Key: API_HOST, Value: host }]),
    });
  });
});
