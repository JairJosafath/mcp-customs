import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { Node } from 'constructs';
import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { beforeAll, describe, expect, it, vi } from 'vitest';

import { ApiStack, PUBLIC_GO_PROXY, WEB_ROUTES } from './api_stack';
import { DEMO_VERSIONS_FILE, GO_PROXY_PREFIX, readDemoVersions } from './demo_proxy';
import { GO_PROXY_URL } from './sandbox';
import { defineStacks } from './stacks';
import type { Operations, Tier } from './standard';

const OPERATIONS: Operations = {
  backups: { retentionDays: 35, copyToRegion: '' },
  recovery: { rpo: '1h', rto: '4h' },
  alerts: { email: '' },
};

/** `o`'s field `key`, or undefined when `o` is no object or has none. */
function field(o: unknown, key: string): unknown {
  return typeof o === 'object' && o !== null && key in o
    ? (o as Record<string, unknown>)[key]
    : undefined;
}

/** A policy statement, with the logical ID of the resource that holds it. */
interface Statement {
  readonly holder: string;
  readonly effect: unknown;
  readonly actions: string[];
  readonly resources: string;
  readonly principal: string;
}

/**
 * Every statement of every policy document in the template: IAM policies,
 * managed policies, roles' inline policies and bucket policies.
 */
function statements(template: Template): Statement[] {
  const documents: [string, unknown][] = [];
  for (const type of ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'AWS::S3::BucketPolicy']) {
    for (const [id, resource] of Object.entries(template.findResources(type))) {
      documents.push([id, field(field(resource, 'Properties'), 'PolicyDocument')]);
    }
  }
  for (const [id, role] of Object.entries(template.findResources('AWS::IAM::Role'))) {
    const inline = field(field(role, 'Properties'), 'Policies');
    for (const policy of Array.isArray(inline) ? (inline as unknown[]) : []) {
      documents.push([id, field(policy, 'PolicyDocument')]);
    }
  }
  return documents.flatMap(([holder, document]) => {
    const list = field(document, 'Statement');
    return (Array.isArray(list) ? (list as unknown[]) : []).map((s) => ({
      holder,
      effect: field(s, 'Effect'),
      actions: [field(s, 'Action')].flat().filter((a): a is string => typeof a === 'string'),
      resources: JSON.stringify(field(s, 'Resource')),
      principal: JSON.stringify(field(s, 'Principal') ?? null),
    }));
  });
}

/**
 * Whether resources reach the demo proxy's objects: every resource, or an
 * object pattern whose prefix before `*` is a prefix of `goproxy/` (`/*`,
 * `/g*`, `/goproxy/*`).
 */
function reachesProxy(resources: string): boolean {
  if (resources === '"*"' || resources.includes('["*"]')) {
    return true;
  }
  return [...resources.matchAll(/"\/([^"*]*)\*"/g)].some(([, prefix]) =>
    GO_PROXY_PREFIX.startsWith(prefix ?? '~'),
  );
}

/** Whether an action may change an object. */
function writes(action: string): boolean {
  return action === '*' || (action.startsWith('s3:') && !/^s3:(Get|List)/.test(action));
}

function build(tier: Tier, demoVersionsFile?: string): { app: App; template: Template } {
  const app = new App();
  const stack = new ApiStack(app, `test-${tier}`, {
    tier,
    operations: OPERATIONS,
    ...(demoVersionsFile === undefined ? {} : { demoVersionsFile }),
  });
  return { app, template: Template.fromStack(stack) };
}

const templates = new Map<Tier, Template>();

beforeAll(() => {
  for (const tier of ['production', 'development'] as const) {
    templates.set(tier, build(tier).template);
  }
});

function templateOf(tier: Tier): Template {
  const template = templates.get(tier);
  if (template === undefined) {
    throw new Error(`no ${tier} template`);
  }
  return template;
}

describe('the demo Go module proxy', () => {
  it('is served read-only by the web function under /goproxy/', () => {
    expect(WEB_ROUTES.filter(([, routePath]) => routePath.startsWith('/goproxy/'))).toEqual([
      ['GET', '/goproxy/{proxy+}'],
    ]);
  });

  it('is named, before the public proxy, to the poller and the MicroVM image', () => {
    const template = templateOf('production');
    const api = Object.keys(template.findResources('AWS::ApiGatewayV2::Api'))[0] ?? '';
    const list = {
      'Fn::Join': ['', [{ 'Fn::GetAtt': [api, 'ApiEndpoint'] }, `/goproxy,${PUBLIC_GO_PROXY}`]],
    };
    template.hasResourceProperties('AWS::Lambda::Function', {
      Environment: { Variables: { [GO_PROXY_URL]: list } },
    });
    template.hasResourceProperties('AWS::Lambda::MicrovmImage', {
      EnvironmentVariables: [{ Key: GO_PROXY_URL, Value: list }],
    });
  });

  it('is written by the deploy alone: no policy of the stack lets anything else write it, in either tier', () => {
    for (const tier of ['production', 'development'] as const) {
      const writers = statements(templateOf(tier))
        .filter((s) => s.effect === 'Allow' && reachesProxy(s.resources) && s.actions.some(writes))
        // Development empties the bucket, every object, when the stack is deleted.
        .filter(
          (s) => !(tier === 'development' && s.principal.includes('CustomS3AutoDeleteObjects')),
        )
        .map((s) => s.holder);
      expect(writers, tier).toEqual([expect.stringMatching(/^DemoProxyAccess/)]);
    }
  });

  it('lets the deploy write under goproxy/ only, list only it, and read only its files’ zip', () => {
    const access = statements(templateOf('production')).filter((s) =>
      s.holder.startsWith('DemoProxyAccess'),
    );
    const s3 = access.filter((s) => s.actions.some((a) => a.startsWith('s3:')));
    expect(s3.map((s) => s.actions)).toEqual([
      ['s3:GetObject'],
      ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
      ['s3:ListBucket'],
    ]);
    expect(s3[1]?.resources).toContain(`/${GO_PROXY_PREFIX}*`);
    expect(s3[0]?.resources).toMatch(/[0-9a-f]{64}\.zip/);
  });

  it('copies the files to goproxy/, pruning what a deploy no longer publishes', () => {
    templateOf('production').hasResourceProperties('Custom::CDKBucketDeployment', {
      DestinationBucketKeyPrefix: GO_PROXY_PREFIX,
      Prune: true,
    });
  });

  it('publishes every version up to the one demo-versions.json names, under goproxy/', () => {
    const file = path.join(
      mkdtempSync(path.join(tmpdir(), 'demo-versions-')),
      'demo-versions.json',
    );
    writeFileSync(file, JSON.stringify({ mail: 'v1.0.1', weather: 'v1.0.0' }));
    const published = mailVersions(build('development', file));
    expect(published).toEqual(['v1.0.0.zip', 'v1.0.1.zip']);
    // The committed file: before the rug pull.
    expect(readDemoVersions(DEMO_VERSIONS_FILE)).toEqual({ mail: 'v1.0.0', weather: 'v1.0.0' });
    expect(mailVersions(build('development'))).toEqual(['v1.0.0.zip']);
  });

  it('reads no context value but tier at synth: the versions come from the committed file alone', () => {
    const read: string[] = [];
    // The spy calls through, and keeps each key asked for.
    const spy = vi.spyOn(Node.prototype, 'tryGetContext');
    try {
      const app = new App({ context: { demoVersion: 'v1.0.1', demoVersions: 'v1.0.0,v1.0.1' } });
      const [stack] = defineStacks(app, 'development');
      if (stack === undefined) {
        throw new Error('no stack');
      }
      expect(mailVersions({ app, template: Template.fromStack(stack) })).toEqual(['v1.0.0.zip']);
      read.push(...spy.mock.calls.map(([key]) => key));
    } finally {
      spy.mockRestore();
    }
    // CDK's own feature flags and settings aside, and the spy saw them.
    expect(read.length).toBeGreaterThan(0);
    expect(
      read.filter((key) => key !== 'tier' && !/^(@aws-cdk|aws:cdk|aws-cdk|cdk-)/.test(key)),
    ).toEqual([]);
  });

  it('refuses a versions file that is not one object of versions', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'demo-versions-'));
    for (const [i, bad] of [
      '[]',
      'null',
      '{"mail": 1}',
      '{"mail": "1.0.1"}',
      '{"mail": "v1.0.1; rm -rf /"}',
    ].entries()) {
      const file = path.join(dir, `${String(i)}.json`);
      writeFileSync(file, bad);
      expect(() => readDemoVersions(file), bad).toThrow(/demo names to versions/);
    }
  });
});

/** The mail demo's zips in the files a stack's deployment copies to goproxy/. */
function mailVersions({ app, template }: { app: App; template: Template }): string[] {
  const deployments = Object.values(template.findResources('Custom::CDKBucketDeployment'));
  expect(deployments).toHaveLength(1);
  const properties = field(deployments[0], 'Properties');
  expect(field(properties, 'DestinationBucketKeyPrefix')).toBe(GO_PROXY_PREFIX);
  const hash = /([0-9a-f]{64})\.zip/.exec(
    JSON.stringify(field(properties, 'SourceObjectKeys')),
  )?.[1];
  const dir = path.join(
    app.outdir,
    `asset.${hash ?? ''}`,
    'github.com/!jair!josafath/mcp-customs/demo/mail/@v',
  );
  return readdirSync(dir)
    .filter((f) => f.endsWith('.zip'))
    .sort();
}
