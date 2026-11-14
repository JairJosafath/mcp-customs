import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

import { ApiStack, PUBLIC_GO_PROXY, WEB_ROUTES } from './api_stack';
import { DEFAULT_DEMO_VERSION, GO_PROXY_PREFIX, demoVersionOf } from './demo_proxy';
import { GO_PROXY_URL } from './sandbox';
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

function build(tier: Tier, demoVersion?: string): { app: App; template: Template } {
  const app = new App();
  const stack = new ApiStack(app, `test-${tier}`, {
    tier,
    operations: OPERATIONS,
    ...(demoVersion === undefined ? {} : { demoVersion }),
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

  it('publishes demoVersion and every earlier version, v1.0.0 by default', () => {
    const files = (version?: string): string => {
      const { app, template } = build('development', version);
      const keys = Object.values(template.findResources('Custom::CDKBucketDeployment')).map(
        (r: unknown) => JSON.stringify(field(field(r, 'Properties'), 'SourceObjectKeys')),
      );
      const hash = /([0-9a-f]{64})\.zip/.exec(keys[0] ?? '')?.[1] ?? '';
      return path.join(
        app.outdir,
        `asset.${hash}`,
        'github.com/!jair!josafath/mcp-customs/demo/mail/@v',
      );
    };
    expect(DEFAULT_DEMO_VERSION).toBe('v1.0.0');
    expect(existsSync(path.join(files(), 'v1.0.0.zip'))).toBe(true);
    expect(existsSync(path.join(files(), 'v1.0.1.zip'))).toBe(false);
    const rugPull = files('v1.0.1');
    expect(existsSync(path.join(rugPull, 'v1.0.0.zip'))).toBe(true);
    expect(existsSync(path.join(rugPull, 'v1.0.1.zip'))).toBe(true);
  });

  it('takes the version from the demoVersion context value, refusing anything but a version', () => {
    expect(demoVersionOf(undefined)).toBe(DEFAULT_DEMO_VERSION);
    expect(demoVersionOf('v1.0.1')).toBe('v1.0.1');
    for (const bad of ['1.0.1', 'v1.0.1; rm -rf /', '', 101]) {
      expect(() => demoVersionOf(bad), String(bad)).toThrow(/demoVersion/);
    }
  });
});
