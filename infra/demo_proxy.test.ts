import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { beforeAll, describe, expect, it } from 'vitest';

import { ApiStack, GO_PROXY_PREFIX, PUBLIC_GO_PROXY, WEB_ROUTES } from './api_stack';
import { GO_PROXY_URL } from './sandbox';
import type { Operations, Tier } from './standard';

const OPERATIONS: Operations = {
  backups: { retentionDays: 35, copyToRegion: '' },
  recovery: { rpo: '1h', rto: '4h' },
  alerts: { email: '' },
};

/** A policy statement as the template has it. */
interface Statement {
  readonly Action: string | readonly string[];
  readonly Resource: unknown;
}

/** `o`'s field `key`, or undefined when `o` is no object or has none. */
function field(o: unknown, key: string): unknown {
  return typeof o === 'object' && o !== null && key in o
    ? (o as Record<string, unknown>)[key]
    : undefined;
}

/** Every statement of the template's IAM policies. */
function statements(template: Template): Statement[] {
  return Object.values(template.findResources('AWS::IAM::Policy')).flatMap((policy: unknown) => {
    const list = field(field(field(policy, 'Properties'), 'PolicyDocument'), 'Statement');
    return Array.isArray(list)
      ? list.filter((s: unknown): s is Statement => field(s, 'Action') !== undefined)
      : [];
  });
}

/** Whether a statement's resources reach the demo proxy's objects: its prefix, or every object. */
function reachesProxy(statement: Statement): boolean {
  const resources = JSON.stringify(statement.Resource);
  return resources.includes(`/${GO_PROXY_PREFIX}*`) || resources.includes('"/*"');
}

const templates = new Map<Tier, Template>();

beforeAll(() => {
  for (const tier of ['production', 'development'] as const) {
    templates.set(
      tier,
      Template.fromStack(new ApiStack(new App(), `test-${tier}`, { tier, operations: OPERATIONS })),
    );
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
    expect(WEB_ROUTES).toContainEqual(['GET', '/goproxy/{proxy+}']);
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

  it('is read by the web function alone, and written by no role of the stack: only the deploy writes it', () => {
    for (const tier of ['production', 'development'] as const) {
      const reaching = statements(templateOf(tier)).filter(reachesProxy);
      expect(
        reaching.flatMap((statement) => [statement.Action].flat()),
        tier,
      ).toEqual(['s3:GetObject']);
    }
  });
});
