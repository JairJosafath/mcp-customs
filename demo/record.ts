// Records the demo: drives the web page of a deployed MCP Customs through
// its three scenes and saves the video. Run it with
//   REVIEWER_KEY=... npx tsx demo/record.ts https://<api-id>.execute-api.us-east-2.amazonaws.com
// It waits on what the page shows, never on fixed sleeps, and stops before
// 2:50 so the video stays under 3 minutes. Once a scene has shown what it
// must, it holds still for --hold-ms so a viewer can read it: that pause
// waits for the viewer, not for the page. demo/script.md is the narration.
import { mkdir, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { chromium, type Locator, type Page } from 'playwright';

/** A server to submit: the form's kind and the pinned ref. */
export interface Server {
  kind: string;
  ref: string;
}

export interface Options {
  baseURL: string;
  /** The key Approve and Block take; the field masks it on the video. */
  reviewerKey: string;
  weather: Server;
  mail: Server;
  mailNext: Server;
  /** A re-check already started (by #10's poller) to show instead of submitting mailNext. */
  recheckURL?: string;
  /** How long each result stays still for the viewer, cut short near the budget. */
  holdMs: number;
  /** Where the video goes; none is recorded without it. */
  videoDir?: string;
  /** The Chromium to drive, when Playwright's own isn't installed. */
  executablePath?: string;
  /** Says what each scene showed, one line each. */
  log?: (line: string) => void;
}

/** What a scene ended on: the check's page and its verdict. */
export interface Scene {
  scene: string;
  url: string;
  verdict: string;
}

/** The longest the video may run: 2:50. */
export const BUDGET_MS = 170_000;

// The demo servers' refs until the deploy names where they are published.
export const DEFAULT_SERVERS = {
  weather: { kind: 'npm', ref: 'weather-mcp@1.0.0' },
  mail: { kind: 'npm', ref: 'mail-mcp@1.0.0' },
  mailNext: { kind: 'npm', ref: 'mail-mcp@1.0.1' },
} as const satisfies Record<string, Server>;

const SETTLED = 'body[data-status="done"], body[data-status="waiting"], body[data-status="failed"]';

/** Plays the three scenes and answers what each ended on. */
export async function record(opts: Options): Promise<Scene[]> {
  const log = opts.log ?? ((): void => undefined);
  const browser = await chromium.launch(
    opts.executablePath === undefined ? {} : { executablePath: opts.executablePath },
  );
  const size = { width: 1280, height: 720 };
  const context = await browser.newContext({
    viewport: size,
    baseURL: opts.baseURL,
    ...(opts.videoDir === undefined ? {} : { recordVideo: { dir: opts.videoDir, size } }),
  });
  const deadline = Date.now() + BUDGET_MS;
  const page = await context.newPage();
  const run: Run = {
    page,
    reviewerKey: opts.reviewerKey,
    left: () => Math.max(1, deadline - Date.now()),
    // A hold is never longer than holdMs, and never eats the last 5 s of
    // the budget, which the waits need.
    hold: (ms = opts.holdMs) =>
      page.waitForTimeout(Math.min(ms, opts.holdMs, Math.max(0, deadline - Date.now() - 5_000))),
  };
  const scenes: Scene[] = [];
  try {
    await submit(run, opts.weather);
    scenes.push(await settle(run, 'weather', 'block'));
    await show(run, finding(page, 'canary-left', /base64/));
    log(`weather: block, the SSH key seen leaving base64-encoded, ${page.url()}`);

    await submit(run, opts.mail);
    scenes.push(await settle(run, 'mail v1.0.0', 'pass'));
    await show(run, page.getByRole('heading', { name: 'Install spec' }));
    log(`mail v1.0.0: pass, ${page.url()}`);

    if (opts.recheckURL === undefined) {
      await submit(run, opts.mailNext);
    } else {
      await page.goto(opts.recheckURL, { timeout: run.left() });
    }
    scenes.push(await settle(run, 'mail v1.0.1', 'block'));
    await show(run, finding(page, 'canary-left', /email/));
    log(`mail v1.0.1: block, the planted address seen leaving, ${page.url()}`);
  } finally {
    const video = page.video();
    await context.close();
    await browser.close();
    if (video !== null && opts.videoDir !== undefined) {
      await rename(await video.path(), join(opts.videoDir, 'demo.webm'));
    }
  }
  return scenes;
}

/** A recording under way: its page, the time left, and the viewer's pause. */
interface Run {
  page: Page;
  reviewerKey: string;
  left: () => number;
  hold: (ms?: number) => Promise<void>;
}

/** Submits s through the home page's form and waits for its check's page. */
async function submit({ page, left, hold }: Run, s: Server): Promise<void> {
  await page.goto('/', { timeout: left() });
  await page.getByLabel('Kind').selectOption(s.kind, { timeout: left() });
  await page.getByLabel(/name@version/).fill(s.ref, { timeout: left() });
  await hold(1_000);
  await page.getByRole('button', { name: 'Check it' }).click({ timeout: left() });
  await page.waitForURL(/\/checks\/[\w-]+$/, { timeout: left() });
}

/**
 * Watches the timeline until the check settles. A check waiting for a
 * person is answered with the decision the scene expects (block); then
 * the verdict must be want.
 */
async function settle(run: Run, scene: string, want: 'pass' | 'block'): Promise<Scene> {
  const { page, left } = run;
  await page.locator(SETTLED).waitFor({ state: 'attached', timeout: left() });
  const status = await page.locator('body').getAttribute('data-status');
  if (status === 'failed') {
    throw new Error(`${scene}: the check failed, ${page.url()}`);
  }
  if (status === 'waiting') {
    if (want === 'pass') {
      throw new Error(`${scene}: the check waits for a person, but should pass alone`);
    }
    await show(run, page.getByRole('heading', { name: 'Waiting for a person' }));
    await page.getByLabel('Reviewer key').fill(run.reviewerKey, { timeout: left() });
    await page.getByRole('button', { name: 'Block' }).click({ timeout: left() });
    await page.locator('body[data-status="done"]').waitFor({ state: 'attached', timeout: left() });
  }
  const verdict = page.locator(`strong.verdict-${want}`);
  await verdict.waitFor({ timeout: left() });
  await show(run, verdict);
  return { scene, url: page.url(), verdict: want };
}

/** The report's row of rule whose evidence matches evidence. */
function finding(page: Page, rule: string, evidence: RegExp): Locator {
  return page
    .locator('table tbody tr')
    .filter({ has: page.locator('code', { hasText: new RegExp(`^${rule}$`) }) })
    .filter({ hasText: evidence })
    .first();
}

/** Scrolls to what a scene shows, outlines it, and holds for the viewer. */
async function show(run: Run, target: Locator): Promise<void> {
  await target.scrollIntoViewIfNeeded({ timeout: run.left() });
  // The CDK app's tsconfig has no DOM types, so the element is typed by
  // the one property this uses. Set through CSSOM, which the page's
  // Content-Security-Policy allows.
  await target.evaluate((el: { style: { outline: string; outlineOffset: string } }) => {
    el.style.outline = '4px solid #d93f0b';
    el.style.outlineOffset = '4px';
  });
  await run.hold();
}

function server(value: string | undefined, fallback: Server): Server {
  if (value === undefined) {
    return fallback;
  }
  const [kind, ...ref] = value.split(':');
  if (kind === undefined || ref.length === 0) {
    throw new Error(`a server is kind:ref, such as npm:weather-mcp@1.0.0, not ${value}`);
  }
  return { kind, ref: ref.join(':') };
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      out: { type: 'string', default: 'demo/video' },
      'hold-ms': { type: 'string', default: '4000' },
      weather: { type: 'string' },
      mail: { type: 'string' },
      'mail-next': { type: 'string' },
      'recheck-url': { type: 'string' },
    },
  });
  const [baseURL] = positionals;
  const reviewerKey = process.env['REVIEWER_KEY'];
  if (baseURL === undefined || reviewerKey === undefined || reviewerKey === '') {
    throw new Error(
      'usage: REVIEWER_KEY=... npx tsx demo/record.ts <base URL> [--out dir] [--hold-ms 4000] ' +
        '[--weather kind:ref] [--mail kind:ref] [--mail-next kind:ref] [--recheck-url url]',
    );
  }
  const holdMs = Number(values['hold-ms']);
  if (!Number.isFinite(holdMs) || holdMs < 0) {
    throw new Error(`--hold-ms takes milliseconds, not ${values['hold-ms']}`);
  }
  await mkdir(values.out, { recursive: true });
  const scenes = await record({
    baseURL,
    reviewerKey,
    weather: server(values.weather, DEFAULT_SERVERS.weather),
    mail: server(values.mail, DEFAULT_SERVERS.mail),
    mailNext: server(values['mail-next'], DEFAULT_SERVERS.mailNext),
    ...(values['recheck-url'] === undefined ? {} : { recheckURL: values['recheck-url'] }),
    holdMs,
    videoDir: values.out,
    log: (line) => process.stdout.write(`${line}\n`),
  });
  process.stdout.write(`${JSON.stringify(scenes)}\nvideo: ${join(values.out, 'demo.webm')}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
