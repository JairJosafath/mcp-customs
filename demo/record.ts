// Records the demo: drives the web page of a deployed MCP Customs through
// its three scenes and saves the video. Run it with
//   REVIEWER_KEY=... npx tsx demo/record.ts https://<api-id>.execute-api.us-east-2.amazonaws.com
// It waits on what the page shows, never on fixed sleeps. Each scene has
// its own budget, its slots in demo/script.md, summing to 2:50: a scene
// that runs out gives up and the next starts, so the video stays under
// 3 minutes and in step with the narration. Real checks may take minutes:
// --scene <name> records one scene to its own file, to cut together.
// Once a scene has shown what it must, it holds still for --hold-ms so a
// viewer can read it: that pause waits for the viewer, not for the page.
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

/** The scenes, in the order the video plays them. */
export const SCENES = ['weather', 'mail', 'mail-next'] as const;
export type SceneName = (typeof SCENES)[number];

/**
 * Each scene's budget: its slots in demo/script.md (demo/script.test.ts checks
 * they match), summing to 2:50, so the video stays under 3 minutes and
 * the narration stays in step with it.
 */
export const DEFAULT_BUDGETS_MS: Record<SceneName, number> = {
  weather: 75_000,
  mail: 35_000,
  'mail-next': 60_000,
};

export interface Options {
  baseURL: string;
  /** The key Approve and Block take; the field masks it on the video. */
  reviewerKey: string;
  weather: Server;
  mail: Server;
  mailNext: Server;
  /** A re-check the poller already started, to show instead of submitting mailNext. */
  recheckURL?: string;
  /** The scenes to record; all of them when not given. */
  scenes?: readonly SceneName[];
  /** Each scene's budget, DEFAULT_BUDGETS_MS's when not given. */
  budgetsMs?: Partial<Record<SceneName, number>>;
  /** How long each result stays still for the viewer, cut short near the scene's budget. */
  holdMs: number;
  /** Where the video goes; none is recorded without it. */
  videoDir?: string;
  /** The Chromium to drive, when Playwright's own isn't installed. */
  executablePath?: string;
  /** Says what each scene showed, one line each. */
  log?: (line: string) => void;
}

/**
 * What a scene ended on: the check's page, its verdict, how long it took,
 * and, when it gave up, why.
 */
export interface Scene {
  scene: SceneName;
  url: string;
  verdict: 'pass' | 'block' | 'gave up';
  ms: number;
  error?: string;
}

// The demo servers' refs until the deploy names where they are published.
export const DEFAULT_SERVERS = {
  weather: { kind: 'npm', ref: 'weather-mcp@1.0.0' },
  mail: { kind: 'npm', ref: 'mail-mcp@1.0.0' },
  mailNext: { kind: 'npm', ref: 'mail-mcp@1.0.1' },
} as const satisfies Record<string, Server>;

const SETTLED = 'body[data-status="done"], body[data-status="waiting"], body[data-status="failed"]';

/** What each scene does, once its check's page is open, and what it must end on. */
const PLAYS: Record<
  SceneName,
  { want: 'pass' | 'block'; then: (run: Run) => Promise<void>; says: string }
> = {
  weather: {
    want: 'block',
    then: (run) => show(run, finding(run.page, 'canary-left', /base64/)),
    says: 'block, the SSH key seen leaving base64-encoded',
  },
  mail: {
    want: 'pass',
    then: (run) => show(run, run.page.getByRole('heading', { name: 'Install spec' })),
    says: 'pass, with its install spec',
  },
  'mail-next': {
    want: 'block',
    then: (run) => show(run, finding(run.page, 'canary-left', /email/)),
    says: 'block, the planted address seen leaving',
  },
};

/**
 * Plays the scenes and answers what each ended on. A scene that runs out
 * of its budget, or finds the page not as it expects, gives up and says
 * why; the next scene starts on time and the video is still saved.
 */
export async function record(opts: Options): Promise<Scene[]> {
  const log = opts.log ?? ((): void => undefined);
  const names = opts.scenes ?? SCENES;
  const browser = await chromium.launch(
    opts.executablePath === undefined ? {} : { executablePath: opts.executablePath },
  );
  const size = { width: 1280, height: 720 };
  const context = await browser.newContext({
    viewport: size,
    baseURL: opts.baseURL,
    ...(opts.videoDir === undefined ? {} : { recordVideo: { dir: opts.videoDir, size } }),
  });
  const page = await context.newPage();
  const scenes: Scene[] = [];
  try {
    for (const name of names) {
      const started = Date.now();
      const deadline = started + (opts.budgetsMs?.[name] ?? DEFAULT_BUDGETS_MS[name]);
      const run: Run = {
        page,
        reviewerKey: opts.reviewerKey,
        left: () => Math.max(1, deadline - Date.now()),
        // A hold is never longer than holdMs, and leaves the scene's waits
        // its last 2 s.
        hold: (ms = opts.holdMs) =>
          page.waitForTimeout(
            Math.min(ms, opts.holdMs, Math.max(0, deadline - Date.now() - 2_000)),
          ),
      };
      const scene = await play(run, name, opts);
      scenes.push({ ...scene, ms: Date.now() - started });
      log(`${name}: ${scene.error ?? PLAYS[name].says}, ${scene.url}`);
    }
  } finally {
    const video = page.video();
    await context.close();
    await browser.close();
    if (video !== null && opts.videoDir !== undefined) {
      await rename(await video.path(), join(opts.videoDir, videoName(names)));
    }
  }
  return scenes;
}

/** The video's file name: the scene's, when only one is recorded. */
export function videoName(names: readonly SceneName[]): string {
  return names.length === 1 && names[0] !== undefined ? `${names[0]}.webm` : 'demo.webm';
}

/** Plays scene name: submits its server, settles its check and shows its result. */
async function play(run: Run, name: SceneName, opts: Options): Promise<Omit<Scene, 'ms'>> {
  const { want, then } = PLAYS[name];
  try {
    if (name === 'mail-next' && opts.recheckURL !== undefined) {
      await run.page.goto(opts.recheckURL, { timeout: run.left() });
    } else {
      await submit(
        run,
        { weather: opts.weather, mail: opts.mail, 'mail-next': opts.mailNext }[name],
      );
    }
    await settle(run, want);
    await then(run);
    return { scene: name, url: run.page.url(), verdict: want };
  } catch (err: unknown) {
    const why = err instanceof Error ? (err.message.split('\n')[0] ?? '') : String(err);
    return {
      scene: name,
      url: run.page.url(),
      verdict: 'gave up',
      error: `${name}: gave up: ${why}`,
    };
  }
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
async function settle(run: Run, want: 'pass' | 'block'): Promise<void> {
  const { page, left } = run;
  await page.locator(SETTLED).waitFor({ state: 'attached', timeout: left() });
  const status = await page.locator('body').getAttribute('data-status');
  if (status === 'failed') {
    throw new Error(`the check failed, ${page.url()}`);
  }
  if (status === 'waiting') {
    if (want === 'pass') {
      throw new Error('the check waits for a person, but should pass alone');
    }
    await show(run, page.getByRole('heading', { name: 'Waiting for a person' }));
    await page.getByLabel('Reviewer key').fill(run.reviewerKey, { timeout: left() });
    await page.getByRole('button', { name: 'Block' }).click({ timeout: left() });
    await page.locator('body[data-status="done"]').waitFor({ state: 'attached', timeout: left() });
  }
  const verdict = page.locator(`strong.verdict-${want}`);
  await verdict.waitFor({ timeout: left() });
  await show(run, verdict);
  // A re-check started by the poller links the approved version.
  const recheck = page.locator('p.recheck');
  if ((await recheck.count()) > 0) {
    await show(run, recheck);
  }
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
      scene: { type: 'string' },
    },
  });
  const [baseURL] = positionals;
  const reviewerKey = process.env['REVIEWER_KEY'];
  if (baseURL === undefined || reviewerKey === undefined || reviewerKey === '') {
    throw new Error(
      'usage: REVIEWER_KEY=... npx tsx demo/record.ts <base URL> [--out dir] [--hold-ms 4000] ' +
        '[--scene weather|mail|mail-next] [--weather kind:ref] [--mail kind:ref] [--mail-next kind:ref] ' +
        '[--recheck-url url]',
    );
  }
  const holdMs = Number(values['hold-ms']);
  if (!Number.isFinite(holdMs) || holdMs < 0) {
    throw new Error(`--hold-ms takes milliseconds, not ${values['hold-ms']}`);
  }
  const only = SCENES.find((n) => n === values.scene);
  if (values.scene !== undefined && only === undefined) {
    throw new Error(`--scene is one of ${SCENES.join(', ')}, not ${values.scene}`);
  }
  await mkdir(values.out, { recursive: true });
  const scenes = await record({
    baseURL,
    reviewerKey,
    weather: server(values.weather, DEFAULT_SERVERS.weather),
    mail: server(values.mail, DEFAULT_SERVERS.mail),
    mailNext: server(values['mail-next'], DEFAULT_SERVERS.mailNext),
    ...(values['recheck-url'] === undefined ? {} : { recheckURL: values['recheck-url'] }),
    ...(only === undefined ? {} : { scenes: [only] }),
    holdMs,
    videoDir: values.out,
    log: (line) => process.stdout.write(`${line}\n`),
  });
  const video = join(values.out, videoName(scenes.map((sc) => sc.scene)));
  process.stdout.write(`${JSON.stringify(scenes)}\nvideo: ${video}\n`);
  if (scenes.some((sc) => sc.verdict === 'gave up')) {
    process.exitCode = 1;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
