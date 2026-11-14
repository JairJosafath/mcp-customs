// Runs demo/record.ts against the web stub (src/cmd/webstub): the real web
// handler and pages, with a fake store and Checker playing the three demo
// checks, so the recorder's selectors are checked against what the page
// shows. Small budgets per scene make a broken selector fail in seconds.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { chromium } from 'playwright';
import { afterAll, beforeAll, expect, test } from 'vitest';
import { DEFAULT_SERVERS, record, type Options } from './record';

const REVIEWER_KEY = 'stub-key';

let stub: ChildProcess | undefined;
let baseURL = '';

/** The Chromium to drive: Playwright's, or the runner's Chrome. */
function browserPath(): string | undefined {
  const given = process.env['CHROMIUM_PATH'];
  if (given !== undefined && given !== '') {
    return given;
  }
  if (existsSync(chromium.executablePath())) {
    return undefined;
  }
  return ['/usr/bin/google-chrome', '/usr/bin/chromium'].find((p) => existsSync(p));
}

/** Whether Playwright's ffmpeg, which records video, is installed here. */
function canRecordVideo(): boolean {
  const browsers =
    process.env['PLAYWRIGHT_BROWSERS_PATH'] ?? join(homedir(), '.cache', 'ms-playwright');
  return existsSync(browsers) && readdirSync(browsers).some((d) => d.startsWith('ffmpeg-'));
}

/** Options for the stub: no holds, budgets that fail a broken selector fast. */
function stubOptions(): Options {
  const exe = browserPath();
  return {
    baseURL,
    reviewerKey: REVIEWER_KEY,
    holdMs: 0,
    budgetsMs: { weather: 40_000, mail: 30_000, 'mail-next': 40_000 },
    ...DEFAULT_SERVERS,
    ...(exe === undefined ? {} : { executablePath: exe }),
  };
}

beforeAll(async () => {
  const bin = join(mkdtempSync(join(tmpdir(), 'webstub-')), 'webstub');
  execFileSync('go', ['build', '-o', bin, './cmd/webstub'], { cwd: 'src', stdio: 'inherit' });
  const proc = spawn(bin, ['-reviewer-key', REVIEWER_KEY], { stdio: ['ignore', 'ignore', 'pipe'] });
  stub = proc;
  // The stub logs one JSON line naming its URL once it listens.
  for await (const line of createInterface({ input: proc.stderr })) {
    const entry: unknown = JSON.parse(line);
    if (
      typeof entry === 'object' &&
      entry !== null &&
      'url' in entry &&
      typeof entry.url === 'string'
    ) {
      baseURL = entry.url;
      break;
    }
  }
});

afterAll(() => {
  stub?.kill();
});

test('the recorder plays the three scenes against the web page', { timeout: 150_000 }, async () => {
  const scenes = await record(stubOptions());
  expect(scenes.map((s) => [s.scene, s.verdict, s.error])).toEqual([
    ['weather', 'block', undefined],
    ['mail', 'pass', undefined],
    ['mail-next', 'block', undefined],
  ]);
  for (const s of scenes) {
    expect(s.url).toMatch(new RegExp(`^${baseURL}/checks/[\\w-]+$`));
  }
});

test(
  'a scene whose check never settles gives up within its budget, and the next one still plays',
  { timeout: 90_000 },
  async () => {
    const opts = stubOptions();
    const budget = 5_000;
    const video = mkdtempSync(join(tmpdir(), 'record-'));
    const scenes = await record({
      ...opts,
      scenes: ['mail', 'mail-next'],
      mail: { kind: 'npm', ref: 'stall-mcp@1.0.0' },
      budgetsMs: { ...opts.budgetsMs, mail: budget },
      ...(canRecordVideo() ? { videoDir: video } : {}),
    });
    const [stalled, next] = scenes;
    expect(stalled?.verdict).toBe('gave up');
    expect(stalled?.error).toMatch(/^mail: gave up: /);
    // Playwright's own timeouts end the scene, plus at most a moment to throw.
    expect(stalled?.ms).toBeLessThan(budget + 1_500);
    expect(next?.verdict).toBe('block');
    if (canRecordVideo()) {
      expect(existsSync(join(video, 'demo.webm'))).toBe(true);
    }
  },
);

test(
  'a scene that ends at another verdict says which it expected and which it got',
  { timeout: 60_000 },
  async () => {
    const scenes = await record({
      ...stubOptions(),
      scenes: ['weather'],
      // The clean mail server passes, where the weather scene needs a block.
      weather: { kind: 'npm', ref: 'mail-mcp@1.0.0' },
    });
    expect(scenes.map((s) => [s.scene, s.verdict, s.error])).toEqual([
      ['weather', 'gave up', 'scene weather: expected block, got pass'],
    ]);
  },
);
