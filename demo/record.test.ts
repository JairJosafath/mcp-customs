// Runs demo/record.ts against the web stub (src/cmd/webstub): the real web
// handler and pages, with a fake store and Checker playing the three demo
// checks, so the recorder's selectors are checked against what the page
// shows. No video: that needs ffmpeg, which only a recording machine has.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { chromium } from 'playwright';
import { afterAll, beforeAll, expect, test } from 'vitest';
import { DEFAULT_SERVERS, record } from './record';

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

test('the recorder plays the three scenes against the web page', { timeout: 180_000 }, async () => {
  const exe = browserPath();
  const scenes = await record({
    baseURL,
    reviewerKey: REVIEWER_KEY,
    holdMs: 0,
    ...DEFAULT_SERVERS,
    ...(exe === undefined ? {} : { executablePath: exe }),
  });
  expect(scenes.map((s) => [s.scene, s.verdict])).toEqual([
    ['weather', 'block'],
    ['mail v1.0.0', 'pass'],
    ['mail v1.0.1', 'block'],
  ]);
  for (const s of scenes) {
    expect(s.url).toMatch(new RegExp(`^${baseURL}/checks/[\\w-]+$`));
  }
});
