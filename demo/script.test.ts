// Checks demo/script.md against the recorder: every section's narration
// fits its slot at 150 words a minute, the slots run back to back from
// 0:00 to no later than 2:50, and each recorder scene's budget is the sum
// of its sections' slots.
import { readFileSync } from 'node:fs';
import { expect, test } from 'vitest';
import { DEFAULT_BUDGETS_MS, SCENES, type SceneName } from './record';

const WORDS_PER_SECOND = 150 / 60;
const LIMIT_S = 170;

interface Section {
  title: string;
  from: number;
  to: number;
  scene: string;
  words: number;
}

const seconds = (mmss: string): number => {
  const [m, s] = mmss.split(':').map(Number);
  return (m ?? 0) * 60 + (s ?? 0);
};

/** The script's sections: each heading's slot and scene, and its narration's words. */
function sections(text: string): Section[] {
  const out: Section[] = [];
  for (const block of text.split(/^## /m).slice(1)) {
    const [heading = '', ...lines] = block.split('\n');
    const m = /^(.*) \((\d+:\d\d)–(\d+:\d\d)\) \[([\w-]+)\]$/.exec(heading);
    if (m === null) {
      throw new Error(`a section heading is "Title (m:ss–m:ss) [scene]", not ${heading}`);
    }
    const narration = lines.filter((l) => l.startsWith('>')).map((l) => l.slice(1));
    out.push({
      title: m[1] ?? '',
      from: seconds(m[2] ?? ''),
      to: seconds(m[3] ?? ''),
      scene: m[4] ?? '',
      words: narration
        .join(' ')
        .split(/\s+/)
        .filter((w) => /\w/.test(w)).length,
    });
  }
  return out;
}

const script = sections(readFileSync('demo/script.md', 'utf8'));

test.each(script)('the narration of "$title" fits its slot', (s) => {
  expect(s.words).toBeGreaterThan(0);
  expect(s.words).toBeLessThanOrEqual(Math.floor((s.to - s.from) * WORDS_PER_SECOND));
});

test('the slots run back to back from 0:00 and end by 2:50', () => {
  expect(script[0]?.from).toBe(0);
  script.slice(1).forEach((s, i) => {
    expect(s.from).toBe(script[i]?.to);
  });
  expect(script.at(-1)?.to).toBeLessThanOrEqual(LIMIT_S);
});

test('each scene budget is the sum of its slots, and they sum to at most 2:50', () => {
  const slots = (name: SceneName): number =>
    script.filter((s) => s.scene === name).reduce((sum, s) => sum + (s.to - s.from), 0);
  for (const name of SCENES) {
    expect(DEFAULT_BUDGETS_MS[name], name).toBe(slots(name) * 1000);
  }
  expect(Object.values(DEFAULT_BUDGETS_MS).reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(
    LIMIT_S * 1000,
  );
  expect(script.every((s) => SCENES.some((n) => n === s.scene))).toBe(true);
});
