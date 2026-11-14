// The file a recording is saved to: --scene <name> writes <name>.webm, so
// scenes recorded one at a time don't overwrite each other; the whole demo
// writes demo.webm.
import { expect, test } from 'vitest';
import { SCENES, videoName } from './record';

test.each(SCENES)('recording only the %s scene writes %s.webm', (scene) => {
  expect(videoName([scene])).toBe(`${scene}.webm`);
});

test('recording every scene, or more than one, writes demo.webm', () => {
  expect(videoName(SCENES)).toBe('demo.webm');
  expect(videoName(['mail', 'mail-next'])).toBe('demo.webm');
});
