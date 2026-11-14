/**
 * A Dockerfile read the way the builder reads it, for the tests that check
 * what sandbox/Dockerfile's image holds: comment lines dropped, continued
 * lines joined, one instruction per entry, split into stages at each FROM.
 */

/** One instruction: its keyword, upper case, and the rest of it. */
export interface Instruction {
  readonly keyword: string;
  readonly args: string;
}

/** The instructions of a Dockerfile, in order. */
export function instructions(dockerfile: string): Instruction[] {
  const out: Instruction[] = [];
  let pending = '';
  for (const line of dockerfile.split('\n')) {
    // A comment line is dropped, even inside a continued instruction.
    if (/^\s*#/.test(line)) {
      continue;
    }
    if (pending === '' && line.trim() === '') {
      continue;
    }
    const continued = line.endsWith('\\');
    pending += (continued ? line.slice(0, -1) : line) + ' ';
    if (continued) {
      continue;
    }
    const [, keyword = '', args = ''] = /^\s*(\S+)\s*(.*?)\s*$/.exec(pending) ?? [];
    out.push({ keyword: keyword.toUpperCase(), args: args.replace(/\s+/g, ' ') });
    pending = '';
  }
  return out;
}

/** The instructions of the final stage: those after the last FROM. */
export function finalStage(dockerfile: string): Instruction[] {
  const all = instructions(dockerfile);
  const from = all.map((i) => i.keyword).lastIndexOf('FROM');
  return all.slice(from + 1);
}

/**
 * The commands of the final stage's last RUN, split at `&&`: the step that
 * fails the build when the image lacks what the harness needs.
 */
export function finalChecks(dockerfile: string): string[] {
  const runs = finalStage(dockerfile).filter((i) => i.keyword === 'RUN');
  const last = runs.at(-1)?.args ?? '';
  return last
    .split('&&')
    .map((command) => command.trim())
    .filter((command) => command !== '');
}
