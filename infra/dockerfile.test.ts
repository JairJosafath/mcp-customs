import { describe, expect, it } from 'vitest';

import { finalChecks, finalStage, instructions } from './dockerfile';

const MULTI_STAGE = `# syntax=docker/dockerfile:1
FROM golang AS builder
RUN test -f /builder-only \\
    && go version

# The final stage.
FROM base
RUN dnf install -y \\
      # a comment inside the step
      git \\
    && dnf clean all
RUN test -x /usr/bin/setpriv \\
    && iptables --version | grep -q nf_tables
USER root
`;

describe('instructions', () => {
  it('joins continued lines and drops comment lines, even inside a step', () => {
    expect(instructions(MULTI_STAGE)).toEqual([
      { keyword: 'FROM', args: 'golang AS builder' },
      { keyword: 'RUN', args: 'test -f /builder-only && go version' },
      { keyword: 'FROM', args: 'base' },
      { keyword: 'RUN', args: 'dnf install -y git && dnf clean all' },
      {
        keyword: 'RUN',
        args: 'test -x /usr/bin/setpriv && iptables --version | grep -q nf_tables',
      },
      { keyword: 'USER', args: 'root' },
    ]);
  });
});

describe('finalStage', () => {
  it('holds only what follows the last FROM', () => {
    expect(finalStage(MULTI_STAGE).map((i) => i.keyword)).toEqual(['RUN', 'RUN', 'USER']);
  });
});

describe('finalChecks', () => {
  it('splits the final stage’s last RUN into its commands', () => {
    expect(finalChecks(MULTI_STAGE)).toEqual([
      'test -x /usr/bin/setpriv',
      'iptables --version | grep -q nf_tables',
    ]);
  });

  it('finds no checks in a Dockerfile without a RUN after its last FROM', () => {
    expect(finalChecks('FROM a\nRUN go version\nFROM b\nUSER root\n')).toEqual([]);
  });
});
