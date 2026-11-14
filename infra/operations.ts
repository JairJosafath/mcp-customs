// What this Container promises however it is deployed: its `spec.operations`
// in theos, with the factory's defaults for what the block leaves out.
// The factory renders this file from the block; a change to the block is
// written here, never the other way, so the two say the same. The stacks
// read it at synth, and the Standard's test checks them against it. The
// tier is not here: it is the deploy target's (`cdk synth -c tier=production`).
import type { Operations } from './standard';

export const OPERATIONS: Operations = Object.freeze({
  backups: Object.freeze({
    retentionDays: 35,
    copyToRegion: '',
  }),
  recovery: Object.freeze({
    rpo: '1h',
    rto: '4h',
  }),
  alerts: Object.freeze({
    email: '',
  }),
});
