import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The function's tests are Go's (`go test`); vitest runs the stacks'
    // and the demo recorder's.
    include: ['infra/**/*.test.ts', 'demo/**/*.test.ts'],
    // An infra test synthesizes its stacks for both tiers in beforeAll,
    // building the function with go build: seconds, and a minute or more
    // with a cold build cache on a small runner, not the default 10 s.
    hookTimeout: 180_000,
    testTimeout: 60_000,
  },
});
