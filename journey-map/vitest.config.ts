import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: (!!process.debugPort) ? 0 : 5000,
  },
});
