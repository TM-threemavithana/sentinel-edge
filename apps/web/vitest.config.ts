import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    exclude: ['node_modules/**', 'dist/**', 'e2e/**'],
    setupFiles: ['./test/setup.ts'],
    passWithNoTests: true,
  },
});