import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  plugins: [
    {
      name: "cloudflare-workers-test-shim",
      enforce: "pre",
      resolveId(id) {
        if (id === "cloudflare:workers") {
          return fileURLToPath(new URL("./test/cloudflare-workers.ts", import.meta.url));
        }
        return null;
      },
    },
  ],
  test: {
    environment: 'jsdom',
    globals: true,
    exclude: ['node_modules/**', 'dist/**', 'e2e/**'],
    setupFiles: ['./test/setup.ts'],
    passWithNoTests: true,
  },
});
