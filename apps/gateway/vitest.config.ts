import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      thresholds: {
        statements: 50,
        branches: 44,
        functions: 55,
        lines: 52,
      },
    },
  },
});
