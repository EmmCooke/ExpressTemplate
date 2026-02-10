import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    root: "..",
    include: ["tests/**/*.test.ts"],
    setupFiles: ["tests/helpers/setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/types/**", "src/server.ts"],
    },
  },
});
