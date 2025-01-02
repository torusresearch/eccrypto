import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["./test/configs/browserSetup.ts"],
    reporters: "verbose",
    browser: {
      screenshotFailures: false,
      headless: true,
      provider: "playwright",
      name: "firefox",
      enabled: true,
    },
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
      include: ["src/**/*.ts"],
    },
  },
});
