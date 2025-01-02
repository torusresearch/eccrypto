import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["./test/configs/browserSetup.ts"],
    environment: "jsdom",
    reporters: "verbose",
    browser: {
      screenshotFailures: false,
      headless: true,
      provider: "playwright",
      name: "chromium",
      enabled: true,
      testerHtmlPath: "./test/test.html",
    },
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
      include: ["src/**/*.ts"],
    },
  },
});
