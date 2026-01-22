import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["./test/configs/browserSetup.ts"],
    environment: "jsdom",
    reporters: "verbose",
    browser: {
      screenshotFailures: false,
      headless: true,
      provider: playwright(),
      enabled: true,
      testerHtmlPath: "./test/test.html",
      instances: [
        { name: "Chrome", browser: "chromium" },
        { name: "Firefox", browser: "firefox" },
        { name: "Safari", browser: "webkit" },
      ],
    },
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
      include: ["src/**/*.ts"],
    },
  },
});
