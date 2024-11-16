// eslint-disable-next-line import/no-extraneous-dependencies
import { nodePolyfills } from "vite-plugin-node-polyfills";
// eslint-disable-next-line import/no-unresolved
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [nodePolyfills({ include: ["buffer"] })],
  test: {
    reporters: "verbose",
    browser: {
      screenshotFailures: false,
      headless: true,
      provider: "playwright",
      name: "chromium",
      enabled: true,
    },
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
    },
  },
});
