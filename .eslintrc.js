require("@rushstack/eslint-patch/modern-module-resolution");

module.exports = {
  root: true,
  extends: ["@toruslabs/eslint-config-typescript"],
  parser: "@typescript-eslint/parser",
  ignorePatterns: ["*.config.js", ".eslintrc.js"],
  parserOptions: {
    sourceType: "module",
    ecmaVersion: 11,
    project: "./tsconfig.json",
  },
  globals: {
    document: true,
    fetch: true,
    jest: true,
    it: true,
    beforeEach: true,
    afterEach: true,
    describe: true,
  },
};
