// Plain ESM (not .ts) so jest can load the config on any Node version.
// Jest only parses a TypeScript config via ts-node (not installed) or
// Node >= 22.6 type stripping — CI runs Node 20, which has neither.
import nextJest from "next/jest.js";

const createJestConfig = nextJest({ dir: "./" });

/** @type {import('jest').Config} */
const config = {
  testEnvironment: "jsdom",
  setupFilesAfterEnv: ["<rootDir>/jest.setup.ts"],
  testMatch: ["<rootDir>/src/**/*.test.{ts,tsx}"],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};

export default createJestConfig(config);
