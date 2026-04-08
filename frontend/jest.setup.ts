import "@testing-library/jest-dom";

// jsdom (Jest 30) does not ship TextEncoder/TextDecoder or a WebCrypto
// implementation. The receipt fingerprint tests in proof-state.test.ts need
// both, so polyfill them from Node's built-ins.
import { TextEncoder, TextDecoder } from "node:util";
import { webcrypto } from "node:crypto";

if (typeof globalThis.TextEncoder === "undefined") {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).TextEncoder = TextEncoder;
}
if (typeof globalThis.TextDecoder === "undefined") {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).TextDecoder = TextDecoder;
}
if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
  // jsdom ships a partial `crypto` object without `subtle`; overwrite it.
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
    writable: true,
  });
}
