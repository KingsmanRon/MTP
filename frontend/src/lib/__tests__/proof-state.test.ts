import {
  signatureCheckStatus,
  policyHashCheckStatus,
  anchorCheckStatus,
  deriveIntegrityStatus,
  isSupportedSchemaVersion,
  checkStatusUiLabel,
} from "../proof-state";

describe("proof-state helpers (PR1 §1.4)", () => {
  describe("schema version support", () => {
    it("accepts v1 and v2", () => {
      expect(isSupportedSchemaVersion("v1")).toBe(true);
      expect(isSupportedSchemaVersion("v2")).toBe(true);
    });
    it("rejects unknown / null", () => {
      expect(isSupportedSchemaVersion("v3")).toBe(false);
      expect(isSupportedSchemaVersion(null)).toBe(false);
      expect(isSupportedSchemaVersion(undefined)).toBe(false);
      expect(isSupportedSchemaVersion("")).toBe(false);
    });
  });

  describe("signature check", () => {
    it("is VERIFIED when signature_valid is true", () => {
      expect(signatureCheckStatus(true)).toBe("verified");
    });
    it("is FAILED when signature_valid is false (never PENDING)", () => {
      expect(signatureCheckStatus(false)).toBe("failed");
    });
  });

  describe("policy hash check", () => {
    const goodHash = "a".repeat(64);

    it("renders VERIFIED when hash present and valid", () => {
      expect(policyHashCheckStatus(goodHash)).toBe("verified");
    });
    it("renders NOT APPLICABLE when receipt has no policy bound", () => {
      expect(policyHashCheckStatus(null)).toBe("not_applicable");
      expect(policyHashCheckStatus(undefined)).toBe("not_applicable");
      expect(policyHashCheckStatus("")).toBe("not_applicable");
      expect(checkStatusUiLabel(policyHashCheckStatus(null))).toBe("NOT APPLICABLE");
    });
    it("renders FAILED when hash is present but does not validate", () => {
      expect(policyHashCheckStatus("not-a-hash")).toBe("failed");
      expect(policyHashCheckStatus("a".repeat(63))).toBe("failed");
      expect(policyHashCheckStatus("A".repeat(64))).toBe("failed"); // uppercase rejected
    });
    it("never reports NOT INCLUDED for any input", () => {
      const inputs = [null, undefined, "", "a", "z".repeat(64), goodHash];
      for (const v of inputs) {
        const s = policyHashCheckStatus(v);
        expect(s).not.toBe("not_included" as unknown);
        expect(checkStatusUiLabel(s)).not.toBe("NOT INCLUDED");
      }
    });
  });

  describe("anchor check", () => {
    it("is VERIFIED when both tx_hash and block_number present", () => {
      expect(anchorCheckStatus("0xabc", 123)).toBe("verified");
    });
    it("is PENDING when only tx_hash present (legitimate transient state)", () => {
      expect(anchorCheckStatus("0xabc", null)).toBe("pending");
    });
    it("is PENDING when nothing has been submitted yet", () => {
      expect(anchorCheckStatus(null, null)).toBe("pending");
    });
  });

  describe("integrity derivation", () => {
    it("is VERIFIED when all checks pass and fingerprint matches", () => {
      expect(
        deriveIntegrityStatus("verified", "verified", "verified", true, "verified"),
      ).toBe("verified");
    });
    it("is VERIFIED when policy is NOT APPLICABLE but everything else is fine", () => {
      expect(
        deriveIntegrityStatus("verified", "not_applicable", "verified", true, "verified"),
      ).toBe("verified");
    });
    it("is FAILED when fingerprint mismatch", () => {
      expect(
        deriveIntegrityStatus("verified", "verified", "verified", false, "verified"),
      ).toBe("failed");
    });
    it("is FAILED when server reports failed integrity", () => {
      expect(
        deriveIntegrityStatus("verified", "verified", "verified", true, "failed"),
      ).toBe("failed");
    });
    it("is FAILED when any individual check failed", () => {
      expect(
        deriveIntegrityStatus("failed", "verified", "verified", true, "verified"),
      ).toBe("failed");
      expect(
        deriveIntegrityStatus("verified", "failed", "verified", true, "verified"),
      ).toBe("failed");
      expect(
        deriveIntegrityStatus("verified", "verified", "failed", true, "verified"),
      ).toBe("failed");
    });
  });

  describe("UI label", () => {
    it("uses canonical four-state vocabulary", () => {
      expect(checkStatusUiLabel("verified")).toBe("VERIFIED");
      expect(checkStatusUiLabel("failed")).toBe("FAILED");
      expect(checkStatusUiLabel("pending")).toBe("PENDING");
      expect(checkStatusUiLabel("not_applicable")).toBe("NOT APPLICABLE");
    });
  });
});
