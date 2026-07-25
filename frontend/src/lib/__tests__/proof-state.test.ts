import {
  signatureCheckStatus,
  effectiveControlsHashCheckStatus,
  anchorCheckStatus,
  deriveIntegrityStatus,
  isSupportedSchemaVersion,
  checkStatusUiLabel,
  canonicalFingerprintPayload,
  canonicalStringify,
  computeReceiptFingerprint,
  type FingerprintableRecord,
} from "../proof-state";

describe("proof-state helpers (PR1 §1.4)", () => {
  describe("schema version support", () => {
    it("accepts v1, v2 and v3", () => {
      expect(isSupportedSchemaVersion("v1")).toBe(true);
      expect(isSupportedSchemaVersion("v2")).toBe(true);
      // v3 renamed policy_hash to effective_controls_hash. Receipts issued
      // under the older versions stay renderable — a rename must not orphan
      // a receipt someone already holds.
      expect(isSupportedSchemaVersion("v3")).toBe(true);
    });
    it("rejects unknown / null", () => {
      expect(isSupportedSchemaVersion("v4")).toBe(false);
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
      expect(effectiveControlsHashCheckStatus(goodHash)).toBe("verified");
    });
    it("renders NOT APPLICABLE when receipt has no policy bound", () => {
      expect(effectiveControlsHashCheckStatus(null)).toBe("not_applicable");
      expect(effectiveControlsHashCheckStatus(undefined)).toBe("not_applicable");
      expect(effectiveControlsHashCheckStatus("")).toBe("not_applicable");
      expect(checkStatusUiLabel(effectiveControlsHashCheckStatus(null))).toBe("NOT APPLICABLE");
    });
    it("renders FAILED when hash is present but does not validate", () => {
      expect(effectiveControlsHashCheckStatus("not-a-hash")).toBe("failed");
      expect(effectiveControlsHashCheckStatus("a".repeat(63))).toBe("failed");
      expect(effectiveControlsHashCheckStatus("A".repeat(64))).toBe("failed"); // uppercase rejected
    });
    it("never reports NOT INCLUDED for any input", () => {
      const inputs = [null, undefined, "", "a", "z".repeat(64), goodHash];
      for (const v of inputs) {
        const s = effectiveControlsHashCheckStatus(v);
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
    it("is FAILED when the server reports failed receipt integrity", () => {
      expect(anchorCheckStatus(null, null, "failed")).toBe("failed");
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
    it("is PENDING while the anchor is pending and the fingerprint matches", () => {
      expect(
        deriveIntegrityStatus("verified", "verified", "pending", true, "pending_anchor"),
      ).toBe("pending");
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

  /* ---------------------------------------------------------------- */
  /*  Canonical fingerprint parity with the Python backend            */
  /* ---------------------------------------------------------------- */
  //
  // The expected SHA-256 hex values below are produced by the identical
  // canonical form used in api/main.py (the `canonical_wire_timestamp`
  // helper + `fingerprint_payload` dict). If you change the field set,
  // ordering, or timestamp encoding, these tests MUST be updated on both
  // sides together — otherwise every public receipt will report
  // "Fingerprint mismatch — receipt may be tampered".
  describe("canonical fingerprint", () => {
    const v3Record: FingerprintableRecord = {
      action_hash:
        "b913fee92806720122d84285c779582172446c1c1c03645cb865f93fc36b8b5b",
      action_type: "financial_transaction",
      agent_id: "11111111-2222-3333-4444-555555555555",
      audit_id: "d8dd0902-4750-42d2-9516-92bf6362e815",
      effective_controls_hash:
        "b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686",
      timestamp: "2026-04-07T22:22:25Z",
      verdict: "approved",
    };

    it("canonicalStringify produces compact, key-sorted JSON (no spaces)", () => {
      const s = canonicalStringify(canonicalFingerprintPayload(v3Record));
      expect(s).toBe(
        '{"action_hash":"b913fee92806720122d84285c779582172446c1c1c03645cb865f93fc36b8b5b",' +
          '"action_type":"financial_transaction",' +
          '"agent_id":"11111111-2222-3333-4444-555555555555",' +
          '"audit_id":"d8dd0902-4750-42d2-9516-92bf6362e815",' +
          '"effective_controls_hash":"b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686",' +
          '"timestamp":"2026-04-07T22:22:25Z",' +
          '"verdict":"approved"}',
      );
    });

    it("pins SHA-256 of a v2 receipt to the backend-canonical value", async () => {
      const hex = await computeReceiptFingerprint(v3Record);
      expect(hex).toBe(
        "51d1f4afecd9e10a83edc1779ee2a3f70301bf2b951ffe59dc51cdcc28570c0c",
      );
    });

    it("pins SHA-256 of a receipt with a null effective_controls_hash, blocked verdict", async () => {
      const nullHashRecord: FingerprintableRecord = {
        ...v3Record,
        effective_controls_hash: null,
        verdict: "blocked",
      };
      const hex = await computeReceiptFingerprint(nullHashRecord);
      expect(hex).toBe(
        "1aafd28570dd0cf98651172fd6fa23f7040fc0c677da06ba1e76bcd7cd86eac7",
      );
    });

    it("rejects the pre-fix '+00:00' timestamp form (regression guard)", async () => {
      // Before the canonical_wire_timestamp fix, the backend hashed
      // "2026-04-07T22:22:25+00:00" while pydantic v2 shipped
      // "2026-04-07T22:22:25Z" on the wire. Make sure the two strings
      // really do hash to different values so any future regression on
      // either side is caught loudly.
      const legacyRecord: FingerprintableRecord = {
        ...v3Record,
        timestamp: "2026-04-07T22:22:25+00:00",
      };
      const legacyHex = await computeReceiptFingerprint(legacyRecord);
      expect(legacyHex).not.toBe(
        "51d1f4afecd9e10a83edc1779ee2a3f70301bf2b951ffe59dc51cdcc28570c0c",
      );
    });
  });
});
