import {
  signatureCheckStatus,
  policyHashCheckStatus,
  anchorCheckStatus,
  deriveIntegrityStatus,
  isSupportedSchemaVersion,
  checkStatusUiLabel,
  anchorDetailLabel,
  integrityDetailLabel,
  proofRollup,
  ANCHOR_CADENCE_MINUTES,
  type CheckStatus,
  canonicalFingerprintPayload,
  canonicalStringify,
  computeReceiptFingerprint,
  type FingerprintableRecord,
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
    it("uses the canonical state vocabulary", () => {
      expect(checkStatusUiLabel("verified")).toBe("VERIFIED");
      expect(checkStatusUiLabel("failed")).toBe("FAILED");
      expect(checkStatusUiLabel("pending")).toBe("PENDING");
      expect(checkStatusUiLabel("not_applicable")).toBe("NOT APPLICABLE");
      expect(checkStatusUiLabel("computing")).toBe("CHECKING");
    });
  });

  /* ---------------------------------------------------------------- */
  /*  P0-2 — the panel must not contradict itself                     */
  /* ---------------------------------------------------------------- */
  //
  // Both live receipts used to render "On-chain anchor — Confirmed on-chain —
  // VERIFIED" directly above "Receipt integrity — Fingerprint matches;
  // awaiting anchoring — PENDING". The panel reported the same receipt as
  // anchored and as awaiting anchoring at the same time, on an artifact shown
  // to auditors. These tests make that pair unrepresentable.

  const ALL_STATUSES: CheckStatus[] = [
    "verified",
    "computing",
    "pending",
    "failed",
    "not_applicable",
  ];
  const SERVER_STATUSES = [null, undefined, "verified", "pending", "failed", "sandbox"];

  describe("panel self-consistency invariant", () => {
    it("never claims a receipt is awaiting anchoring while the anchor is confirmed", () => {
      for (const integrity of ALL_STATUSES) {
        for (const fingerprint of [true, false, null]) {
          for (const server of SERVER_STATUSES) {
            const detail = integrityDetailLabel(integrity, "verified", fingerprint, server);
            expect(detail.toLowerCase()).not.toContain("awaiting");
            expect(detail.toLowerCase()).not.toContain("anchor confirmation expected");
          }
        }
      }
    });

    it("only says the receipt is waiting on an anchor while the anchor is pending", () => {
      // "Waiting" phrasing, in any form the copy might take. A row that merely
      // states a sandbox receipt is not anchored, or that an anchor proof
      // failed, is describing a settled fact rather than claiming a wait.
      const waiting = /awaiting|expected within|in progress|pending anchor/i;
      for (const anchor of ALL_STATUSES) {
        for (const integrity of ALL_STATUSES) {
          for (const server of SERVER_STATUSES) {
            const detail = integrityDetailLabel(integrity, anchor, true, server);
            if (waiting.test(detail)) {
              expect(anchor).toBe("pending");
            }
          }
        }
      }
    });

    it("does not assert the fingerprint matches before it has been computed", () => {
      const detail = integrityDetailLabel("computing", "verified", null, null);
      expect(detail).toBe("Recomputing the receipt fingerprint in your browser");
      expect(detail.toLowerCase()).not.toContain("matches");
    });

    it("a confirmed anchor yields a verified integrity row with a plain detail", () => {
      const integrity = deriveIntegrityStatus("verified", "verified", "verified", true, null);
      expect(integrity).toBe("verified");
      expect(integrityDetailLabel(integrity, "verified", true, null)).toBe(
        "Fingerprint matches record",
      );
    });

    it("propagates the computing state instead of reporting a false pending", () => {
      expect(deriveIntegrityStatus("verified", "verified", "computing", true, null)).toBe(
        "computing",
      );
    });

    it("labels a failed integrity row as failed rather than as still verifying", () => {
      // Regression guard: the old label chain fell through to "Verifying
      // integrity..." whenever integrity failed for a reason other than a
      // fingerprint mismatch.
      const detail = integrityDetailLabel("failed", "verified", true, null);
      expect(detail).toBe("Fingerprint matches, but another proof check did not pass");
    });
  });

  describe("anchor detail label", () => {
    it("explains what an un-anchored receipt is waiting for, and for how long", () => {
      const waiting = anchorDetailLabel("pending", null);
      expect(waiting).toContain(String(ANCHOR_CADENCE_MINUTES));
      expect(waiting.toLowerCase()).toContain("minutes");

      const submitted = anchorDetailLabel("pending", "0xabc");
      expect(submitted).toContain(String(ANCHOR_CADENCE_MINUTES));
      expect(submitted.toLowerCase()).toContain("awaiting confirmation");
    });

    it("says confirmed only when the anchor is verified", () => {
      expect(anchorDetailLabel("verified", "0xabc")).toBe("Confirmed on-chain");
      for (const s of ALL_STATUSES.filter((x) => x !== "verified")) {
        expect(anchorDetailLabel(s, "0xabc")).not.toBe("Confirmed on-chain");
      }
    });
  });

  describe("panel rollup", () => {
    it("reports 4 of 4 for a fully verified receipt", () => {
      const rollup = proofRollup(["verified", "verified", "verified", "verified"]);
      expect(rollup.label).toBe("4 of 4 checks verified");
      expect(rollup.status).toBe("verified");
      expect(rollup.verified).toBe(4);
      expect(rollup.total).toBe(4);
    });

    it("is derived, not hardcoded: a pending anchor shows in the rollup", () => {
      const rollup = proofRollup(["verified", "verified", "pending", "pending"]);
      expect(rollup.status).toBe("pending");
      expect(rollup.label).toBe("2 of 4 checks verified · 2 pending");
    });

    it("a failure dominates a pending", () => {
      const rollup = proofRollup(["verified", "failed", "pending", "failed"]);
      expect(rollup.status).toBe("failed");
      expect(rollup.label).toContain("2 failed");
    });

    it("excludes not-applicable checks from the denominator", () => {
      const rollup = proofRollup(["verified", "verified", "not_applicable", "not_applicable"]);
      expect(rollup.total).toBe(2);
      expect(rollup.label).toBe("2 of 2 checks verified · 2 not applicable");
      expect(rollup.status).toBe("verified");
    });

    it("reports checking while the fingerprint digest is still running", () => {
      const rollup = proofRollup(["verified", "verified", "verified", "computing"]);
      expect(rollup.status).toBe("computing");
      expect(rollup.label).toContain("Checking");
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
    const v2Record: FingerprintableRecord = {
      action_hash:
        "b913fee92806720122d84285c779582172446c1c1c03645cb865f93fc36b8b5b",
      action_type: "financial_transaction",
      agent_id: "11111111-2222-3333-4444-555555555555",
      audit_id: "d8dd0902-4750-42d2-9516-92bf6362e815",
      policy_hash:
        "b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686",
      timestamp: "2026-04-07T22:22:25Z",
      verdict: "approved",
    };

    it("canonicalStringify produces compact, key-sorted JSON (no spaces)", () => {
      const s = canonicalStringify(canonicalFingerprintPayload(v2Record));
      expect(s).toBe(
        '{"action_hash":"b913fee92806720122d84285c779582172446c1c1c03645cb865f93fc36b8b5b",' +
          '"action_type":"financial_transaction",' +
          '"agent_id":"11111111-2222-3333-4444-555555555555",' +
          '"audit_id":"d8dd0902-4750-42d2-9516-92bf6362e815",' +
          '"policy_hash":"b5e687b5bd9878f561f8050e994fbd8632fec823503fa4bd8c047a3e3b14f686",' +
          '"timestamp":"2026-04-07T22:22:25Z",' +
          '"verdict":"approved"}',
      );
    });

    it("pins SHA-256 of a v2 receipt to the backend-canonical value", async () => {
      const hex = await computeReceiptFingerprint(v2Record);
      expect(hex).toBe(
        "2fc29223fb1265448f2da2afd730628d228bcf3b09bb29b7006d5b19ce30bf63",
      );
    });

    it("pins SHA-256 of a v1 receipt (null policy_hash, blocked verdict)", async () => {
      const v1Record: FingerprintableRecord = {
        ...v2Record,
        policy_hash: null,
        verdict: "blocked",
      };
      const hex = await computeReceiptFingerprint(v1Record);
      expect(hex).toBe(
        "7085431bb41614f6d847cddbf0f579d38550caeb77720de27bc78f5faa7f3c7c",
      );
    });

    it("rejects the pre-fix '+00:00' timestamp form (regression guard)", async () => {
      // Before the canonical_wire_timestamp fix, the backend hashed
      // "2026-04-07T22:22:25+00:00" while pydantic v2 shipped
      // "2026-04-07T22:22:25Z" on the wire. Make sure the two strings
      // really do hash to different values so any future regression on
      // either side is caught loudly.
      const legacyRecord: FingerprintableRecord = {
        ...v2Record,
        timestamp: "2026-04-07T22:22:25+00:00",
      };
      const legacyHex = await computeReceiptFingerprint(legacyRecord);
      expect(legacyHex).not.toBe(
        "2fc29223fb1265448f2da2afd730628d228bcf3b09bb29b7006d5b19ce30bf63",
      );
    });
  });
});
