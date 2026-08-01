/**
 * The canonical public receipts shown on the marketing surfaces.
 *
 * These IDs were scattered across the homepage, the pilot page, the README and
 * the runbooks, which meant regenerating the demo receipts left stale links
 * behind in whichever copy nobody remembered to grep. Every frontend surface
 * now imports from here, so regenerating them is a one-line change.
 *
 * Deliberately NOT labelled `PASS_ID` / `BLOCK_ID`. Which receipt carries which
 * verdict is a property of the artifact, not of this file — the live proof
 * section reads the verdict off each fetched record and lays itself out from
 * that. A constant asserting a verdict is a claim that can go stale the moment
 * the receipts are regenerated against a new policy version.
 *
 * When regenerating (scripts/generate_mainnet_receipts.py), replace both IDs
 * here and update the copies in:
 *   - README.md                       (public verify / proof curl examples)
 *   - docs/trust/README.md            (auditor walkthrough)
 *   - scripts/USECASE_POC_RUNBOOK.md  (demo runbook)
 *   - scripts/usecase_poc_demo.py     (LIVE_MAINNET_RECEIPT)
 *
 * Test fixtures under tests/ and src/lib/__tests__/ also contain receipt IDs.
 * Those are canonicalization vectors whose expected hashes are computed over
 * the exact bytes — do not touch them.
 */
export const CANONICAL_RECEIPT_IDS = [
  "975151ca-834e-4919-9ef6-d9e80803e5f1",
  "65cc4da3-3774-495d-9748-865a7ff98d40",
] as const;

/**
 * A receipt to deep-link to when the surface just needs "a live receipt" and
 * makes no claim about its verdict.
 */
export const SAMPLE_RECEIPT_ID = CANONICAL_RECEIPT_IDS[0];
