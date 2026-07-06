# Inntris Evidence Pack — Verification Methodology

This document defines, exactly and exhaustively, how the evidence in this
pack is constructed, hashed, signed, and anchored — and therefore how to
verify it **without trusting Inntris**. Every rule here is checkable by the
`verify_pack.py` script shipped alongside this file, using only the Python
standard library and, optionally, a Base RPC node of your choosing.

If anything in this pack cannot be verified by the procedure below, treat it
as unverified. The pack asks you to check the math, not to take our word.

---

## 1. Pack layout

| Path | Content |
| --- | --- |
| `manifest.json` | **The attested object.** JCS-canonical JSON listing every other file's SHA-256 |
| `manifest.sig.json` | Ed25519 signature over the exact bytes of `manifest.json` |
| `METHODOLOGY.md` | This document (covered by the manifest) |
| `verify_pack.py` | Standalone offline verifier (covered by the manifest) |
| `custody_log.json` | Chain-of-custody events for every evidence file (covered) |
| `receipts/<audit_id>.json` | Public verification receipts, one per action (covered) |
| `proofs/<audit_id>.json` | Merkle inclusion proofs for anchored receipts (covered) |
| `evidence/...` | Source artifacts: policy exports, logs, screenshots, etc. (covered) |

Every file except `manifest.json` and `manifest.sig.json` is listed in the
manifest. A file present in the archive but absent from the manifest — or
vice versa — is a verification failure, not a warning.

## 2. What is attested: the manifest, not the container

The object Inntris signs — and the hash that should be quoted, compared, or
anchored — is the **manifest**, not the ZIP:

```
pack_hash = SHA-256( bytes of manifest.json )
```

`manifest.json` is serialized with RFC 8785 (JSON Canonicalization Scheme),
so the same logical manifest always yields the same bytes and the same hash.
The ZIP container is mere packaging: you may re-compress, extract, or
re-archive the files without affecting what was attested, because
verification re-hashes the *files* against the manifest and re-checks the
signature over the *manifest bytes*.

The container is nevertheless built deterministically (section 3) so that
the archive bytes themselves are also reproducible. But if a container hash
and the manifest disagree, the manifest — the signed object — governs.

## 3. Deterministic container construction

Rebuilding a pack from identical inputs must yield a byte-identical archive.
The builder pins every source of ZIP nondeterminism:

1. **Entry order:** entries appear sorted by arcname (bytewise UTF-8).
2. **Timestamps:** every entry carries one fixed timestamp — the
   `SOURCE_DATE_EPOCH` environment variable (seconds since the Unix epoch,
   the reproducible-builds.org convention) if set, otherwise the pack's
   declared `snapshot_time`, clamped to the ZIP minimum of 1980-01-01 UTC.
3. **Compression:** DEFLATE, level 9, for every entry.
4. **Metadata:** creator system 3 (Unix), external attributes 0644 regular
   file, no extra fields, no directory entries, UTF-8 arcnames.
5. **JSON payloads:** every JSON file written by the builder
   (`manifest.json`, `manifest.sig.json`, `custody_log.json`, receipts,
   proofs) is serialized as RFC 8785 (JCS) canonical bytes.

“Identical inputs” means: the same file contents, the same arcnames, the
same `snapshot_time` / `SOURCE_DATE_EPOCH`, and the same Ed25519 signing key
(Ed25519 is deterministic — no per-signature randomness).

## 4. Hash scheme

| Layer | Hash | Rationale |
| --- | --- | --- |
| File leaves (`manifest.files[].sha256`) | SHA-256 over raw file bytes | Universally available; auditors can re-check with `sha256sum` |
| Manifest / pack hash | SHA-256 over JCS bytes of `manifest.json` | Canonical serialization removes JSON ambiguity |
| Receipt fingerprint | SHA-256 over the seven-field canonical payload (section 5) | Matches the server contract in `docs/RECEIPT_CANONICALIZATION.md` |
| Action hash (Merkle leaf) | SHA-256 over the canonical action signing payload | Computed at decision time; signed by the agent key |
| Merkle interior nodes | keccak256(left ‖ right) | Must match `AnchorRegistry.sol`, which verifies with Solidity `keccak256` |
| Manifest signature | Ed25519 over `manifest.json` bytes | Deterministic signatures preserve reproducibility |

Two hash functions coexist by design: SHA-256 where auditors need commodity
tooling, keccak256 where the on-chain contract dictates the algorithm. A
Merkle tree is built by pairing nodes left-to-right, duplicating the last
node when a level has odd length, and hashing `keccak256(left ‖ right)`
upward to a single root.

## 5. Receipt canonicalization contract

A receipt's `receipt_fingerprint` is SHA-256 over exactly this JSON object,
serialized with lexicographically sorted keys and separators `(",", ":")`
(no whitespace), UTF-8 encoded:

```json
{"action_hash": "...", "action_type": "...", "agent_id": "...",
 "audit_id": "...", "policy_hash": "... or null",
 "timestamp": "ISO 8601 with Z suffix", "verdict": "..."}
```

Rules that bite:

- `timestamp` uses the `Z` suffix, never `+00:00`.
- `policy_hash` is `null` for v1 receipts; non-null in v2 means the policy
  hash is bound into the fingerprint.
- The agent's Ed25519 `signature` is **excluded** from the fingerprint; it is
  verified separately, over the raw 32 bytes of `action_hash`, against the
  `public_key_b64` in the receipt.

## 6. Chain of custody

Custody is checked at every hop, never asserted once and assumed:

1. **Ingest:** when a source artifact enters custody it is hashed
   (SHA-256) and the hash, size, and UTC ingest time are recorded.
2. **Retrieval re-verification:** when this pack was assembled, every
   artifact was read back from storage, **re-hashed, and compared against
   its ingest-time hash**. Any mismatch hard-fails the build — a pack cannot
   be produced containing a file whose current bytes differ from the hash
   recorded at ingest.
3. **Evidence of the check:** each re-verification is logged as its own
   event (`hash_reverified_at_retrieval`) in `custody_log.json`, which is
   itself covered by the signed manifest. You can see that the check
   happened and what it compared, rather than trusting that it did.

## 7. Signature and key verification

`manifest.sig.json` contains the Ed25519 signature over the exact stored
bytes of `manifest.json`, plus the public key and its SHA-256 fingerprint.

A key embedded in the pack proves **internal consistency only** — a forger
who rebuilt the whole pack could embed their own key. To close the loop,
compare the key (or its fingerprint) against a channel Inntris does not
control at verification time: the key published in the Inntris repository
history, prior correspondence, or a previously received pack. Pass the
published key to the verifier with `--pubkey` to enforce the match.

## 8. What the on-chain anchor attests — and what it does not

Each anchored batch is a Merkle root submitted to the `AnchorRegistry`
contract on Base (chain id 8453). The root, batch id, log count, submission
timestamp, and submitter address are readable by anyone via
`getBatch(bytes32)`.

**The anchor attests:**

- **Inclusion:** the receipt's `action_hash` is a leaf of a Merkle tree
  whose root was submitted to the contract (the inclusion proof in
  `proofs/` reconstructs the path).
- **Existence by a point in time:** the leaf existed no later than the
  block in which the root was accepted.
- **Immutability since anchoring:** any post-anchoring change to the
  receipt's bound fields changes `action_hash` and breaks the proof.
- **Submitter identity:** which address submitted the batch.

**The anchor does NOT attest:**

- that the action's payload is true, lawful, or well-intentioned — only
  that these exact bytes were recorded;
- that the policy applied was appropriate — only which policy hash was
  bound;
- **completeness** — that every action an agent performed was captured. An
  action executed outside the Inntris boundary produces no receipt at all;
  absence of a receipt is not evidence of absence of an action;
- wall-clock accuracy of the receipt's `timestamp` beyond the anchoring
  block's upper bound;
- the real-world identity of the agent operator — only possession of the
  signing key;
- anything about receipts whose batches have not (yet) been anchored.

## 9. Verification procedure

Fully offline (no network at all):

```bash
python verify_pack.py /path/to/pack.zip --pubkey <published-key-hex-or-b64>
```

This checks, in order: the Ed25519 signature over `manifest.json`; every
file's SHA-256 against the signed manifest (both directions — nothing
missing, nothing smuggled); every receipt's fingerprint against the
canonical contract; every agent signature over its action hash; and every
Merkle inclusion proof rebuilt leaf-to-root with keccak256.

With one added network call — to a Base RPC node **you** choose, not to
Inntris:

```bash
python verify_pack.py /path/to/pack.zip \
    --pubkey <published-key> \
    --rpc https://base-rpc.publicnode.com
```

This additionally calls `AnchorRegistry.getBatch(root)` for every anchored
root in the pack and fails unless the contract reports a nonzero batch.

The verifier needs only the Python 3.10+ standard library. If `pynacl` or
`eth-hash` are installed they are used for speed; otherwise built-in
pure-Python Ed25519 and Keccak-256 implementations (self-tested at startup)
are used. Exit code 0 means every attempted check passed; any failure exits
nonzero and lists the failing checks.

## 10. Reproducing the pack

Given the same input files, receipts, `snapshot_time`, and signing key, the
builder (`evidence_pack/` in the Inntris repository, commit recorded in
`manifest.inntris_commit`) reproduces this archive byte-for-byte:

```bash
SOURCE_DATE_EPOCH=<epoch> python scripts/build_evidence_pack.py build ...
sha256sum pack.zip   # matches the distributed archive
```

A reproduction that matches the manifest hash but not the container hash
indicates a packaging difference only (section 2); the attested evidence is
unchanged. A manifest-hash difference means the inputs differ — diff
`manifest.json` to locate exactly which file, field, or timestamp changed.
