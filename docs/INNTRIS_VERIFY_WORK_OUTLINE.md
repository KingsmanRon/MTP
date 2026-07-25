# `inntris-verify` — work outline

Companion to `docs/INNTRIS_WORK_PLAN.md` §12. Written for the session working in
`Inntris/inntris-verify`, which cannot see this repository.

**The governing rule: MTP is upstream.** `verify_pack.py` and `METHODOLOGY.md` are authored
in MTP's `evidence_pack/pack_contents/` and only ever *arrive* here as byte-for-byte
copies — that is step 3 of this repository's own documented release procedure. Nothing in
this outline asks `inntris-verify` to author verifier content, and it must not.

---

## Phase 1 — start now, no MTP dependency

Nothing here waits on MTP. All six items are independent.

### 1.1 Tag `v1.0.0` at current `main`

Free: changes no bytes, triggers no republication cascade. `git tag -l`, the releases API,
and the tags API are all currently empty, so step 5 of the documented procedure ("Tag a
release here") has never once run — `## v1.0.0 — 2026-07-20` in the CHANGELOG is prose.
Tagging makes the CHANGELOG's "auditable through tags" promise true, and it exactly
describes the currently-published `SHA256SUMS`.

**Size: minutes.**

### 1.2 Pin the `## Retired` table shape

`## Retired` is literally `(none)` with no header row, while the rotation policy promises
retired rows carry a retirement date — a sixth column no regex on either side accepts
today. Define the header row, extend the CI key regex to accept both active and retired
shapes, and document which columns are required for each.

Do this now. During a real rotation is the worst possible time to be designing a regex.

**Size: small.**

### 1.3 Validate the README's inlined hashes

`README.md`'s "Integrity of this repository" block inlines both digests verbatim, and
**nothing checks them against `SHA256SUMS`**. It is an existing silent-drift surface, and
publishing a third pinned file (Phase 2) doubles it.

Add to the `integrity` job: assert every `digest  name` line in `SHA256SUMS` appears
verbatim in `README.md`.

**Size: small.**

### 1.4 Correct the release procedure

The `## Update procedure` in `CHANGELOG.md` omits the README block entirely — which is why
1.3 drifted unnoticed. Add it as an explicit step. While editing, note that the procedure's
five steps span two repositories and that MTP's CI goes red between steps 2 and 3 by
design.

**Size: minutes.**

### 1.5 Build the end-to-end verification harness ⭐

**The highest-value item in this outline.** This repository has CI but no test suite — no
pytest, no `tests/`, no runner. Both existing jobs are integrity and import checks, so
**no CI anywhere, in either repository, runs an actual pack verification.** The verifier is
published, hash-pinned and cross-mirrored, and nothing proves it can verify a pack.

Build it:

* add a `tests/` directory and a runner (plain `unittest` keeps the stdlib-only spirit of
  the `fallbacks` job);
* take MTP's frozen v1 fixture — `tests/fixtures/packs/v1/inntris-v1-format-fixture.zip`
  (32 KB) and `PUBKEY.hex` — as **opaque test inputs**. Do not try to generate a pack:
  building one requires MTP's entire `evidence_pack` package plus pynacl, which means
  vendoring the builder rather than writing a test;
* assert the four properties: the pack verifies with the pinned `--pubkey` (exit 0), a
  single flipped byte fails, a wrong pinned key fails, and the run is offline-clean with no
  network;
* wire it into `verify.yml` as a third job.

The fixture's key is a throwaway, deliberately absent from `KEYS.md`. **Keep it that way** —
publishing it in the canonical registry would make synthetic packs verifiable as production
artifacts.

**Size: medium.** Ask the MTP session for the two files.

### 1.6 Draft the registry reconciliation proposal

`KEYS.md` and MTP's `.well-known/inntris-keys.txt` mirror carry **different field sets,
neither a superset of the other**:

| Field | `KEYS.md` | `.well-known` mirror |
|---|---|---|
| key_id, public key, fingerprint, effective date | ✓ | ✓ |
| **scope** | ✓ column 5 | ✗ absent |
| **status** | ✗ structural (`## Active` / `## Retired`) | ✓ field 5 (`active\|retired`) |

Consequences:

* `KEYS.md` states *"Copies elsewhere (inntris.com) mirror it; on any discrepancy, treat
  verification as failed."* The mirror is not a copy, so that check is unenforceable by
  construction. **This is a truth-up item** — either correct the wording or make the claim
  true.
* Manifest v2's `signer_scope` (B1.3) has its canonical source in `KEYS.md` column 5, which
  the mirror drops and the verifier cannot reach.

`KEYS.md` is this repository's file, so the design belongs on this side. Propose one of:
extend the mirror to carry `scope`; extend `KEYS.md` to carry `status` as a column; or
define an explicit, checkable projection between the two shapes. Hand the proposal to MTP —
implementing it touches both repositories.

**Size: small (design only).**

---

## Phase 2 — the sync point, after MTP's Block B

Do not start any of this until MTP hands over. It arrives as one batch.

**Received from MTP:**

* new `verify_pack.py` — manifest v2 `schema_version` branching, `--strict` (E1), required
  checks (E2), honest skip counts (E3), `__version__` + `--version` (E4)
* possibly a new `METHODOLOGY.md`
* the manifest v2 JSON schema — a **new third pinned file** (B1.7)

**Updated here:**

1. `SHA256SUMS` — three entries, not two
2. `.github/workflows/verify.yml` → `expected_files` — the set is compared with exact
   equality, so it must change in lockstep
3. `README.md` — the inlined digest block
4. `.gitattributes` — an LF rule for the new file (safe: the check is a subset check)
5. `CHANGELOG.md` — the entry
6. Tag `v1.1.0`

MTP separately updates its `PINNED_PATHS`, `verify_publication.lock`, and the `.well-known`
mirror. **Six locations total.** Both repositories enforce exact-set equality on their
pinned lists, so a partial update fails CI on one side or the other.

**Add the cross-repo drift check last**, once both sides are in sync. MTP will fetch this
repository's raw `SHA256SUMS` and diff it against its lock — one-directional, no secrets,
no new scope. Adding it earlier leaves MTP red for the entire development window, because
the documented procedure updates MTP's lock (step 2) before the copy lands here (step 3).

---

## Constraints a verifier rewrite must not break

The `fallbacks` job (matrix 3.10 / 3.11 / 3.12) monkeypatches `builtins.__import__` to
block `eth_hash`, `nacl` and `web3`, then asserts exact strings. None of this is obvious
from reading `verify_pack.py`, and all of it will bite an E-block reporting-layer rewrite:

1. `load_keccak256()` and `load_ed25519_verify()` must keep those exact names, stay
   module-level, and keep returning a `(callable, implementation_string)` 2-tuple.
2. The implementation strings are compared with `!=` against the literals `"pure-python"`
   and `"pure-python (RFC 8032)"`. Even `"pure-python (RFC 8032 verify-only)"` fails.
3. `import verify_pack` must stay side-effect-safe — the job imports at module level, so no
   startup self-test may `sys.exit`, and `main()` must stay behind
   `if __name__ == "__main__"`.

Relay these to MTP before it writes the E-block, rather than discovering them at the sync
point.

---

## Do not

* **Author changes to `verify_pack.py` or `METHODOLOGY.md`.** MTP is upstream. Editing here
  produces a merge conflict in an artifact whose entire value is that two repositories agree
  on its bytes.
* **Add the fixture pack to `SHA256SUMS`.** It is a test artifact with no third-party
  consumers; pinning it drags the six-location cascade into every fixture refresh.
* **Publish any test key in `KEYS.md`.** Including the fixture's.
* **Sign anything with `ipk-2026-01`.**

---

## Status of the open questions

Resolved by the audit: integrity is clean (both digests match MTP's lock, fingerprint
recomputes), the repository is public at `Inntris/inntris-verify`, and the CI contracts are
enumerated above.

Still open: whether `https://inntris.com/.well-known/inntris-keys.txt` serves current
bytes. Blocked in **both** sessions — 403 at the agent proxy, a policy denial rather than a
site failure. It needs an unrestricted machine or an allowlist entry. Note that file is
composite, carrying both the key registry and the `SHA256SUMS` digests, so a stale deploy
breaks third-party key pinning and hash cross-checking together.
