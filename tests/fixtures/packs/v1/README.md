# v1-format evidence pack — frozen regression corpus

**This is not a production artifact.** It is signed with a throwaway test key
that is deliberately absent from `KEYS.md` and from
`frontend/public/.well-known/inntris-keys.txt`. A verifier that pins the
published Inntris registry will not accept it.

| | |
|---|---|
| Pack | `inntris-v1-format-fixture.zip` |
| Manifest SHA-256 | `61156f80c49b513e1e76b311ea7a6ee9e067121e0962e468da339fc64c0bbe5c` |
| Container SHA-256 | `4e6bebb091a8408e99227a8fc85dac5ff0ed23c1cd32e32f0f09f4025525d993` |
| Test signing key | `15bb74eba2615927ab0e5d8b247043d61acebbc5868bc2e8fd3f44e228a6758c` (`PUBKEY.hex`) |
| Manifest format | `inntris-evidence-pack` v1.0 |
| Minted | 2026-07-25, against the v1 builder at `HEAD` |

## Why it is committed rather than generated on demand

Manifest v2 (Block B1) breaks the pack format. B1.1 requires that the v2
verifier still verify v1 packs, so a v1 pack has to exist to test against —
and none ever did, in this repository or in `Inntris/inntris-verify`.

The *container* stays reproducible from `METHODOLOGY.md` after the break. The
*signature* does not. Regenerating a signed v1 pack later would mean signing a
synthetic pack with the production key `ipk-2026-01`, which manufactures a
genuine-looking production artifact — exactly the hazard Block A3 exists to
prevent. So the pack was minted while the v1 builder was still `HEAD`, and it
is the artifact of record from here on.

## Verifying it

```bash
python evidence_pack/pack_contents/verify_pack.py \
    tests/fixtures/packs/v1/inntris-v1-format-fixture.zip \
    --pubkey $(cat tests/fixtures/packs/v1/PUBKEY.hex)
```

Exit code 0. `tests/test_v1_pack_compat.py` runs exactly this and is what
fails if manifest v2 breaks backward compatibility.

## Not part of the publication contract

This pack is deliberately **not** listed in `verify_publication.lock` or in
`inntris-verify`'s `SHA256SUMS`. It is a test artifact with no third-party
consumers, and both repositories enforce exact-set equality on their pinned
file lists — adding it would drag a six-location cross-repository
republication into every fixture refresh for no external benefit. Its bytes
are pinned in `tests/test_v1_pack_compat.py` instead. See
`docs/INNTRIS_WORK_PLAN.md` §12.4.

## Expected to fail `--strict`

Once Block E lands, this pack must **fail** `--strict`: it has no
`registered_policy_version`, no `registered_policy_hash`, no nonce, no token
consumption evidence, and its key is not in the registry. Add that assertion
to `tests/test_v1_pack_compat.py` when `--strict` exists — one fixture then
covers B1.1, E1, and E2.

## Regenerating

`scripts/generate_v1_fixture_pack.py` reproduces these exact bytes **while the
v1 builder still exists**. After the manifest v2 cutover it will not, and that
is intended.
