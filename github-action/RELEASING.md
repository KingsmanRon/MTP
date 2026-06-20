# Releasing the Inntris CI Guard action

The action source lives in `github-action/index.js`. Its dependencies (js-yaml)
are bundled into `github-action/dist/index.js` with
[`@vercel/ncc`](https://github.com/vercel/ncc); `action.yml` points GitHub at
that bundle. The bundle is committed, so consumers run a single self-contained
file with no install step.

## Build & test locally

```bash
cd github-action
npm ci
npm test          # node:test unit + golden-vector tests
npm run build     # rebuild dist/index.js
```

CI (`.github/workflows/ci.yml`, job `action`) runs the tests and then rebuilds
and `git diff --exit-code -- dist/`, so a source change **cannot merge without
its rebuilt bundle**. If CI fails on a stale bundle, run `npm --prefix
github-action run build` and commit `dist/`.

## Cutting a release

1. Land your change on the default branch, including the rebuilt `dist/`.
2. Tag a semver release and push it:

   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```

3. `.github/workflows/release-action.yml` then:
   - re-runs the tests,
   - verifies the bundle is current at the tagged commit,
   - moves the **floating major tag** (`v1` → `v1.2.3`) so consumers pinning
     `@v1` pick up the release,
   - publishes auto-generated release notes.

## How consumers reference it

`action.yml` is at the repo root, so the action resolves three ways:

```yaml
# Same repo (dogfood): no tag/publish needed -- run the local action.
- uses: ./

# External repo, floating major (gets patches). This monorepo works today
# because action.yml is at its root:
- uses: KingsmanRon/MTP@v1

# Hardened (supply-chain): pin the exact commit, note the version.
- uses: KingsmanRon/MTP@<full-sha>    # v1.2.3
```

The admin **workflow generator** emits the reference from
`NEXT_PUBLIC_INNTRIS_ACTION_REF` (default `inntris/inntris-verify@v1`). Set that
env var on the frontend deployment to whatever you actually publish — the
monorepo (`KingsmanRon/MTP@v1`), a dedicated mirror, or a pinned SHA — so the
generated `uses:` always resolves.

**SHA-pinning** is recommended for regulated consumers: a commit SHA is
immutable, whereas `@v1` moves.

### Publishing under a dedicated `inntris/inntris-verify` repo (optional)

To expose the action under the friendly `inntris/inntris-verify@v1` name used in
the docs/generator, mirror `action.yml`, `dist/`, and this README to that repo
on each release (e.g. a `peaceiris/actions-gh-pages`-style sync step or a
`git subtree push` using a deploy key stored as a secret). The dedicated repo
should contain **only** the built action, not the monorepo, so partners pull a
minimal, auditable artifact. Until that mirror exists, point the generated
workflow at `<owner>/<repo>@v1`.
