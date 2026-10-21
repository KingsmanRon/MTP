# Security scanner remediation — 21 October 2026

Scope: the failing full-history Gitleaks, npm audit and production-image Trivy
jobs in security run `39416103016`, default branch commit `5971840`.
Scanner thresholds, coverage and full-history traversal remain unchanged.

## Historical secret alerts

All 168 newly reported occurrences were reviewed against their exact historical
commits, including remote branches. No operational credential was identified in
these occurrences. Only exact commit/path/rule/line fingerprints were added to
`.gitleaksignore`; new occurrences continue to fail. Git history was preserved.

- 150 `signing_key_fingerprint` values in the Mastercard VI proof evidence are
  SHA-256 digests of the Ed25519 verifying public key included in each file.
  Every flagged digest was independently recomputed from those public bytes.
- Seven `delegate_key_thumbprint` and seven `agent_key_thumbprint` values are
  RFC 7638 public P-256 JWK thumbprints. Every value was recomputed from the
  proof fixture's deterministic agent key derived from its published label
  (`scripts/mastercard_vi/fixture.py` in the corresponding historical tree).
  These fields are digests, not bearer credentials or private keys.
- Two occurrences in historical evidence-chain tests are literal grant
  identifiers in calls with a parameter named `key`. Another is the comment
  quoting that call in an older `.gitleaksignore`.
- The private-key alert in historical `api/trust/issuer_registry.py` is a PEM
  header string in `_FORBIDDEN_MARKERS`, used to reject private material. It
  contains no encoded key body.

This classification is limited to the scanner's reported occurrences; it is
not a claim that a repository can never contain an undiscovered secret.

## Dependencies

The frontend stays on Next 15, React 18 and Tailwind 3. Next, sharp and compatible
transitive dependencies are updated. Explicit overrides refresh selector parsing
and the NYC config reader's YAML dependency; the latter uses the retained `load`
API and no longer pulls the vulnerable sprintf implementation through argparse 1.
The widget uses a patched esbuild release. The GitHub Action dependency audit
requires no package change.

`braces@3.0.3` has no upstream fixed release for GHSA-vfj7-8cjw-p6xm. The local
[backport](../../frontend/vendor/braces/README.md) retains upstream MIT source,
adds bounded parser/AST traversal, and is exercised before every frontend test
run. Its private package name makes it distinguishable from unpatched upstream
code; npm audit alone cannot validate this private fork. Its provenance,
maintenance obligations, regression checks and removal condition are documented.
No third-party fork or postinstall patch script is used.

## Image

The Python 3.12/bookworm image previously inherited vulnerable `libpcre2-8-0`
and `perl-base`: 11 fixable high/critical findings. Both builder and runtime now
upgrade inherited Debian packages before installing their required packages.
Non-root execution, health checks, dependency removal and image targets are
preserved. Rebuilds are necessary to incorporate future OS updates; already
running containers do not update themselves.

## Local verification

- Full-history Gitleaks v8.30.1: 512 commits scanned, zero unreviewed findings.
- npm audit: zero vulnerabilities in frontend, widget and GitHub Action.
- Frontend: lint, TypeScript, 85 application tests and 11 dependency security
  tests pass. The latter check deep/cyclic AST rejection, ordinary glob behavior,
  installed consumer resolution, and PNG/WebP/AVIF processing with sharp.
- The original braces package reproduces `RangeError` in all three walkers with
  a 12,000-level AST; the backport refuses it with a controlled `SyntaxError`.
- Widget: typecheck and CJS/ESM/declaration builds pass. GitHub Action: 19 tests
  pass and regenerated dist is unchanged.
- Trivy v0.70.0 on a rebuilt API image: zero fixable high/critical OS or Python
  findings. Installed libpcre2 is `10.42-1+deb12u2`, perl-base is
  `5.36.0-7+deb12u4`. Native asyncpg/psycopg2/nacl/cryptography/uvicorn imports pass
  as UID 999.

The local Docker build uses a temporary Dockerfile with the managed environment's
CA mounted only during pip downloads; the committed Dockerfile is validated by
GitHub CI without that environment-specific trust mount. A scanner pass is a
point-in-time result, not proof that all product security work is complete.
