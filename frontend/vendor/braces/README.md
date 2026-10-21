# Inntris temporary braces security backport

This private, local dependency is upstream `braces@3.0.3` (MIT, license and
attribution retained) with bounded parser nesting and iterative AST validation
before the recursive compile, expand and stringify walkers. It addresses
[GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm).
Upstream has no published patched version as of 21 October 2026.

Source npm tarball SHA-512 (base64):
`yQbXgO/OSZVD2IsiLlro+7Hf6Q18EJrKSEsdoMzKePKXct3gvD8oLcOQdIzGupr5Fj+EDe8gO/lxc1BzfMpxvA==`

The guard follows the proposed upstream [PR #88](https://github.com/micromatch/braces/pull/88),
commit `a795ee83ecd011131b2d618fe754ac5a8e124dae`, with explanatory comments.
This is an Inntris-maintained backport, not an upstream release or certification.
Only `lib/parse.js`, `lib/compile.js`, `lib/expand.js`, `lib/stringify.js` and
new `lib/assert-depth.js` change runtime behavior. The package manifest uses a
private name/version and omits upstream development tools.

Nesting over 128 or cyclic ASTs raises `SyntaxError` before recursion; normal
patterns and shared acyclic nodes retain existing behavior. Callers must handle
invalid-input errors. This does not promise bounded memory for every possible
brace expansion. The dependency is used by frontend build/watch tooling.

`npm test` runs regressions and verifies both micromatch and chokidar resolve
this implementation. The override is local so no unreviewed third-party fork
or install-time patch script executes. npm audit does not know advisories for
this private package: maintainers must continue reviewing upstream braces
advisories manually. Remove the backport and override once a compatible upstream
release fixes this issue; retain the regression tests when doing so.
