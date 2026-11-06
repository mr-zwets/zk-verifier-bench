# Public raw-Miller to monic transfer v3

Status: **PREPARED_STATIC_NO_MATH_EXECUTION**.

This additive v3 preserves v1 and v2 and fixes their reviewable
plan boundary.  The manifest now declares the exact math source string, pins
the full external dependency closure, and validates package metadata, file
counts, byte totals, complete-tree hashes, and all twelve dependency-edge
hashes before an ordinary library import.  With the dependency root and
Node's explicit `--experimental-import-meta-resolve`, plan and execute modes
resolve exactly the five package-to-package Noble edges against the pinned
package root.  No dynamic import is
performed by `--check-plan`.

The field constants are asserted before import: the BN254 prime `p`, scalar
order `r`, `BN_X`, modulus `X^12-18X^6+82`, and flatten basis
`[0,2,4,1,3,5]`.  After the ordinary library is imported, the checker asserts
both `Fp.ORDER == p` and `Fr.ORDER == r`.

ETA is now derived exactly from the formal basis.  The checker converts the
polynomial element `X` into the ordinary tower, computes `Frobenius^2(X)`,
requires support only at degree one, reads that coefficient, and checks
`eta^6 = 1`, `eta^3 = p-1`, and `eta^2 != 1`.  It does not search over a sampled field
element or import the source ETA constant.

The actual math action remains deliberately unrun pending root review:

```text
node --experimental-import-meta-resolve docs/fixed-preprocessing/check-fixed-preprocessing-public-v3.mjs \
  --check-plan --dependency-root EXTERNAL_PINNED_ROOT
node --experimental-import-meta-resolve docs/fixed-preprocessing/check-fixed-preprocessing-public-v3.mjs \
  --execute --dependency-root EXTERNAL_PINNED_ROOT \
  --noble-entry EXTERNAL_PINNED_ROOT/@noble/curves/esm/bn254.js
```

The seven source/build edges in the locked closure remain separate
build-reproduction evidence and are not claimed as loaded by this checker.
This packet transfers only the public fixed-VK raw-Miller quotient relation.
Current native emission is owned by the current PUB003 owner; VM/compiler,
complete-verifier, arbitrary-VK/advice, qualification, and publication claims
remain outside this packet.
