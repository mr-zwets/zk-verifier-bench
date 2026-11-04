# Source5 42-input public key/ABI anchor

This package is a portable, read-only qualification for the public authenticated42 replacement. It consumes two public benchmark roots:

```text
node check.mjs <pr11-benchmark-root> <auth42-benchmark-root>
```

The checker verifies the pinned PR11 pairing vector, original intra-tx/grouped vector hashes, authenticated42 checked-vector hash, independent BN254 VKx arithmetic, and the proof/scalar/state/Miller byte anchors. It performs no VM execution, compilation, producer/prover work, negative testing, network access, or optimization.

The original native42 and grouped42 architectures, lifecycle layouts, and performance/resource claims remain withdrawn. The replacement disposition is limited to the finite-domain mathematical statement implemented by the public authenticated42 checked packet, with its explicit BCH2026, curve, hash-binding, graph-anchor, and runtime statement premises.

The historical source5 current-integration origin is recorded in `certificate.json` only for provenance. Its nonmatching current builder files are deliberately not published as stable source owners.
