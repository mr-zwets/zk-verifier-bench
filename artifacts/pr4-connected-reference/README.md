# Source4 finite compiled artifact

This package is the artifact side of the source4 BN254/BLS12-381 finite-domain replacement. The source owner is the sibling `../public-source` directory; its `source-manifest-v2.json` is the source-closure seal. `compiled-catalog.json` is the sole owner of compiled program bytes and carries the logical receipt `source4-master-covenant-equivalence-v1`.

The package contains 48 BN254 programs and 86 BLS12-381 programs, compact existing-positive prefix contexts, and a standalone `replay.mjs`. The runner imports a caller-pinned external libauth entry, verifies its hash before import, verifies every program SHA-256 and P2SH hash, reconstructs the unlocking prefix plus the catalog-owned redeem program, and evaluates the synthetic one-input/one-output token-thread covenant under loosened, consensus, and standard BCH 2026 policies.

Each catalog row also carries the canonical ABI/codec boundary: spend parameter declarations, state input/output terms, successor locking bytecode, compiler variant/options, and canonical compile-source SHA. These records are keyed by the unchanged program SHA; no program bytes are duplicated. BLS raw compiler options are preserved only for inputs 79, 81, 83, and 84; all other BLS rows and all BN rows use the recorded `rescheduleStacks` variant.

Run from this directory with an external pinned libauth entry:

```text
node replay.mjs . bn254-positive-context-v2.json /absolute/path/to/@bitauth/libauth/build/index.js replay-receipt-bn-v2.json
node replay.mjs . bls12-381-positive-context-v2.json /absolute/path/to/@bitauth/libauth/build/index.js replay-receipt-bls-v2.json
```

The published positive receipts are 144/144 loosened BN254 and 172/172 loosened BLS12-381. Consensus/standard results are 24/144 and 170/172 respectively because the remaining existing unlocking programs exceed the 10,000-byte policy. These are resource-policy holds, not mathematical failures.

The contexts intentionally retain only prefix bytes, state commitments, token category/capability, and proof/public-input payloads. Historical fixture paths, hashes, benchmark PR/head, and compiler identity are provenance metadata; the historical fixture bodies and old VM/harness are not redistributed. No new proofs, negative or mutation cases, producer/prover/builder execution, cybersecurity testing, or byte optimization is represented.

The theorem disposition is conditional finite-domain correctness only. BN neutral/infinity branches and unrestricted raw-input completeness remain unproved. BLS arbitrary B subgroup admission and external neutral/infinity ABI completeness remain unproved. Setup, SNARK knowledge, zero knowledge, arbitrary keys/circuits, mainnet deployment, and relayability are out of scope.
