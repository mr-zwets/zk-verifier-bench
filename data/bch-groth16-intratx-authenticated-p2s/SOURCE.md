# BCH Groth16 intra-tx — authenticated P2S dispatcher

## Origin

Derived from `src/bch/groth16-intratx-vectors.json` (the 42-input BN254 Groth16
intra-tx verifier) by `tools/derive-groth16-intratx-authenticated-p2s.mts`.
Unlocking bytecodes are copied byte-identical (stage bodies forward-check
successor unlockings at fixed byte offsets); each 35-byte P2SH32 locking is
replaced by this 44-byte bare (P2S) dispatcher:

```text
OP_DUP OP_HASH256 <hash256(stage body)> OP_EQUALVERIFY
<999> OP_DEFINE <999> OP_INVOKE

hex: 76aa20 <32-byte digest> 88 02e703 89 02e703 8a
```

The stage body stays as the final push of the unlocking — ordinary
authenticated data instead of a P2SH redeem script.

## Authentication

The dispatcher hash256-checks the supplied body against the committed digest
before defining and invoking it. Two invalid runs added beyond the inherited
witness tampers exercise exactly this: one byte flipped inside a stage body,
and two stages' (valid, differing-digest) bodies swapped. The harness rejects
all 8/8 invalid runs (the six inherited verifier failures plus both dispatcher
authentication failures).

## Why P2S

P2SH authentication exists only as the entire top-level pattern of a locking
script — one hash, one body, the body is the whole program. The dispatcher is
ordinary bytecode, so it composes: introspection/covenant checks before or
after the body, several committed digests dispatching between bodies, or an
aggregator contract that references a proof-commit hash instead of carrying
the proof. Bare lockings are relay-standard only up to 201 bytes, so whole
verifier bodies can't be bare lockings — a 44-byte hash-referencing dispatcher
can. Standalone, this entry just emulates P2SH32 at +9 bytes per input and is
redundant as a leaderboard result; it exists as the smallest
harness-measurable prototype of the embeddable pattern.

## Reserved function identifier

The dispatcher defines the body under identifier 999 (the top of OP_DEFINE's
0..999 range) because OP_DEFINE errors on redefinition and the stage bodies
define identifiers densely from 0 upward (currently 0..24). Stage-body codegen
must never define 999; the derivation script asserts this per body.

## Numbers

From the harness (small proof / worst-case proof):

```text
inputs: 42
locking bytes: 1,848 (42 × 44)
unlocking bytes: 329,110
script bytes: 330,958
tx overhead: 1,826
score: 332,784 (+378 vs bch-groth16-intratx = 42 × (44 − 35))
total op-cost: 262,853,837 / 298,160,220
max step op-cost: 7,954,688 / 7,955,222 (budget 8,032,800)
BCH compatible: yes; packaging: secure (bare P2S)
```

Scope: prototype of the authenticated-dispatch primitive only; no covenant,
aggregation, or privacy construction is demonstrated.
