# Verifier checkpoints (graded reward)

Building a Groth16 verifier is otherwise all-or-nothing: nothing verifies until
~all of it is correct. To get a dense feedback signal for our BCH verifier, we
grade it against two intermediate "golden" values computed off-chain
(`src/checkpoints/bn254.ts`, via `@noble/curves` BN254). Run `pnpm checkpoints`.

## The two checkpoints

| # | stage | value on the stack | why this point |
|---|-------|--------------------|----------------|
| 1 | **vk_x** = IC[0] + Σ inputsᵢ·ICᵢ₊₁ (public-input MSM on G1) | a **G1 point** (affine x,y in Fp) | earliest & cheapest: only Fp + G1 ops, no tower, no pairing. The ideal first "runs on BCH" milestone. |
| 2 | **Miller-loop → final-exponentiation boundary** | an **Fp12** (the pre-finalExp product e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ)) | the canonical ~halfway split in every pairing library; `finalExponentiate(it) == 1` iff the proof verifies. |

- **Checkpoint #1 is representation-free**: a G1 affine `(x,y)`, so it can be
  asserted *exactly* across implementations. `computeVkX(ic, inputs)`.
- **Checkpoint #2 is tower-basis-dependent**: the Fp12 value is in noble's basis.
  To grade another implementation against the exact bytes, that implementation
  must use the same Fp12 basis; otherwise compare via `finalExponentiate(...) == 1`
  (basis-tolerant). `millerBoundary(vk, proof, vk_x)` → `fp12Hex(...)`.

> **Pairing milestone oracle (checkpoint #2 → #3).** The full pairing checker,
> a deterministic **non-degenerate** vector generator, py_ecc cross-validation,
> and the precise **Fp12-basis finding** (noble's 2-over-3-over-2 tower vs
> py_ecc's flat power basis — same tower *shape*, different serialization) live in
> [`pairing-checker.md`](./pairing-checker.md). Run `pnpm checkpoints:pairing`
> (`gradeCandidate` grades vk_x exactly, the Miller Fp12 exactly if same-basis
> else via finalExp, and the verdict). Vectors: `src/checkpoints/pairing-vectors.json`.

`pnpm checkpoints` validates the math on a constructed BN254 instance: it checks
vk_x against a manual MSM, accepts a valid instance, rejects a tampered public
input, and prints both golden values.

## Grading our BCH verifier

The multi-step BCH design carries state forward as `hash256(state)` in the NFT
commitment, so each step already commits a verifiable intermediate. The reward
falls out: at step k, compute the expected intermediate off-chain (these
functions) and check it against the committed state. Difficulty ramp / checkpoint
order: Fp ops → **vk_x (#1)** → Fp2 → G2 → Fp12 → one Miller iteration → full
Miller → **boundary (#2)** → final exp → full verify.

## Competing on in-between cost

A `Step` can be tagged with `checkpoint: "<label>"`. The benchmark then records
the **cumulative op-cost and on-chain bytes to reach that step**, so two
implementations can be compared not just on the full total but on each milestone
(e.g. "cheapest to reach vk_x"). The breakdown prints under the implementation's
row:

```
bch-multistep-demo  ...  3 steps  ...
    > reach "milestone-1" @ step 1: 1,298 op-cost, 76 B
    > reach "milestone-final" @ step 3: 3,894 op-cost, 228 B
```

Two reward axes therefore stack: **correctness** (does the committed intermediate
match the golden value above) and **cost** (op-cost + bytes to reach it).

## The BSV reference reaches both checkpoints

The real sCrypt BN256 verifier (`scrypt-bn256`, same curve) **reaches and passes
both checkpoints for its on-chain proof**, demonstrated by `pnpm scrypt-bn256:verify`:

- it **ACCEPTs** the genuine mainnet proof — which is only possible if it computed
  a correct vk_x (#1) and reached the Miller→finalExp boundary (#2) with a product
  that finalises to 1; and
- it **REJECTs** tampered proofs (the boundary product no longer finalises to 1).

That is end-to-end evidence that both checkpoints are real stages the deployed
verifier passes through. Reading the BSV verifier's *own* vk_x off its stack and
matching it to a golden additionally requires its **verifying key** (the IC
points), which is embedded as constants in the 11.7 MB locking script — a
separate extraction we have not done. It is not needed to grade our verifier: the
goldens come from `@noble/curves` (the canonical reference), and the BSV ACCEPT
independently confirms the checkpoints are the right stages.
