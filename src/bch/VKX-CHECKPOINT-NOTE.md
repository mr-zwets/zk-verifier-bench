# Groth16 verifier checkpoint #1 — `vk_x` (public-input aggregation)

`vk_x = IC0 + input0*IC1 + input1*IC2` over BN254/alt_bn128 (G1). This is
`prepareVerificationInput` in `groth16_contract/groth16.cash`, the first
checkpoint of the BCH Groth16 verifier.

## Files
- Contract: `groth16_contract/vkx.cash` (CashScript, compiled by the local
  `feat/reusable-functions` cashc). Fp ops `addFp/subFp/mulFp/negFp/sqrFp/
  inverseFp` are user-defined functions → `OP_DEFINE`/`OP_INVOKE` (6 defines,
  229 invokes). Jacobian point doubling/addition + double-and-add scalar
  multiply are inlined (point values are 3 coords; user functions can't return
  tuples yet). One final modular inverse converts the projective result to
  affine.
- py_ecc reference + vector generator: `groth16_contract/vkx_ref.py`
  (writes `vkx_vectors.json`) and `groth16_contract/vkx_sim.py` (Python port of
  the exact contract algorithm — matches py_ecc bit-for-bit).
- Standalone measurement scripts (this dir):
  - `vkx.ts` — full vk_x contract, op-cost/size/inputsNeeded.
  - `vkx-scalarmult.ts` — the per-scalarMult sub-checkpoint (one scalar
    multiply + one Jacobian add). ACCEPTS the py_ecc-correct result and REJECTS
    a wrong one on the real-shaped BCH 2026 VM.
- Vectors (committed as data, regenerate as below): `vkx-vectors.json`,
  `vkx-scalarmult-vectors.json`.

## Regenerating vectors
1. `cd groth16_contract && python vkx_ref.py`            # py_ecc → vkx_vectors.json
2. `cd cashscript && node packages/cashc/dist/cashc-cli.js \
     ../groth16_contract/vkx.cash -o ../groth16_contract/vkx.json`
3. A short SDK script (cashscript repo, `contractType:'p2s'`) builds the
   locking bytecode for the correct + wrong expected and the unlocking push of
   (input0,input1) reversed, writing `src/bch/vkx-vectors.json`. (The generator
   used `Contract(...).bytecode` for locking and `encodeFunctionArgument` +
   `scriptToBytecode([...].reverse())` for unlocking.)

## Measured numbers (loosened BCH 2026 VM, baseInstructionCost=100)
- Full vk_x: locking 3792 B (≤10 000 ✓), unlocking 10 B, operationCost
  **76 004 958**, arithmeticCost 20 773 232, 522 497 instructions.
- One BCH input budget at the 10 000-B standard unlocking cap = 8 032 800.
- **inputsNeeded = ceil(76 004 958 / 8 032 800) = 10.**  vk_x does NOT fit one
  input. The script size fits; the op-cost is the wall.
- Per-scalarMult sub-checkpoint: locking 2041 B, operationCost 39 407 049
  (≈5 inputs). Two of them ≈ the full 76 M, consistent.

## Becoming harness checkpoint #1
`benchmark.ts` should register vk_x as the first checkpoint by importing the
locking/unlocking vectors here and calling `evaluatePair(createRealVm(), …)`
for the consensus verdict and `createLoosenedVm()` for math + metrics, then
reporting `operationCost` and `ceil(operationCost / standardInputBudget())`.
The `vkx-scalarmult` vectors are the natural per-input chunk unit.

## Chunking sketch (not built)
Because vk_x needs ~10 inputs, a real on-chain verifier splits the two
double-and-add scalar multiplies into per-bit-range steps, carrying the running
Jacobian accumulator (and base point) between inputs as state. State is
committed with `hash256` of the serialized (X,Y,Z) coords in the locking script
of the next input (introspection/covenant), so each input verifies one bit
range and hands off. The final input does the single inverse → affine and the
equality check. One `vkx-scalarmult` step ≈ one chunk's worth of op-cost.

## Status
Full vk_x is correct on the BCH 2026 VM (accepts the py_ecc-correct point, rejects
wrong) at ~76M op-cost (~10 inputs). The `vkx-scalarmult` sub-step is registered as
the per-step chunk unit; the full vk_x can be registered as a multi-input checkpoint
once its vectors are regenerated (note: cashc pushes ctor/unlocking args in reverse
declaration order).
