# sCrypt verifiers (BN256 + BLS12-381)

sCrypt built two distinct Groth16 verifier lines, and we obtained both directly
from chain (no compilation needed):

1. **BN256 / alt_bn128 (Jul 2022)**: sCrypt's first Groth16 verifier ("first
   zk-SNARK on Bitcoin"). Same curve as this project's `BN256.cash` (prime
   `0x30644e72...cfd47` =
   `21888242871839275222246405745257275088696311157297823662689037894645226208583`).
   Deployed and spent on **BSV mainnet** in one block. We pulled the verifier
   (~11.7 MB locking script) and its 510-byte proof straight off mainnet and
   registered it as the `scrypt-bn256` benchmark entry. See
   [`data/scrypt-bn256/SOURCE.md`](../data/scrypt-bn256/SOURCE.md).
2. **BLS12-381 (Dec 2022)**: a later, separate verifier. An early unoptimised
   version is on **BSV testnet** as tx `eba3...09dd` (output 0, ~27.5 MB). We
   extracted its opcodes as a profile. See [`data/scrypt/`](../data/scrypt/SOURCE.md).

## scrypt-bn256 (curve-matched, registered, runnable)

The directly comparable BSV reference, on the same curve as our repo. Findings:

- **Functionally correct, BSV-style.** Self-contained (proof in the unlocking, no
  introspection, no signature checks). It accepts the genuine mainnet proof and
  rejects tampered proofs: `pnpm scrypt-bn256:verify`.
- **Uses the BSV OP_RETURN terminator.** The script leaves the verification
  boolean on the stack and halts at an `OP_RETURN`. Post-Genesis BSV (active since
  Feb 2020, so it applied to this Jul 2022 tx) treats that as success iff a single
  non-zero item remains; BCH treats an executed `OP_RETURN` as failure. So the
  harness judges its correctness by the BSV rule (`bsvOpReturnTerminator`) while
  keeping the BCH verdict strict.
- **Not BCH-compatible.** ~11.7 MB locking script (far over the 10,000-byte cap)
  and ~998M op-cost (~125x one input's budget). See `pnpm benchmark`.

## BLS12-381 (data/scrypt, profile-only)

27,549,371 bytes, 22,940,451 instructions, 55 distinct opcodes; every opcode it
uses exists on BCH 2026 (the only non-standard one is `OP_CAT`, which BCH has).
Curve confirmed empirically from the 48/49-byte field-element pushes. It is a
deploy output (verifier with embedded proof), so we keep it as a size/opcode
profile rather than a runnable entry: `pnpm scrypt:extract`.

## scrypt-pairing source: structural reference (not compiled)

sCrypt's BN256 source lives at
[`sCrypt-Inc/scrypt-pairing`](https://github.com/sCrypt-Inc/scrypt-pairing)
(`bn256/zksnark.scrypt`). We did not compile it: we did not need to (the deployed
verifier is on mainnet, above), and a compiled *BSV* opcode count would not map
cleanly to BCH op-cost anyway. It is also legacy `.scrypt` (the `scryptc`
compiler is superseded by `scrypt-ts`), so compiling would be high-effort and
low-ROI. It stays useful as a **structural reference** for our own verifier:

- the full **FQ2 / FQ6 / FQ12 tower** laid out concretely (the part `BN256.cash`
  currently stubs), and
- **projective coordinates** (`CurvePoint{x, y, z, t}`), which avoid the per-step
  modular inversions our affine code does (an op-cost win).

## Pinning `N_steps`

To get `N_steps` in the cost model that actually binds us, measure **our own**
representative chunks (an F_p¹² mul, one Miller-loop iteration, a
final-exponentiation segment) on the BCH 2026 VM the way `src/bch/fp-mul.ts`
measures a single field mul, rather than converting a BSV opcode count.
