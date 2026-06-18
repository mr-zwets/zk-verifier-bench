# sCrypt BN256 Groth16 verifier

sCrypt's first Groth16 verifier (Jul 2022, "first zk-SNARK on Bitcoin"), over
**BN256 / alt_bn128** — the same curve as this project's `BN256.cash` (prime
`0x30644e72...cfd47` =
`21888242871839275222246405745257275088696311157297823662689037894645226208583`).
Deployed and spent on **BSV mainnet** in one block, so it carries a real proof
and is fully runnable. Registered as `scrypt-bn256`; provenance in
[`data/scrypt-bn256/SOURCE.md`](../data/scrypt-bn256/SOURCE.md).

## Findings

- **Self-contained.** Proof in the unlocking, no introspection, no signature
  checks. Accepts the genuine mainnet proof, rejects tampered proofs:
  `pnpm scrypt-bn256:verify`.
- **BSV OP_RETURN terminator.** It leaves the verification boolean on the stack
  and halts at an `OP_RETURN`. Post-Genesis BSV (active since 4 Feb 2020, so it
  applied to this Jul 2022 tx) treats that as success iff a single non-zero item
  remains; BCH treats an executed `OP_RETURN` as failure. So the harness judges
  correctness by the BSV rule (`bsvOpReturnTerminator`) and keeps the BCH verdict
  strict.
- **Not BCH-compatible.** ~11.7 MB locking script (far over the 10,000-byte cap)
  and ~998M op-cost (~125x one input's budget). See `pnpm benchmark`.

## sCrypt's BLS12-381 line (not included)

sCrypt later (Dec 2022) built a separate BLS12-381 verifier. Its testnet deploy
(tx `eba3...09dd` vout 0, ~27.5 MB) was **never spent** (confirmed via
WhatsOnChain `/{vout}/spent`: 404 = unspent), so no proof exists on-chain and it
cannot be run as a success case (an empty unlock underflows; it needs ~12 proof
elements from a spender that does not exist). We do not carry it: the BLS12-381
curve is already a runnable entry via `nchain` (mainnet, spent with a real proof).

## scrypt-pairing source: structural reference (not compiled)

sCrypt's BN256 source lives at
[`sCrypt-Inc/scrypt-pairing`](https://github.com/sCrypt-Inc/scrypt-pairing)
(`bn256/zksnark.scrypt`). We did not compile it: the deployed verifier is already
on mainnet (above), a compiled *BSV* opcode count would not map cleanly to BCH
op-cost, and it is legacy `.scrypt` (the `scryptc` compiler is superseded by
`scrypt-ts`). It stays useful as a **structural reference** for our own verifier:

- the full **FQ2 / FQ6 / FQ12 tower** laid out concretely (the part `BN256.cash`
  currently stubs), and
- **projective coordinates** (`CurvePoint{x, y, z, t}`), which avoid the per-step
  modular inversions our affine code does (an op-cost win).

## Pinning `N_steps`

Measure **our own** representative chunks (an F_p¹² mul, one Miller-loop
iteration, a final-exponentiation segment) on the BCH 2026 VM the way
`src/bch/fp-mul.ts` measures a single field mul, rather than converting a BSV
opcode count.
