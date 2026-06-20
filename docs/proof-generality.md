# Proof generality: runtime-general vs instance-specific

A Groth16 verifier on-chain can bind the proof to the program in one of two ways,
and the difference matters more than raw byte counts:

- **runtime-general** — the proof `(A, B, C)` and public inputs arrive *push-only*
  in the unlocking (witness) script at spend time. One deployed locking script
  verifies **any** valid proof for its verifying key (VK). This is how the
  references (`nchain`, `scrypt-bn256`) and our **singleton** verifiers work.
- **instance-specific** — the proof is **baked into the locking program**. Our
  **chunked** verifiers commit each step's carried state (`hash256` of the
  intermediate Miller / final-exp values) into the chunk scripts, so the program is
  specialized to one proof; a different proof needs the chunks regenerated.

Both genuinely verify on-chain (an invalid proof cannot satisfy either). But the
deployment models differ, so their byte totals are not directly comparable — see
"Not every Groth16 is alike" in the [README](../README.md).

The benchmark **proves this distinction empirically** instead of just asserting it.

## How the harness checks it

Each `Implementation` declares a `proofBinding: 'runtime' | 'baked'`
(`src/harness/types.ts`). For verifiers whose trusted setup we control, the
scenario also carries `extraValidProofs: Step[][]` — additional *distinct* valid
proofs to run against the **same** locking. The harness
(`src/harness/benchmark.ts`):

1. runs the main valid proof (proof #0),
2. runs every `extraValidProofs` run against the identical locking bytecode,
3. reports `proofsTested` / `proofsPassed` and a one-line verdict:
   - `runtime` + N/N pass → **"runtime-general — one fixed locking verifies N/N
     distinct proofs"**,
   - `runtime` + only 1 proof available → **"runtime-general by construction"**
     (the references; we cannot mint proofs for a VK whose setup we do not hold),
   - `baked` → **"instance-specific — the proof is baked into the program"** (the
     per-step tamper test already confirms only the baked witness is accepted).

A program that *claimed* runtime-generality but had the proof baked in would be
caught here: it would accept 1 of N. The `generality` block is also emitted into
`results.json` (`src/harness/export-json.ts`) for the website.

## How the extra proofs are minted

The generators are
`groth16_contract/singleton/bn254/gen_multiproof.mjs` (BN254) and
`groth16_contract/singleton/bls12-381/gen_multiproof.mjs` (BLS12-381).

The key idea: **hold the VK fixed so the locking is unchanged, and only vary the
proof.** Because the singleton locking bakes the VK (`alpha, beta, gamma, delta,
IC`) and nothing else, every minted proof reuses the *byte-for-byte same*
`lockingOK` — only the unlocking witness (`A, B, C, in0, in1`) differs. That is
exactly the runtime-general property under test.

We do not need a real circuit or prover, because we know the trusted-setup scalars
(the same ones `src/checkpoints/gen-pairing-vectors.ts` / the BLS `bls_instance.mjs`
used to construct the committed instance). The Groth16 pre-final-exp product is

```
e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta)
  = e(g1,g2) ^ ( -a·b + alpha·beta + vkx·gamma + c·delta )      (scalars mod r)
```

so `finalExponentiate(product) == 1` iff that exponent ≡ 0 (mod r). To mint a fresh
valid proof under the fixed VK we pick new public inputs and a new random `a, b`,
then **solve for the one remaining scalar** in the exponent so the sum is zero:

- **BN254** (`gen_multiproof.mjs`): pick `in0, in1, a, b`; with
  `vkx = ic0 + in0·ic1 + in1·ic2`, solve
  `c = (a·b − alpha·beta − vkx·gamma) · delta⁻¹ (mod r)`.
  Materialize `A = [a]G1, B = [b]G2, C = [c]G1`.
- **BLS12-381** (`gen_multiproof.mjs`): the committed instance fixes `B = 1·G2`, so
  we pick `in0, in1, c` and solve `A` instead:
  `A = alpha·beta + vkx·gamma + c·delta (mod r)`, with `B = G2`, `C = [c]G1`.

Each minted proof is checked **two ways** before it is written:

1. in `@noble/curves` (the oracle) — `pairingBatch(..., true) == Fp12.ONE`, and the
   tampered variant (`in1 + 1`) must *not* verify;
2. on the **loosened BCH 2026 VM**, executed against the actual committed
   `lockingOK` — the witness must be ACCEPTED and the tampered witness REJECTED.

The generators also re-derive the VK from the scalars and assert it equals the
committed VK, so a mismatch (which would mean the locking is for a different VK)
fails loudly rather than silently producing a proof the locking can't verify.

Output (read by the singleton implementations):
`src/bch/groth16-singleton-multiproof-vectors.json` and
`src/bch/groth16-bls12381-singleton-multiproof-vectors.json` — each a shared
`lockingOK` plus a `proofs[]` array (`proofs[0]` is the committed instance;
`proofs[1..]` the minted extras). PRNGs are seeded deterministically, so the output
is reproducible.

## Regenerating

```sh
# from the groth16_contract repo (writes into ../verifier/src/bch/)
node singleton/bn254/gen_multiproof.mjs              # EXTRA_PROOFS=3 by default
node singleton/bls12-381/gen_multiproof.mjs

# then, from the verifier repo
pnpm benchmark          # see the "proof generality" lines
pnpm benchmark:json     # refresh results.json (adds the generality block)
```

Set `EXTRA_PROOFS=N` to mint more/fewer (each extra proof is a full singleton VM
evaluation, ~3.5–4 s, so the default of 3 keeps the benchmark snappy while still
proving N≥2 generality).
