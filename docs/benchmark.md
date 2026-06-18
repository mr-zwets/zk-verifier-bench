# Benchmark harness

Goal: compare verifier implementations on a level field, including ones that span
**multiple transactions**. The unit of execution is a **Step** (one locking +
unlocking pair = one transaction's script evaluation). A single-tx verifier is
one Step; a multi-tx verifier (BCH's split-across-transactions approach, or
any covenant that carries state forward) is an ordered list of Steps.

For each implementation the harness:

1. **proves correctness** — the valid run is fully ACCEPTED, invalid runs are
   REJECTED, on the BCH 2026 VM with limits loosened (so even oversized verifiers
   run to completion);
2. **measures cost** — per-step and aggregate locking/unlocking bytes + op-cost;
3. **checks BCH compatibility** — replays the valid run on the **real** BCH 2026
   VM (consensus limits) and reports whether every step actually validates.

Correctness gates the cost numbers. Results are grouped into **separate
leaderboards** by `(proofSystem, structure)`.

The two VMs matter: the *loosened* VM ("BCH without the limits") is used to prove
correctness and measure op-cost; the *real* VM applies the actual consensus
limits, so a single-tx Groth16 verifier like nChain reports **BCH compatible: no**
(its 39,876-byte unlocking alone exceeds the 10,000-byte script-size limit),
while the multi-step demo reports **yes**.

Run it: `pnpm benchmark`.

## The contract

An implementation is an `Implementation` (see `src/harness/types.ts`) whose
`load()` returns a `Scenario`:

```ts
export const myImpl: Implementation = {
  id: 'my-impl',
  name: 'My verifier',
  proofSystem: 'Groth16',     // defines the leaderboard
  field: 'BN254',             // curve or field ("M31", "-", ...)
  structure: 'multi-tx',      // 'single-tx' | 'multi-tx'
  source: 'generated | txid | repo',
  load: async () => ({
    valid: [                  // ordered steps; ALL must be accepted
      { label: 'step 1', lockingBytecode, unlockingBytecode },
      // ...
    ],
    invalid: [ /* optional: full step-lists that MUST fail */ ],
    tamperable: true,         // else: derive invalid runs by bit-flipping each step's witness
  }),
};
```

Register it in `REGISTRY` in `src/harness/benchmark.ts`. A single-tx verifier is
just `valid: [oneStep]`.

- **Correctness.** The valid run must have every step accept. Invalid runs are
  either given explicitly or, if `tamperable`, derived by flipping a bit in each
  step's witness (works when witnesses are push-only data). A run is "rejected"
  if any of its steps fails.
- **Multi-tx note.** The harness evaluates each step's script independently;
  cross-step continuity is whatever each step's script enforces (e.g. the
  hash256 commitment in the BCH demo), not a simulated on-chain covenant.

## Metrics

- **op-cost** is read from the loosened BCH 2026 VM (`src/harness/vm.ts`), so
  large scripts run to completion.
- **BCH compatible** = every step of the valid run validates on the real BCH 2026
  VM (`createRealVm`, consensus limits, non-standard). `no (reason; ~N steps by
  op-cost)` gives the first consensus limit hit (`script-size`, `op-cost`,
  `stack-depth`, ...) and, separately, how many standard inputs the op-cost alone
  implies (`ceil(maxStepOpCost / 8,032,800)`, the budget of one input at the
  10,000-byte unlocking cap). A verifier "runs on BCH" only when every step is
  compatible.

## Current entries

| id | track | state | notes |
|----|-------|-------|-------|
| `nchain` | Groth16 / single-tx | runnable | real mainnet verifier (BLS12-381); BCH-incompatible (script-size; ~64 steps by op-cost) |
| `scrypt-bn256` | Groth16 / single-tx | runnable | real mainnet verifier (BN254, same curve as `BN256.cash`); see `data/scrypt-bn256/SOURCE.md` |
| `bch-multistep-demo` | demo / multi-tx | runnable | hash-chained state across 3 steps; validates the multi-tx path, every step BCH-compatible |

### Not yet registered

- **sCrypt BLS12-381** (Groth16 / single-tx, profile-only): `pnpm fetch:scrypt`,
  then a loader over `data/scrypt`'s extracted script with no valid witness (it
  is a deploy output; we lack a spendable proof). See `docs/scrypt.md`.

Next target: our own BCH BN254 Groth16 verifier as a **multi-tx** entry, so it
can be compared on size and per-step budget fit against these references.
