# Benchmark harness

Goal: compare verifier implementations on a level field, including ones that
span **multiple inputs and transactions**. The unit of execution is a **Step**
(one locking + unlocking pair = one input's script evaluation). A single-tx
verifier is one Step; every other structure is an ordered list of Steps whose
cross-step continuity the harness reproduces faithfully (see *Structures*
below).

For each implementation the harness:

1. **proves correctness** — the valid run is fully ACCEPTED and every invalid
   run REJECTED, on the BCH 2026 VM with limits loosened (so even oversized
   verifiers run to completion);
2. **measures cost** — per-step and aggregate bytes, op-cost, padding, and
   serialized-tx overhead; and
3. **checks deployability** — replays the valid run on the real consensus VM
   (`bchCompatible`) and the standard/relay VM (`fitsBchStandardness`).

Correctness gates the cost numbers. Results are grouped into separate
leaderboards by category (`full` / `partial` / `spec` / `demo`) and curve; the
score is total on-chain bytes.

Run it: `pnpm benchmark`. Positional args are substring filters on the entry id
(`pnpm benchmark genpow`, `pnpm benchmark singleton chunked`); `--demos`
includes demo entries. The JSON exporter (`pnpm benchmark:json`) intentionally
takes no filter: `results.json` and `score-history.json` are complete
artifacts.

## The VMs

Five constructors in `src/harness/vm.ts`:

| VM | used for |
|----|----------|
| `createLoosenedVm` | correctness + op-cost measurement (every ceiling lifted, so oversized entries run to completion) |
| `createRealVm` | consensus limits → the `BCH compatible` verdict |
| `createStandardVm` | mempool-relay policy → the `fitsBchStandardness` verdict |
| `createRealVmSpec` / `createStandardVmSpec` | the proposed **bch-spec** VM (100,000-byte scripts, op-cost budget `(10,000 + len) × 800`); grades `vm: 'bch-spec'` entries |

`no (reason; ~N steps by op-cost)` on the compatibility column gives the first
consensus limit hit (`script-size`, `op-cost`, `stack-depth`, ...) and how many
standard inputs the op-cost alone implies (`ceil(maxStepOpCost / 8,032,800)`,
one input's budget at the 10,000-byte unlocking cap).

## The contract

An implementation is an `Implementation` (see `src/harness/types.ts`) whose
`load()` returns a `Scenario`:

```ts
export const myImpl: Implementation = {
  id: 'my-impl',
  name: 'My verifier',
  proofSystem: 'Groth16',
  field: 'BN254',              // or 'BLS12-381', '-'
  structure: 'multi-tx',       // 'single-tx' | 'multi-tx'
  source: 'generated | txid | repo',
  proofBinding: 'runtime',     // or 'baked' (proof compiled into the chunks)
  vm: 'bch-2026',              // or 'bch-spec' (graded on the spec VM instead)
  load: async () => ({
    valid: [ /* ordered steps; ALL must be accepted */ ],
    extraValidProofs: [ /* distinct proofs vs the SAME locking (generality) */ ],
    worstCaseProof: [ /* dense near-r inputs; op-cost recorded separately */ ],
    invalid: [ /* full step-lists that MUST fail */ ],
    invalidInputs: [ /* off-curve / out-of-subgroup points; MUST fail */ ],
    tamperable: true,          // else: derive invalid runs by bit-flipping witnesses
  }),
};
```

Register it in `REGISTRY` in `src/harness/benchmark.ts`.

- **Correctness.** The valid run must have every step accept. Invalid runs are
  given explicitly and/or, if `tamperable`, derived by flipping a bit in each
  step's witness (works when witnesses are push-only data). A run is "rejected"
  if any of its steps fails.
- **Proof-generality.** `proofBinding: 'runtime'` claims one deployed program
  verifies any proof for its VK; where `extraValidProofs` are supplied the
  harness proves it (N/N distinct proofs accepted against the one fixed
  locking). See `docs/proof-generality.md`.
- **Worst case.** Op-cost is proof-dependent for the chunked verifiers, so the
  committed proof alone understates it; `worstCaseProof` runs dense inputs
  through the same locking and the result is reported as `worstCase`.
- **Input validation.** `invalidInputs` carry well-formed witnesses with
  structurally invalid curve points (off-curve, or on-curve but outside the
  order-r subgroup); EIP-197-style validation must reject them all.

## Structures

A step optionally carries one of three deployment contexts (`Step` in
`types.ts`), and the harness builds the matching synthetic transaction:

- **`covenant`** — token-threading covenant chain: the running state lives in
  the spent/created NFT commitment; one fixed program per chunk, one 1-in/1-out
  token transaction per step. `tokenSafetyEnforced` reports whether the
  covenant actually pins category/capability continuity.
- **`intraTx`** — all chunks are inputs of ONE shared transaction, binding each
  other by reading sibling unlocking bytecode via `OP_INPUTBYTECODE`. State
  passes as raw byte blobs — no 128-byte commitment limit, no hashing.
- **`grouped`** — the hybrid: intra-tx binding within each of a handful of
  standard (<100,000 B) transactions, NFT-commitment hand-off between them.

Bare steps (no context) are evaluated standalone; cross-step continuity is
whatever the scripts enforce (e.g. the hash256 chain in the demo).

## Metrics

Why bytes rank but op-cost is reported with equal weight, and why the same
verifier is graded under three rule sets (consensus, standardness, bch-spec),
is covered in the README's *Why these measures* section: the harness exists to
decompose where the cost comes from — cryptography, VM limits, or relay
policy — not just to rank.

- **score** = total on-chain bytes: locking + unlocking + per-structure
  serialized-tx overhead (`txOverheadBytes` — envelope, outpoints, varints,
  CashToken output prefixes), so single-tx, covenant-chain, and grouped entries
  compare fairly. All-zero padding pushes that exist only to buy op-cost budget
  are counted in the score but surfaced separately (`padBytes`).
- **op-cost** is read from the loosened VM; `worstCase` op-cost from the dense
  proof run. For `vm: 'bch-spec'` entries the budget uses the spec formula.
- **BCH compatible** = every step of the valid run validates on the real VM
  for the entry's target (`bch-2026` or `bch-spec`).
- **standardness** = every step also passes the standard/relay VM. Intra-tx
  bundles are consensus-valid but non-standard; grouped entries are standard.
- **secure packaging** — P2SH20 packaging is flagged (collision-attack
  surface).
- **Checkpoint cost.** Tag a step with `checkpoint: "<label>"` and the
  benchmark reports the cumulative op-cost + bytes to reach it, printed under
  the row — implementations compete per-milestone, not just on the total. See
  `docs/checkpoints.md`.

## Entries

~40 entries are registered across two curves (BN254, BLS12-381), five
structures (singleton, chunked, covenant chain, intra-tx, grouped), the
optimization variants (`-opcode-optimized`, `-genpow`, `-minop`, `-residue`,
GLV vk_x), the `bch-spec` 100 kB builds, the `vkx-*` / `pairing-*` partial
milestones, and the two BSV reference baselines (`nchain`, `scrypt-bn256`).
See the family table in the top-level README; current scores live in
`results.json`.
