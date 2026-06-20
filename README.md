# zk-verifier-bench

A benchmark harness for **zero-knowledge-proof verifiers on the Bitcoin Cash VM**.
It takes a verifier implementation (its opcode program + a curve/field and proof
vectors), and on the BCH 2026 virtual machine (libauth) it:

1. **proves correctness** — the valid proof is ACCEPTED and invalid proofs are
   REJECTED;
2. **measures cost** — locking/unlocking byte size and op-cost; and
3. **checks BCH compatibility** — replays the run on the *real* BCH 2026 VM
   (consensus limits) to see whether it actually validates.

Implementations can be **single-transaction** or **multi-transaction** (state
carried across steps, the way BCH must split heavy work). Results are grouped
into separate leaderboards by proof system and structure.

## Why

BSV runs a Groth16 verifier in one ~0.5 MB transaction because it removed
Bitcoin's script/transaction limits. BCH kept those limits, so the same verifier
cannot run in a single transaction and must be split across a chain of
transactions. This harness quantifies that: it runs the real on-chain BSV
verifiers, shows they are **not BCH-compatible** as-is, and provides the rails to
build and benchmark BCH-native (multi-step) verifiers against them. It is the
experimental companion to the comparison writeup in the `groth16_contract` repo.

## Quick start

```
pnpm install
pnpm fetch:nchain     # download the real nChain verifier + proof from WhatsOnChain
pnpm benchmark        # run the leaderboards
```

Current output:

```
### Groth16  [single-tx]
nchain               BLS12-381   PASS (1/1✗)   1   522,477  510,467,864  510,467,864  no (script-size; ~64 steps by op-cost)

### demo (hash-chained state)  [multi-tx]
bch-multistep-demo   -           PASS (3/3✗)   3       228        3,894        1,298  yes
```

The real BSV Groth16 verifier is functionally correct but **not BCH-compatible**
(its 39,876-byte unlocking alone exceeds BCH's 10,000-byte script-size limit,
and its op-cost is ~64x a single input's budget). A properly chunked multi-step
run keeps every step inside the limits.

## How it works

Two VMs (see `src/harness/vm.ts`):

- a **loosened** BCH 2026 VM (every resource ceiling lifted) to prove correctness
  and measure op-cost even for oversized verifiers, and
- the **real** BCH 2026 VM (consensus limits) to decide BCH compatibility.

The unit of execution is a `Step` (one locking + unlocking pair = one
transaction's evaluation). A single-tx verifier is one step; a multi-tx verifier
is an ordered list. See `docs/benchmark.md` for the full contract and how to add
an implementation.

## Scripts

| script | what |
|--------|------|
| `pnpm benchmark` | run all registered implementations and print the leaderboards |
| `pnpm checkpoints` | compute/validate the BN254 golden checkpoints (vk_x + Miller boundary) |
| `pnpm fetch[:nchain\|:scrypt-bn256]` | download raw tx hex artifacts from WhatsOnChain |
| `pnpm nchain:extract` | disassemble the nChain verifier to an opcode listing |
| `pnpm nchain:run` / `nchain:verify` | run / accept-reject the nChain verifier in detail |
| `pnpm scrypt-bn256:run` / `scrypt-bn256:verify` | run / accept-reject the sCrypt BN256 verifier |
| `pnpm bch:fp-mul` | measure a single BN254 field multiply's op-cost on BCH |
| `pnpm typecheck` | `tsc --noEmit` |

## Layout

```
src/harness/          types, VM(s), tamper, benchmark runner
src/implementations/  one module per verifier (registered in benchmark.ts)
src/checkpoints/      off-chain BN254 golden checkpoints (vk_x, Miller boundary)
src/nchain/           detailed nChain extract/run/verify scripts
src/scrypt-bn256/     sCrypt BN256 extract/run/verify scripts
src/bch/              BCH primitive measurements (fp-mul)
data/<impl>/          SOURCE.md provenance (raw hex + listings are gitignored, re-fetchable)
docs/                 benchmark.md, scrypt.md, checkpoints.md
```

## Implementations

| id | track | state |
|----|-------|-------|
| `nchain` | Groth16 / single-tx | real BSV mainnet verifier (BLS12-381) |
| `scrypt-bn256` | Groth16 / single-tx | real BSV mainnet verifier (BN254, same curve as `BN256.cash`); accepts/rejects via `pnpm scrypt-bn256:verify` |
| `bch-vkx-scalarmult` | Groth16 vk_x (BCH-native) / single-tx | first BCH-native step (vk_x scalar-mult sub-step); normalized vs scrypt-bn256 at the same scalar |
| `bch-multistep-demo` | demo / multi-tx | hash-chained-state demo validating the multi-tx path |

Next target: a BCH-native BN254 Groth16 verifier as a multi-tx implementation, so
the harness can report step by step when it becomes BCH-compatible.

## Not every Groth16 is alike

The Groth16 entries are not interchangeable. Comparing their *totals* mixes
several factors that have nothing to do with implementation quality:

- **Curve.** `nchain` is BLS12-381 (48-byte field elements); `scrypt-bn256` is
  BN254 (32-byte). Our BCH work covers **both** — the BN254 line is the same-curve
  match for `scrypt-bn256`, the BLS12-381 line for `nchain` — so each reference has
  a same-curve BCH counterpart. A bigger curve means bigger, costlier scripts.
- **Statement / circuit.** Each verifies a different proof for a different
  circuit, with a different verifying key and a different number of public inputs
  (which sets the size of the vk_x multi-scalar-multiplication).
- **Optimization.** Precomputed pairings (e.g. `e(alpha,beta)` folded into the
  VK), affine vs projective coordinates, window sizes, etc.
- **Codegen.** BSV scripts are fully unrolled; BCH uses loops and functions, so
  the same work compiles to far smaller bytecode.
- **Deployment model — proof at runtime vs baked per-proof.** The references
  (`nchain`, `scrypt-bn256`) and our **singleton** entries are *runtime-general*:
  the proof (A,B,C) arrives push-only in the unlocking script at spend time, so one
  deployed verifier validates any proof for that circuit. Our **chunked** entries
  are *instance-specific*: the proof points are baked into the chunk scripts (the
  public inputs are recomputed on-chain but pinned to the baked vk_x), so a
  different proof requires regenerating the chunks. Both genuinely verify on-chain
  — an invalid proof cannot satisfy the chain — but a per-proof-compiled multi-tx
  chain and a runtime-general single script are different artifacts, so their byte
  totals are not directly comparable.

So a cross-entry "Nx larger / cheaper" on totals is *indicative, not a clean
benchmark*. An apples-to-apples result needs the same curve, statement, inputs,
and deployment model; that is why per-milestone comparisons are normalized (e.g. vk_x measured
at the same scalar, both loops fixed-iteration, so the gap reflects per-operation
efficiency rather than input size — see `docs/checkpoints.md`).

## Notes

- libauth `@bitauth/libauth@3.1.0-next.8` provides the BCH 2023/2025/2026 VMs;
  `@noble/curves` provides the off-chain BN254 reference for the checkpoints.
- A step can be tagged `checkpoint: "vk_x"`; the benchmark then reports the
  cumulative op-cost + bytes to reach it, so implementations compete on the
  in-between metrics, not just the total. See `docs/checkpoints.md`.
- Large raw-hex and disassembly artifacts are gitignored; each `data/<impl>/`
  folder keeps a `SOURCE.md` with provenance and the commands to regenerate.
