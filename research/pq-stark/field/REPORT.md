# Track 5 / Field cost: cutting the field arithmetic of the SHA-256 STARK verifier

Research only, not a leaderboard entry.

- Generator: groth16_cashscript main, `research/pq-stark/field/verifier/gen.mjs`. It is a copy of the Track 4 generator with mode switches.
- Kernels: zk-verifier-bench `research/pq-stark/field/kernels`. `results/k-field5.json` holds 51 cases on libauth BCH 2026 with the Track 4 measure harness. Every output is checked against an independent BigInt reference.
- Proofs (the Track 4 vectors), the Merkle checks and the soundness argument are unchanged. These are Track 4-format proofs with independent γ_j, so their soundness rests on [ADK] Thm 2 as published.

## Result
| | Track 4 | Track 5 field |
|---|---|---|
| P128-0 layout b op-cost std | 71,541,117 | 50,053,779 (-30.0%) |
| P128-0 BCHN-adjusted, standard basis (std + DEFINE body bytes) | - | 50,057,571 |
| P128-0 BCHN-adjusted, consensus basis | 70,953,309 | 49,465,827 |
| P128 share of base-41 budget | ~90% | 63.2-64.9% (P128-0..3) |
| P128 redeem / unlocking / tx | 5,945 / 96,383 / 96,472 B | 5,915 / 96,353 / 96,442 B |
| P100-0 layout b op-cost std | 38,728,435 | 27,861,234 (-28.1%) |
| P100-0 BCHN-adjusted, standard / consensus basis | - | 27,865,088 / 27,634,560 |
| P100 redeem / tx | 5,968 / 56,661 B | 6,002 / 56,695 B |
| P128-0 today standard (layout a) | 19 inputs, 2 txs, 154,831 B, 91.7M | 19 inputs, 2 txs, 150,891 B, 81.2M (BCHN, standard basis, 81.5M) |
| P100-0 today standard | 10 inputs, 1 tx, 77,623 B (pad 6,337) | 10 inputs, 1 tx, 70,764 B (pad 1,132) |
| P128-0 bch-spec (base 10,000) | - | 58.8% |

- **BCHN basis:** `grade-b.mjs` in this phase writes `opBchnAdjusted` on the consensus basis and `opBchnAdjustedStd` on the standard basis. `grade-a.mjs` uses the standard basis. The Verifier phase now uses the standard basis everywhere, so compare its figures with the standard-basis rows above.
- **Rejection suites:** `test-b` and `test-a` gave all verdicts as expected on C100, C128, P100, P128 and U100, including the cross-proof splice.
- **Function tests:** `test-fns` checks the legacy and the new functions against JS references, including inputs with every limb at its maximum.
- **Today's standard rules:** the input count does not drop. Query inputs are byte-bound: 3 queries fit in 8,455 B of unlocking, and a fourth needs about 11.3 KB. They use 81% of their op-cost budget (Track 4: 92%).

## Per-query profile (P128-0, layout b)
| phase | Track 4 | Track 5 | saved per query |
|---|---|---|---|
| entry (x0) | 55.5k | 10.8k | 44.7k (runtime window tables) |
| parse | 68.8k | 75.0k | -6.2k (packing at parse) |
| deep | 454.0k | 317.8k | 136.2k (DPK, lazy) |
| layers | 347.4k | 218.7k | 128.7k (PAIRK/UR) |
| final (D=256) | 478.0k | 271.7k | 206.3k (group-packed H=8) |
| per query | 1,403.7k | 894.1k | 509.6k (-36%) |
| per proof unpack | 762.6k | 1,083.3k | -320.7k |

After the change, Merkle (9.4M) is about 19% of op-cost (was 13%) and field arithmetic about 80% (was ~84%).

## Kernels (std op-cost, mean of trials)
| kernel | Track 4 | best Track 5 | verdict |
|---|---|---|---|
| A1 F_p^3 mul / F_p^2 mul | 8,266 | 3,877 (F_p^2) | needs a field and soundness change; not applied |
| A2 F_p^3 x per-proof const | 8,301 | 5,853 (+5.0k once per constant) | win: rotation columns |
| A3 a*b+c*d F_p^3 | 21,943 | 15,461 | win: lazy |
| B1 fold pair | 20,954 | 13,093 | win: PAIRK+UR |
| B2 fold arity 4/8/16 | 65.7k/156.0k/336.9k | 39.7k/91.3k/193.3k | win; per value, arity 16 (12.1k) is no cheaper than arity 8 (11.4k) |
| B3 DEEP per point | 63,536 | 37,971 | win: DPK |
| B4 final per query D=32/64/128/256 | 107.7k/160.3k/265.7k/475.4k | 55.2k/88.6k/154.9k/268.1k | win; best H=4 for D<=128, H=8 for D=256 |
| B4 final per proof D=256 | 756k | 1,083k | cost of the winner |
| C1 invert 9 values | 29,135 (Montgomery) | 10,658 (all witnessed) | +64 B per query: not applied |
| D1 x0 | 52,126 (XPOW) / 13,426 (tables in code, +768 B) | 7,322 (runtime tables) | win |
| E1 leaf parse | 5,836 (64 B) | 21,990 (192 B into packed F_p^3) | price of packing |

**Why packing pays.** OP_MUL is charged by operand length. So a product of values packed in 3 slots costs one instruction and one OP_MOD per slot, instead of 9 multiplications. Most of the gain is fewer instructions and fewer stack fetches. Before the change, instructions were about 72% of op-cost, and stack fetches about 43%.

## Not applied / did not work
- **Witnessed inverses:** -18.5k per query (-1.6% per proof), but +2.75 KB at P128. P128-3's tx is already 99,957 B, and today's query inputs are byte-bound.
- **Packing H=16:** the OP_MUL length cost grows faster than the savings (303.8k vs 268.1k).
- **Degree-2 extension:** cheaper per multiply, but not sound at P128 without re-deriving the parameters.
- **Smaller final degree / higher arity (SPEC §4.4):**
  - A fourth FRI layer adds about 15 KB, so the proof no longer fits one 100 KB input.
  - Arities like [8,16,16] raise the batch+fold soundness term, where P128 has a 0.31-bit margin.
  - Left to the soundness and prover tasks. B4 gives the per-D costs.
- **Karatsuba for F_p^3:** not measured as a separate kernel. With lazy reduction the cost is dominated by instructions and stack traffic, and rotation columns cover constant operands.

## Reproduce
**Requirements:**
- Node with `@bitauth/libauth` 3.1.0-next.8. Every node command needs an untracked `node_modules` link at the worktree root: `node_modules -> ../../../pq-hash/verifier/node_modules`, pointing at the Track 4 install.
- Run everything single-threaded under `nice`.

**Generator:** groth16_cashscript main, `research/pq-stark/field/verifier`, with `V=../../../pq-hash/prover/vectors`:
- `node test-fns.mjs $V/P128-0.json`
- `node grade-b.mjs $V/*-[0-3].json`
- `node grade-a.mjs $V/*-[0-3].json`
- `node test-b.mjs $V/*-[0-3].json > results/test-b.log`
- `node profile-b.mjs $V/*-[0-3].json`

**Kernels:** zk-verifier-bench `research/pq-stark/field/kernels`:
- `PQ_FIELD_SRC=<groth16_cashscript checkout>/research/pq-stark/field/verifier node run.mjs`
- `PQ_FIELD_SRC` is required in a clean checkout. Without it, `k-field5.mjs` finds the generator through the sibling-worktree layout (`../../../../../g16/...`), which exists only under `work/pq-stark/field/{g16,bench}`.
