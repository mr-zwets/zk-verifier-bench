# Track 4: a post-quantum, SHA-256 STARK verifier on CashVM

Date: 2026-10-28. Status: research. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json. Two internal reviews: one blocker (layout b witness shape), fixed and re-graded; all minors resolved or stated as conditions below.

## 1. Question

The site's [/beyond-groth16](https://github.com/mr-zwets/zk-verifier-competition/blob/main/src/routes/beyond-groth16.tsx) page estimated how post-quantum proof systems would fit CashVM: "our assessment, not measured". This track measures two things:
1. A real hash-based verifier: bytes, inputs, transactions, op-cost and hash iterations, under today's standard rules and under TXv5 / bch-spec.
2. The kernels behind the page's "BCH VM fit" column: native SHA-256, emulated RPO / Tip5 / Blake2s, GF(2^128) and prime fields.

## 2. Design and parameters

Full spec: [SPEC.md](SPEC.md). Calculator: [params.py](params.py) (outputs: [params-output.txt](params-output.txt)).

| | choice |
|---|---|
| protocol | DEEP-ALI STARK with batched DEEP-FRI (ethSTARK structure); folds 4, 8, 8; final polynomial degree < 2^8 |
| field | Goldilocks p = 2^64 − 2^32 + 1; challenges, OOD values and FRI layers ≥ 1 in F_{p^3} = F_p[u]/(u^3 − 7) |
| hash | SHA-256 (native) for Merkle trees, Fiat-Shamir and 28-bit grinding; nodes truncated to h bytes |
| statement | MiMC-7 chain, 8 periodic round constants; trace 2 columns × 2^16 rows; 4 constraints of degree 3 |
| zero-knowledge | **out of scope**: no masking; the statement is fully public |

| set | regime | ρ | m | queries | h | λ (classical) | proof bytes (measured, 4 vectors) |
|---|---|---|--:|--:|--:|--:|--:|
| **P100** | provable, Johnson (BCIKS20 Thm 8.3) | 2^−7 | 3 | 22 | 25 | **100** (digest cap; λ_IOP 100.11) | 49,093–50,618 |
| **P128** | provable, Johnson | 2^−5 | 4 | 43 | 32 | **128** (commit 128.31, query 128.19) | 88,752–92,240 |
| U100 | unique decoding (comparison) | 2^−? (deg-2 field) | – | 79 | 25 | 100 | 105,892–106,967 |
| C100 / C128 | **conjectured** (comparison only) | – | – | 11 / 15 | 25 / 32 | 100* / 128* | 24,326 / 42,032 |

**Soundness bound.** λ = min(λ_IOP, 4h), where λ_IOP is the minimum over rounds of −log2 ε_round + grinding:
- ALI and DEEP: list size L = (m + ½)/√ρ.
- Batching and folds: BCIKS20 Thm 8.3, checked against ECCC TR20-083.
- Query round: (√ρ·(1 + 1/2m))^s · 2^−28.

**Open condition.** "Provable" assumes that each per-round Fiat-Shamir commit error is at most the combined ε_C (ePrint 2023/1071, list-decoding regime). This has not been checked. Margins: P128 has 0.31 bits on the commit rounds and 0.19 bits on the query round; P100 has about 24 bits on the commit rounds. **Quantum (indicative):** collisions about 67 bits (h = 25) and 85 bits (h = 32); overall about 50 (P100) and 64 (P128) bits ([SPEC §4.5](SPEC.md)).

**Correctness of the reference code.** The prover is deterministic. The Python and an independent JS verifier accept 14/14 valid proofs and reject 100/100 tampered ones.

## 3. Kernels (selected)

Full tables: [kernels/results/RESULTS.md](kernels/results/RESULTS.md), [kernels/results/RATIOS.md](kernels/results/RATIOS.md). Method: [kernels/REPORT.md](kernels/REPORT.md).
- 87 kernels measured on libauth BCH_2026, standard op-cost.
- Each kernel is checked in-script against an independent reference (node:crypto, BigInt, Miden's and twenty-first's test vectors).
- Each also passes the real VM as a padded P2SH32 spend, except 8 large unrolled cases, which are marked.

| kernel | op-cost | note |
|---|--:|---|
| SHA-256 node (OP_CAT OP_SHA256) | 680 | 2 hash iterations; 0.03× the 25,600 that 32 bytes buy |
| Merkle path level with index bit, h = 32 | 1,938 | h = 25: 2,059 (truncation saves bytes, not op-cost) |
| Tip5 permutation (emulated) | 756,986 | **24×** its digest bytes' budget |
| Blake2s compression (emulated), unrolled / function | 837,797 / 961,245 | **33× / 38×** |
| RPO permutation (emulated), x^(1/7) computed / witnessed | 4,966,796 / 1,053,526 | **194× / 41×** (witnessed: +672 B per hash) |
| GF(2^128) mul: holes / 4-bit windowed / bit-serial | 44,362 / 100,031–117,009 / 460,668 | **36×** / 81–95× / 373× a 128-bit prime mulmod |
| Goldilocks mulmod / 128-bit prime / P-192 | 569 / 1,234 / 2,278 | op-cost is mostly instruction count |
| Goldilocks^2 / Goldilocks^3 (schoolbook, packed) / BabyBear^4 / QM31 mul | 3,657 / 8,064, 7,449 / 11,783 / 15,076 | small fields lose at equal challenge size |
| F_{p^3} inversion: computed / witnessed norm inverse | 72,097 / 12,943 | |
| FRI fold arity 4 / 8 / 16 (binary folds) | 58,559 / 134,686 / 287,741 | |
| final polynomial, 256 F_{p^3} coefficients / 32 | 706,281 / 87,162 | the main op-cost knob |
| AIR identity at z, cross-multiplied | 334,043 | |
| full Fiat-Shamir transcript, P128 | 164,175 | 167 hash iterations |

## 4. Measured verifier

The sources are in groth16_cashscript main, [`research/pq-hash/verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-hash/verifier). Cross-check with this harness's own VM wrappers: [verifier/crosscheck.ts](verifier/crosscheck.ts) → [verifier/crosscheck.json](verifier/crosscheck.json). Result copies: [verifier/results/](verifier/results/).

**Layouts**
- **Layout (b)** is one P2SH32 input under TXv5 or bch-spec: the code is the redeem, and every tree uses a full deduplicated LIFO multiproof with the witness shape pinned per tree.
- **Layout (a)** follows today's standard rules:
  - A shared P2SH32 redeem. A CODE input carries the code, which is hash-checked and loaded with OP_DEFINE.
  - The input count and locking bytecode are pinned. HEAD and QRY inputs each re-derive the transcript, and each role pins its own layout.
  - P128 spans two transactions linked by a CashToken NFT thread: tx0 mints the token with commitment SHA256(tag ‖ G ‖ 1), and tx1 recomputes G, checks the commitment and burns the token.

**Measures**
- Budgets: TXv5-as-written is (41 + unlocking) × 800; bch-spec is (10,000 + unlocking) × 800.
- **BCHN-adjusted** adds the OP_DEFINE body bytes. For layout (b) it is standard op-cost plus the bodies. For layout (a) it is an upper bound: all bodies are charged to every input.

| set | layout | proof B | total B | inputs | txs | op-cost (std) | BCHN-adj. | hash iter. | % budget | fits today | fits TXv5 |
|---|---|--:|--:|--:|--:|--:|--:|--:|---|---|---|
| P100 | (b) | 50,618 | 57,526 | 1 | 1 | 38,818,064 | 38,822,165 | 1,837 | 84.4–86.1% TXv5 / 72.0–73.1% spec | no (input > 10 kB) | **yes** |
| P128 | (b) | 92,240 | 99,981 | 1 | 1 | 72,002,598 | 72,006,662 | 4,842 | 90.1–92.7% / 81.9–84.1% | no | **yes** (19 B spare) |
| U100 | (b) | 106,967 | 114,670 | 1 | 1 | 92,099,805 | 92,102,769 | 4,113 | 100.4–101.3% TXv5 | no | **no** (> 100 kB) |
| C100* | (b) | 24,326 | 30,441 | 1 | 1 | 16,006,309 | 16,010,378 | 943 | 65.8–66.7% | no | yes |
| C128* | (b) | 42,032 | 49,153 | 1 | 1 | 26,642,921 | 26,647,511 | 2,196 | 67.8–68.0% | no | yes |
| P100 | (a) | 50,618 | 77,626 | 10 | 1 | 47,808,060 | ≤ 47,969,010 | 4,388 | ≤ 94% per input | **yes** | yes |
| P128 | (a) | 92,240 | 154,829 (79,370 + 75,459) | 19 | 2 | 91,687,949 | ≤ 92,036,143 | 11,314 | ≤ 94% per input | **yes** | yes |
| U100 | (a) | 106,967 | 188,560 | 31 | 2 | 117,443,690 | ≤ 117,906,086 | 12,321 | ≤ 94% per input | yes | yes |
| C100* / C128* | (a) | 24,326 / 42,032 | 36,787 / 60,435 | 6 / 7 | 1 | 16.7M / 30.4M | | 1,859 / 3,870 | ≤ 77% | yes | yes |

\* conjectured soundness, comparison only.

**Acceptance.** Every valid vector is accepted, standard and consensus:
- layout (b) on bch-spec and on TXv5-as-written;
- layout (a) on the real BCH 2026 VM, per input and as a full-transaction `vm.verify`, with token rules for P128.

**Rejection** (constructive tests only):
- Layout (b): 38 cases per set, 190/190 rejected. They cover 20 prover tamperings and 18 witness manipulations, including the count-preserving shape cases added for the review blocker.
- Layout (a): all cases per set rejected, including graph, pad and NFT-thread cases.
- No rejection comes from budget exhaustion.

**Where layout (b) P128 spends its op-cost** (profile of P128-3)

| phase | op-cost | share |
|---|--:|--:|
| setup (pushes, redeem hash, OP_DEFINEs) | 0.15M | 0.2% |
| transcript | 0.20M | 0.3% |
| AIR at z and constants | 0.54M | 0.8% |
| Merkle multiproofs (5 trees) | 9.86M | 13.7% |
| final-polynomial unpack | 0.76M | 1.1% |
| 43 queries: entry / leaf parse / DEEP / folds / final polynomial, each per query | 56k / 69k / 454k / 347k / 478k | 60.4M = 83.8% |

- **Model vs measurement.** Bytes matched the calculator (P128: 91.5 KB modelled, 88.8–92.2 KB measured).
- **Op-cost** exceeded the original model (59% of budget) but matched the kernel projection (94% projected, 90.1% measured). Packed dot products bring the final polynomial to 478k per query, against 706k in the kernel.
- **Layout (a)** needs more inputs than the design expected (P100: 10 inputs, not 6; P128: 19, not 14). Op-cost binds per input: 3 queries per QRY input, with P100 padding 6,340 B to cover its budget.

## 5. The page's estimates against the measurements

| page claim | measured | verdict |
|---|---|---|
| a 32-byte node buys 16 hash iterations, checking it costs 2 | 2 iterations; 680 op-cost per node, 1,938 per path level | holds |
| a 100 KB proof brings ~80M op-cost and ~50,000 iterations; "should cover the hashing with room to spare and the field arithmetic too" | P128: 72.0M of 80.0M (90.1%), 4,842 of ~50,000 iterations; Merkle 14%, query field arithmetic 84% | **partly**: hashing has ample room; field arithmetic nearly fills the budget at 128 bits |
| emulated RPO / Tip5 ~100×, Blake2s ~10–30× (reviewer estimates) | RPO 194× (41× witnessed), Tip5 24×, Blake2s 33–38× | direction holds; RPO ~2× worse, Tip5 ~4× better, Blake2s slightly above |
| Miden: "compute does not fit" | RPO 194× | holds |
| Stwo: "likely needs padding" | Blake2s 33× | holds: it needs padding |
| GF(2^128): "tens to over a hundred times a prime-field multiply" | 36× (holes), 81–95× (windowed), 373× (bit-serial) | holds |
| today: "a dozen or so inputs across at least two transactions" for ~100 KB | 92 KB: 19 inputs, 2 txs; 50 KB (P100): 1 tx, 10 inputs | holds for 2 txs; more inputs, because op-cost binds per input |
| TXv5: "a proof of up to about 90 KB fits in one input with its verifier" | 92.2 KB proof + 5.9 KB redeem in one 99,981 B tx | holds, with 19 B to spare; 1–2 more queries would not fit |
| Lattice Jolt: lattice-check cost "not yet assessed" | not measured (K18 not done) | open |

## 6. Caveats

- **libauth, not BCHN.** Op-cost is libauth 3.1.0-next.8. BCHN-adjusted figures add OP_DEFINE body bytes by computation and were not run on BCHN. BCHN CPU time per op-cost was not measured for these scripts (see [../opcost-timing/REPORT.md](../opcost-timing/REPORT.md)).
- **Budget bases.** TXv5-as-written uses density base 41; bch-spec uses 10,000. Both are reported.
- **No zero-knowledge.** Opened trace values leak; a ZK variant (masking column, randomized composition) is not built.
- **Soundness condition.** "Provable" depends on the open per-round Fiat-Shamir check, with thin P128 margins (§2). λ is classical.
- **Kernel costs are upper bounds** for our implementations: SWAR Blake2s, a better Tip5 lookup and other cheaper variants may exist.
- **One statement shape.** A MiMC chain with n = 2^16. At 128 bits the bytes grow quickly with n (138 KB at 2^18, per the calculator).
- **Research artifact.** It is not registered and not externally reviewed, and only constructive tests were run.

## 7. Sources and reproduction

| what | where |
|---|---|
| spec, calculator | this folder; developed on zk-verifier-bench `wip/pq-hash-design` (b53135f) |
| kernels | [kernels/](kernels/) (`node run.mjs && node table.mjs && node ratios.mjs`, byte-identical); developed on `wip/pq-hash-kernels` (6afde39) |
| prover, Python + JS reference verifiers, vectors | groth16_cashscript main, [`research/pq-hash/prover/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-hash/prover) |
| on-chain verifier, graders, rejection suites, profiler | groth16_cashscript main, [`research/pq-hash/verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-hash/verifier) |
| harness cross-check | [verifier/crosscheck.ts](verifier/crosscheck.ts): `PQ_VERIFIER_SRC=<groth16_cashscript>/research/pq-hash/verifier tsx research/pq-hash/verifier/crosscheck.ts`; developed on `wip/pq-hash-verifier` (453f999) |