# Tracks 5 and 8: a post-quantum SHA-256 STARK verifier on CashVM (Plonky3, Goldilocks)

Status: research. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json.

- **Track 8** (2026-11-01, first part below) makes the verifier usable: a real statement (a zero-knowledge Merkle-membership spend with a nullifier, bound to the spending transaction), Plonky3's multi-table `batch-stark` protocol, and all three deployment layouts at 128 bits.
- **Track 5** (2026-10-29, second part) is the first Plonky3 build. Its text is kept as it was.

---

## Track 8 (2026-11-01): a usable verifier for a real statement

Two internal reviews ran on the build: protocol/soundness, which also checked the AIRs against their spec (verdict fix: 1 major, 3 minors), and measurement (verdict fix: 1 major, 5 minors). A fix phase handled every finding. Before the reviews, the soundness write-up itself found one gap in the scripts as built: proof field lanes were not reduced safely. It was fixed, and every on-chain suite was re-run on the fixed scripts (§T8.6, §T8.7). An independent re-review of the fix phase and of this report passed with minors (all applied: proof-size range, limits framing, s8-arith wording, reproduce notes); it re-ran the layout-b production suite byte-identically.

The sources are on groth16_cashscript branch `wip/stark-usable` (scripts at 12d47d4, results at c47d104, summary at 0d23832). The links in §T8.10 point to `main` paths, which are valid once the branch is merged. The design, the calculators and the AIR spec are on zk-verifier-bench branch `wip/stark-usable-design` (6050eaf). The integrated summary is copied here as [results/verifier-summary-track8.json](results/verifier-summary-track8.json).

### T8.1 What changed

Track 5 verified Plonky3 proofs of toy AIRs (MiMC, Fibonacci) in Plonky3's single-table `uni-stark` format. It left four gaps between that and a deployment. Track 8 closes each one:

| | Track 5 (main) | Track 8 |
|---|---|---|
| statement | toy AIRs, no public meaning | **M1:** depth-30 Merkle membership, nullifier, outputs binding (§T8.2) |
| protocol | `uni-stark`, one table | `p3-batch-stark`: N tables, mixed heights, preprocessed columns, LogUp lookups (M2 and Plonky3's five batch test AIRs) |
| zero knowledge at 128 bits | fib-S128z: 112.5 KB, did not fit one 100 KB input; 3 txs / 35 inputs / 234.6 KB today | M1 with ZK: one 100 KB input (91.4–95.0 KB); **1 tx / 12 inputs / 98,690 B today** |
| two 100 KB inputs | not built | layout b2 with one shared code library (M1 and M2) |
| binding to the transaction | none | CTX = SHA-256 of the spending transaction's outputs, computed by the script and bound by the transcript |
| constraint check | hand-written per AIR | a byte-coded interpreter for the constraint graph exported from Plonky3 |

**Every layout now reaches 128 bits with ZK, on one statement that means something.** Today's standard rules need no raised limit and fit in one transaction.

### T8.2 Statement

**M1** is a fixed-denomination, zero-knowledge spend. It has no value field; value-carrying notes are for a later track.

- **Public values** (12 Goldilocks elements, each checked < p):
  - ROOT[4], a constant compiled into the script;
  - NF[4], a witness item; the script checks each lane < p;
  - CTX[4], computed by the script from the spending transaction's outputs: SHA-256 over an injective output serialization, truncated to 28 bytes, as four 56-bit chunks (prover/FORMAT.md, "CTX serialization").
- **Witness:** nk[4], r[4], 30 path bits and 30 siblings.
- **Relation.** P is Poseidon2-Goldilocks width 8, with the stock p3-goldilocks constants; T keeps the first 4 lanes.
  - NF = T(P(nk‖0,0,0,TAG_NF))
  - leaf = T(P(NF‖r))
  - node_i = T(P(swap_{b_i}(node_{i−1}, S_i)))
  - ROOT = node_30
- **AIR:** one table of 2^10 rows × 17 columns, 11 periodic columns, 53 constraints of degree ≤ 4, 8 ZK quotient chunks, 94 opened values.
  - The spec (`design-t8/AIR-SPEC.md`) is checked in both directions:
    - a Python reference and the Rust AIR produce identical traces;
    - Poseidon2 agrees with p3-goldilocks on 10,002 inputs plus the test vector;
    - every single-cell mutation of an honest trace breaks a constraint (17,408 of 17,408).
- **CTX is not read by any constraint.** It is bound only because it is a public value, observed in the transcript before every challenge (SOUNDNESS-T8 Lemma 13). The generator refuses a constraint graph that reads it.
- **Prover:** M1 takes about 1.0 s with 4 threads under nice (3.8 s with 1 thread), with a peak RSS of 1.06 GB. M2 takes 1.3 s (6.7 s with 1 thread) at 1.45 GB.

**M2** is a generality test vector, not the production statement. It expresses the same relation as two tables:
- **T_hash:** 2^10 rows × 24 columns, plus 1 preprocessed column.
- **T_ctl:** 2^7 rows × 13 columns, plus 5 preprocessed columns.
- **The bus:** one LogUp bus of width 13 joins the tables. Σw·h = 1152 < p.

M2 covers two heights, mixed-height Merkle injection, a FRI roll-in, a salted preprocessed commitment, the permutation tree, terminals and the lookup PoW.
- Under ZK, the preprocessed commitment is salted, so it cannot be recomputed from the AIR alone.
- It can be recomputed from the AIR plus a published setup seed (`SETUP_SEED` = "t8SETUP1").

What M1 does not do, and Track 9 must: it does not publish NF in an output, keep a nullifier set or update ROOT. **Replaying one valid proof in two transactions is not prevented by the verifier.**

### T8.3 Parameters

| set | used by | blowup | fold | final poly | Q | PoW (query / commit / batch / lookup) | ZK | cap |
|---|---|--:|---|--:|--:|---|---|---|
| Z128 | M1 | 2^9 (LDE 2^20) | one arity-8 fold | 256 | 24 | 24 / 2 / 20 / – | yes (rc 3, salt 2) | 0 (b, b2) or 5 (a′) |
| Z128-g | M2 | 2^9 | [3, 3] (20 → 17 → 14) | 32 | 24 | 24 / **3** / 20 / 8 | yes | 0 |

- The field is Goldilocks with a cubic trinomial extension. Commitments and the transcript use SHA-256. The prover is Plonky3 at 0d80373, and the wire format is our own p3b-v1 (prover/FORMAT.md).
- **Batch PoW 20,** not 12: at 12, the batch round would sit at 128.33 bits.
- **M2 needs commit PoW 3,** not the designed 2. Charging the roll-in curve at degree a costs 0.19 bits on fold1, and with commit PoW 2, M2 reaches only 127.92.
- **Each deployment's verifying key fixes its own Merkle cap.** A proof made for another cap, set, PoW, setup seed or statement is rejected.

### T8.4 Results per layout and regime

All figures below are post-fix (§T8.7). The proof and statement sets are:
- M1: 24 transaction-bound statements (leaves 0, 2^30 − 1 and 22 derived), cap 0 for b and b2, re-proved at cap 5 for a′;
- M2: 8 statements.

The op-cost columns use these conventions:
- **BCHN-adjusted** = libauth op-cost + OP_DEFINE body bytes (Track 8a; it is exact on stock BCHN 29.1.0), gated as max(standard, consensus) + define bytes.
- **Budget** = (41 + unlocking length) × 800 per input.

| layout | statement | limits to raise (consensus / relay) | inputs (txs) | proof B | unlocking B | tx B | BCHN-adj. op-cost per input | % of budget | accepted |
|---|---|---|--:|--:|--:|--:|--:|--:|--:|
| b, one input | M1 | consensus: per-input unlocking, bytecode and stack-item limits raised to 100,000 B; relay tx size unchanged | 1 (1) | 71,344–74,928 | 91,388–94,968 | 91,477–95,057 | 35.53–36.04M | 47.4–48.6% | 24/24 |
| b2, two inputs | M1 | consensus per-input limits raised to 100,000 B; relay tx size 100,000 B unchanged | 2 (1) | 71,344–74,928 | 61,919–63,555 + 33,335–35,245 | **96,153–98,321** | 27.16–27.38M / 19.56–19.82M | 53.8–54.8% / 70.2–73.3% | 24/24 |
| b2, two inputs | M2 | consensus per-input limits raised to 100,000 B **and** the relay tx-size limit raised (passes at 200,000 B) | 2 (1) | 121,350–124,710 | 79,778–82,436 + 75,783–77,391 | 156,384–159,749 | 35.20–35.52M / 33.20–33.51M | 53.8–55.1% / 54.1–54.8% | 8/8 per input; whole tx 0/8 at 100,000 B, 8/8 at 200,000 B |
| a′, today, 1 tx | M1 (cap 5) | **none** | 12 (1) | 73,648–78,512 | 6,454–9,322 per input | **98,690** | 1.31–6.09M | max input 90.80–91.01% (QRY; all QRY inputs 90.67–91.01%) | 24/24 |
| a′, today, 2 txs | M1 (cap 5) | none | 16 (2) | same | same roles | 91,059 + 40,497 = 131,556 | ≤ 6.09M | max 91.10% | 24/24 |

- **bch-spec** (base 10,000): layout b passes 24/24 at 42.9–43.8%. b2 passes M1 24/24 (46.5–47.2% / 54.8–56.4%) and M2 8/8 per input; M2's whole transaction again needs the size limit raised.
- **Today's rules** reject layouts b and b2 (0/24 and 0/32): the unlocking exceeds 10,000 B.
- **Policy controls are live.** libauth's standard mode rejects a 10,025 B unlocking, a 100,118 B transaction and a 208 B output locking.
- **The a′ 1-transaction plan fits at Z128 itself.** It needs no parameter trade (the design's fallback was Q 23 with query PoW 28), and its margin under 100,000 B is 1,310 B. Its bytes are the same for every statement, because full paths have fixed length.
- **b2 for M1 fits a standard 100,000 B transaction.** Only the per-input limits must rise.

**Layout a′ per role** (1 transaction; BCHN-adjusted includes 36,844 B of OP_DEFINE bodies per input):

| role | inputs | unlocking B | op-cost | % of budget | what it does |
|---|--:|--:|--:|--:|---|
| HEAD | 1 | 6,454 | 1.31M | 25.2% | caps, OOD values, PoW, NF, CTX; transcript; combines the AIR parts with the quotient |
| CODE1 / CODE2 | 2 | 9,322 / 9,316 | 5.47M / 4.98M | 73.1% / 66.6% | code blobs (9.3 KB each); constraint ranges [0,21) and [21,53) at ζ |
| FIN | 1 | 6,462 | 3.76M | 72.4% | final polynomial; checks a 312 B table of query indices, α′, β, DEEP constants and A sums |
| QRY | 8 | 8,322 | 6.07–6.09M | **90.7–91.0%** | 3 queries each, full paths to the cap; recomputes the α′ ladder |

- Every input has the same 118 B P2S locking. That locking authenticates both code blobs by SHA-256, then pins the input graph: the input count and every locking.
- Values move between inputs only as pushes. Each push is checked by its owner, and readers parse it with exact headers.
- **QRY is the binding input, at about 91% of its budget.**
  - Its op-cost: row keys 1.40M, final-polynomial unpack 1.26M, three queries with paths about 2.95M.
  - Publishing the α′ powers instead would save 1.4M per QRY input, but add about 2.3 KB and break the 1-transaction fit.
- **The 2-transaction baseline** links the transactions with Track 5's NFT thread, whose commitment binds the final transcript digest. tx1 carries HEAD, FIN and both code inputs again, which is why it is larger than the design's 14 inputs and 115–120 KB.

**Where layout b's op-cost goes** (statement 0, 35.98M libauth):

| part | op-cost | S0 model |
|---|--:|--:|
| queries (24 × 0.67M) | 16.09M | 16.79M |
| Merkle | 7.05M | 7.23M |
| fixed part | 12.83M | 4.23M |
| of which: AIR at ζ | 8.03M | 0.6M |
| of which: constraint-graph interpreter | 5.79M | – |
| of which: periodic columns | 1.19M | – |
| of which: DEEP constants | 3.16M | – |

- The constraint graph (551 nodes, 53 constraints) runs as a 2.1 KB byte program on an OP_INVOKE-based interpreter.
- Inlining it would be faster but makes the redeem too large to fit; this was measured. It would grow from 19,024 B to about 48 KB.
- **Track 5's finding that "the AIR is under 1% of op-cost" does not carry over to a real statement:** here the AIR is 22% of the op-cost.

**b2 profile:**
- Input 0 for M1: AIR 7.85M, DEEP/FRI constants 4.68M, 12 queries 8.04M, Merkle 3.80M, entry 2.76M.
- Input 1 re-derives the constants: a 4.7M duplicate for M1 and 8.2M for M2.
- The library defines (19,468 B for M1, 27,759 B for M2) are part of the BCHN adjustment on both inputs.

**Plonky3's own batch AIRs on chain.** single_instance, three_instances_mixed_sizes, mixed_preprocessed, both_lookups_zk and periodic_air_zk verify on chain under Z128, Z128-g, ZK off and n = 2^10, in layouts b and b2. They are coverage vectors and are not graded. At Plonky3's own small parameters (Q = 2), the b2 split leaves input 1 too few bytes for its op-cost budget, so those three files run in layout b.

### T8.5 Tests

Every suite has 0 unexpected verdicts. Each on-chain case must get the same verdict from the script, from the JS model of the on-chain algorithm and from the independent reference verifier `verify-batch.mjs`. The reference in turn agrees with Plonky3's Rust `verify_batch`.

**Agreement:**

| check | cases | result |
|---|--:|---|
| Rust `verify_batch` vs JS reference (S3): 128 valid proofs, tamper families, VK variants, forced proofs | 14,027 | 0 disagreements; all 128 transcripts byte-identical (every SHA-256 challenger input) |
| on-chain model vs reference, M1 (S4) | 3,762 | 0 disagreements |
| on-chain model vs reference, all S3 cap-0 files, unsplit and with the b2 split (S5) | 17,911 | 0 disagreements, transcripts identical |
| forced unsatisfying traces, proved by the release prover | 16 | 16/16 rejected by Rust and JS (bus-only cases on the LogUp terminal sum) |
| CTX script block vs JS serialization | 4 txs | 0 mismatches; other output sets rejected |

**On-chain sweeps** (post-fix; [summary](results/verifier-summary-track8.json)):

| suite | cases | not run on chain | encoder-only | files skipped |
|---|--:|--:|--:|--:|
| b production, M1 (CTX from the tx) | 2,929 | 0 | 0 | 0 |
| b harness, S3's M1 cap-0 case files | 3,309 | 33 | 1 | 2 |
| b2, M2 + Plonky3 AIRs | 8,252 | 59 | 0 | 3 |
| b2 harness, M1 | 2,558 | 35 | 1 | 2 |
| b2 production, 24 M1 + 8 M2 | 1,030 | 0 | 0 | 0 |
| a′ production, 1 tx | 3,765 | 0 | 55 | 2 |
| a′ production, 2 txs | 4,181 | 0 | 55 | 2 |
| a′ harness, S3's M1 cap-5 case files | 2,387 | 35 | 69 | 2 |

The families are DESIGN-T8 §8's test matrix:
- **Tampered proofs:** every cap digest, OOD value, terminal, random-codeword value, PoW witness, final coefficient, row and salt (injected short-table rows included), sibling and FRI value; truncation, extension and non-canonical encodings.
- **Statement:** each public value + 1, NF − 1, NF + p, foreign or stale ROOT, foreign NF or CTX, permuted values.
- **Other VKs:** cap, parameter set, ZK on/off, PoW bits, setup seed, M1 ↔ M2.
- **Transaction:** changed value or recipient, extra or split output, added token, another statement's outputs.
- **Witness manipulations (1,014 in b):** hints, record repacking, item sizes, NF lanes.
- **b2 layout (814):** mismatched proofs across the inputs, a third input, another locking, a tampered or truncated library, swapped inputs, moved blobs or records, bad injection paths.
- **a′:** tampered HEAD/FIN/CODE constants (650), including ACC_1 + 1 with ACC_2 compensated; input (598), graph (208), cross-input and cross-transaction mixing (130/156); NFT thread and replay (390).

How to read the counts:
- **Not run on chain:** the statement layer or the generator refuses the case before a script exists, for example a CTX lane ≥ 2^56 or a VK the generator does not support. The verdict (reject) is right, but no script ran.
- **Encoder-only:** malformed-by-length proofs whose on-chain witness is the valid proof's, so the script accepts the valid witness, as in Track 5's layout a. A production encoder refuses them.
- **Files skipped:** cap + 1 and ood-PoW = 1 VKs, which are outside the generators' scope, and cap-0 files in a′.

**Coverage limits:**
- The lookup-PoW and FRI final-polynomial checks cannot be reached by plain tampering: any edit before the query indices are drawn changes the indices, and a Merkle check rejects first. In a fault-injection run of the suite, removing either check gave 0 disagreements. Both are checked by code reading, not by tests.
- No test exercises a consistently built proof with non-canonical lanes. That case is covered by the §T8.6 congruence argument and an op-level check.
- BCHN node run ([node-check](../node-check/README.md#track-8-stark-m1)): all 24 M1 statements in both a′ plans accepted on stock BCHN 29.1.0, 106 sampled rejections rejected, matching libauth; the default relay policy allows every tx, and the 2-tx plan also broadcasts with tx0 unconfirmed.

### T8.6 Soundness summary

Details are in [SOUNDNESS-T8.md](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-stark-batch/SOUNDNESS-T8.md). The calculator is `design-t8/params8.py --asbuilt`, which reads every shape from the 45 committed vectors' VK data. All 45 match the exported shapes, and the S0 tables match the built constraint graphs field by field.

| statement / set | λ_IOP | binding round | λ (digest 4h) | strict digest |
|---|--:|---|--:|--:|
| M1, Z128 (cap 0 and cap 5) | 128.06 | fold1 | **128** | 127.21 |
| M2, Z128-g, commit PoW 3, lookup PoW 8 | 128.70 | query | **128** | 127.21 |

All figures are "JB; powers batching by [BCIKS20] Thm 7.2, FRI step proved in [BATCHING-PROOF.md](BATCHING-PROOF.md) (internally reviewed, not externally)".

- **Each new charge has its own lemma and round term:** multi-table ALI, DEEP (the script checks Z_H(ζ) ≠ 0 and ζ^n ≠ −1 per instance), batching per height, roll-in at degree a, LogUp, preprocessed columns, and caps with mixed-height injection.
- **AIR ⇒ relation** is proved row type by row type for M1, and through the bus for M2.
- **Chain lemmas cover b2, a′ (1 tx) and the NFT thread,** and an owner table names the script step that fixes or checks every value the verdict depends on.
- **What rests on the powers-batching proof:** the batching round (margin 8.33 bits over 128 for M1, 7.15 for M2), M2's roll-in fold1 (margin 0.87, the tightest), and the per-height split of the batching term. The batching step is a direct application of [BCIKS20] Thm 7.2; the remaining FRI step (per-height ladders, degree-a roll-ins) is proved in [BATCHING-PROOF.md](BATCHING-PROOF.md), reviewed internally but not externally.
  - M1's binding round, the query round, ALI, DEEP and LogUp do not depend on it.
- **One gap was found and closed.** The scripts read proof lanes as unreduced 8-byte integers, as Track 5 did. The constraint interpreter's subtract and negate ops added only p, so a lane in [p + 1, 2^64) could drive an intermediate negative, and the packed extension product was then wrong mod p.
  - The fix adds 2p to the four ops, at no byte cost. An op-level check runs the generated op bodies in libauth on maximal lanes: 64/64 congruent; the pre-fix subtraction form gives a wrong residue on negative lanes (2/2, s8-arith Part A).
  - Every S4–S7 suite was then re-run (§T8.5).
  - No exploit was built or attempted. With the fix, a non-canonical lane is only another encoding of the same residue. That is malleability, with no soundness effect.
- **CTX is bound by the transcript.** The same proof bytes with changed outputs change every challenge while the openings stay fixed, so they are rejected except with negligible probability; the transaction families test exactly this.
  - That a mempool observer cannot make a fresh proof for new outputs needs simulation extractability of the compiled ZK proof. It is **not proved; it is an assumption.**

### T8.7 Reviews and fixes

**Found while writing SOUNDNESS-T8, before the reviews:** the interpreter residue gap (§T8.6). It was fixed at 12d47d4, which also added generator asserts:
- packed-slot bounds;
- next-row reads;
- count_weight;
- ROOT lanes < p;
- the b2 tail length.

**Protocol/soundness review** (it also checked the AIRs against AIR-SPEC): fix, 1 major and 3 minors.
- *Major:* SOUNDNESS-T8 claimed that every suite had been re-run, but the re-run had stopped inside the b2 block when the machine went down, so no b2 or a′ result was post-fix. The re-run was resumed and completed (2026-11-01), every count was regenerated, and the results were committed (726ea25, c47d104).
- *Minor:* Lemma 13 used round-by-round soundness for a true statement. It is now split into same-bytes replay, which is argued directly, and a new proof, which rests on the simulation-extractability assumption.
- *Minor:* stale commit citations, now corrected.
- *Minor:* the case totals mixed in cases that never ran on chain. They are now counted separately (§T8.5).
- The review's code reading confirmed the following against Plonky3 at the pin: the transcript order and domain separators, zero-bit PoW elision, query-bit sampling, the roll-in β^arity, the presence of the lookup-PoW and final-polynomial checks, and the AIRs against AIR-SPEC (M1 53, T_hash 40 + lookup, T_ctl 31 + lookup).

**Measurement review:** fix, 1 major and 5 minors. It re-ran grading for all 32 b2 statements and all 24 a′ statements, plus subset sweeps. Its findings:
- *Major:* the same incomplete re-run.
- *Minor:* quote the post-fix op-cost. It moved by +193 to +307 on the means; bytes are identical, and no budget percentage moved by more than 0.1 point.
- *Minor:* the b2 library hash changed (now 95630cef…26b9).
- *Minor:* separate the not-run-on-chain counts.
- *Minor:* state the S0 op-cost model miss.
- *Minor:* use one BCHN gate, max(std, cons), in every grader. No verdict changed.

Its check of false rejections, using copies of the harnesses that log every chain error, found every rejection to be a real script failure (OP_VERIFY in nearly all cases), never a limit or encoding error.

**Re-review:** An independent re-review of the fix phase and of this report passed with minors (all applied: proof-size range, limits framing, s8-arith wording, reproduce notes); it re-ran the layout-b production suite byte-identically.

### T8.8 Comparison with Track 5 and the design model

| | Track 5 best at 128 bits | Track 8 M1 (ZK, real statement) |
|---|---|---|
| one 100 KB input | mimc-S128 (no ZK, toy AIR): 88.3 KB, 33.9M; fib-S128z (ZK): does not fit | 91.4–95.0 KB, 35.5–36.0M (47.4–48.6%) |
| today's standard rules | mimc-S128: 2 txs, 17 inputs, 123,452 B; fib-S128z (ZK): 3 txs, 35 inputs, 234,553 B | **1 tx, 12 inputs, 98,690 B** |

Against the design and S0 models:

| layout | design (DESIGN-T8 §0) | S0 model | built |
|---|---|---|---|
| b, unlocking | 89–94 KB, about 32M | 87.2–92.2 KB, 28.26M | 91.4–95.0 KB, 35.5–36.0M |
| b2 M1, tx | about 97 KB | 91–96 KB | 96.2–98.3 KB |
| b2 M2, tx | 100–120 KB proof, tx size raised | 146–152 KB | 156.4–159.7 KB |
| a′, today | 2 txs, about 14 inputs, 115–120 KB; 1 tx stretch 101–103 KB | 98.5–101.5 KB (1 tx only with 7.5 KB code) | 1 tx 98,690 B / 2 txs 131,556 B |

- **The op-cost model missed by +26.8%** on layout b (acceptance band ±15%). Queries and Merkle match it. The fixed part does not: the constraint check at ζ costs 7.85–8.03M against an assumed 0.6M, because the model was calibrated on Track 5's toy AIR.
- **The code is larger than modelled:** 19.0 KB redeem (13–18 KB assumed), 19.5 / 27.8 KB b2 libraries (18–24 KB), 9.3 KB a′ code blobs (7.5–9 KB). Put the real code sizes into the byte model and it agrees within about +0.5% to +1.3%.
- **a′ still fits one transaction because of a different design choice:** each QRY input recomputes the α′ ladder, so FIN publishes a 312 B table instead of a 2.3 KB one.

### T8.9 Caveats (Track 8)

- **Post-quantum meaning, stated plainly.** 128 bits is a **classical** figure. Digests are 4-element Poseidon2-Goldilocks (in the circuit) and SHA-256 (commitments and transcript). Generic quantum collision search (BHT) on either reaches **about 85 bits**. That is the level of SHA-256 itself; the maintainer accepted it, and Track 8 has no 6-element digests.
- **The strict reading** of the Fiat–Shamir digest term gives 127.21 bits; "128" uses the usual birthday convention.
- **Every λ rests on the powers-batching argument.** The batching step is a direct application of [BCIKS20] Thm 7.2; the remaining FRI step (per-height ladders, degree-a roll-ins) is proved in [BATCHING-PROOF.md](BATCHING-PROOF.md). That proof has been reviewed internally but not externally, and the DEEP-ALI front end is still inherited from [ADK] Thm 2. M2's roll-in has only 0.87 bits of slack. If the bound needed a larger factor, raising the batch or commit PoW would restore the sets at no byte cost.
- **Simulation extractability is assumed, not proved.** It is what stops a mempool observer from re-binding someone else's proof to new outputs. ZK holds by construction; FRI-layer hiding is open.
- **Not a pool.** ROOT is a script constant, NF is not published in an output, and nothing prevents spending the same note twice. That is Track 9's pool covenant. In the 2-transaction a′ plan, tx0 alone is a partial check: it can mint an NFT for a proof that tx1 would reject, with no other effect. The minting baton must be created at deployment.
- **Tight budget.** The a′ QRY inputs run at about 91% of their op-cost budget, the highest of any input. a′ fits one transaction with 1,310 B to spare.
- **Model miss.** The op-cost model missed by +26.8% (§T8.8). The design's ±15% acceptance criterion for layout b is not met.
- **M2 needs the transaction size limit raised** in layout b2, and M2 does not fit one 100 KB input (152.4 KB in layout b).
- **Coverage vectors are below 128.** Plonky3's three_instances_mixed_sizes vectors come out at 127.90–127.92 bits under our accounting. They are coverage only and are not used by any claim.
- **BCHN node run ([node-check](../node-check/README.md#track-8-stark-m1)):** layout a′ ran on stock BCHN 29.1.0. All 24 statements in both plans were accepted, worst input 91.01% (1 tx) / 91.10% (2 txs) of the budget under BCHN's accounting, with 16.6–17.0 ms Verify per 1-tx proof. `testmempoolaccept` on a default-policy node allows every tx. Layouts b and b2 cannot run on BCHN today, because they need raised limits.
- **Size spread.** Proof size varies with the random query set: M1 by −2.2% to +1.8%, M2 by about ±3.3% (one of 65 proofs fell at −3.29% against S0's ±3%). Prover timings vary widely on this machine.
- **The generators' scope:** ood PoW 0 only; cap 0 for b and b2 and cap 5 for a′.

### T8.10 Sources

groth16_cashscript `main` (once wip/stark-usable is merged), [`research/pq-stark-batch/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark-batch):
- [`prover/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark-batch/prover):
  - the batch-stark prover crate at Plonky3 0d80373: `src/cfg.rs` (sets), `src/stmt.rs` (M1, M2 AIRs and witness), `src/wire.rs`, `src/dag.rs`, `src/s2.rs`;
  - FORMAT.md (p3b-v1, CTX serialization), README.md;
  - `gen-vectors.sh`, `gen-s2.sh`, `vectors/{P3,Z128,S2,S4,S5,S7}`.
- [`verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark-batch/verifier): `verify-batch.mjs` (reference), `gen-cases.mjs`, `agree.mjs`, `gen-s3.sh`, `report/`, README.md.
- [`onchain/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark-batch/onchain):
  - models: `model.mjs`, `modeln.mjs`, `modela.mjs`;
  - generators: `gen.mjs` (b), `genn.mjs` (N tables, b2), `gena.mjs` (a′);
  - layouts: `layout-b.mjs`, `layoutn.mjs`, `layouta.mjs`; `ctx.mjs`, `vm.mjs`, `vmn.mjs`;
  - test and grading scripts: `test-*.mjs`, `grade-*.mjs`, `profile-*.mjs`, `s8-arith.mjs`, `summary-t8.mjs`;
  - pipelines: `gen-s4.sh`, `gen-s5.sh`, `gen-s7.sh`, `rerun-s8b.sh`, `rerun-s8b-resume.sh`;
  - `results/` (all post-fix, including `summary-t8.json`) and README.md (Track 8 S4 through S8b sections).
- [SOUNDNESS-T8.md](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-stark-batch/SOUNDNESS-T8.md).

zk-verifier-bench (this folder, from branch `wip/stark-usable-design` 6050eaf):
- `DESIGN-T8.md`, with the maintainer decisions;
- `design-t8/`: AIR-SPEC.md, air8_ref.py, params8.py (λ tables and `--asbuilt`), bytes8.py, and poseidon2-gl8-constants.json.

Development branch: groth16_cashscript `wip/stark-usable` (S1 f1b1c3f … S8b a6fd286, summary 0d23832).

**Reproduce** (groth16_cashscript `research/pq-stark-batch`; Rust under nice with RAYON_NUM_THREADS=4 and `-j4`; one heavy job at a time; a repo-root `node_modules` (gitignored) holding libauth 3.1.0-next.8):

```sh
export CARGO_TARGET_DIR=/path/cache/target C=/path/cache
cd prover && nice cargo build --release --offline -j4
./gen-vectors.sh                                              # S1: Plonky3 batch AIRs, about 1 min
S2_CACHE=$C/s2 AIR8_REF_DIR=<bench>/research/pq-stark/design-t8 ./gen-s2.sh   # M1/M2, about 4 min
cd ../verifier && S3_CACHE=$C/s3 S2_BATCH=$C/s2/batch ./gen-s3.sh             # Rust/JS agreement, about 3 min
cd ../onchain
S4_CACHE=$C/s4 S3_CACHE=$C/s3 ./gen-s4.sh                                     # layout b, about 20 min
S5_CACHE=$C/s5 S4_CACHE=$C/s4 S3_CACHE=$C/s3 ./gen-s5.sh                      # layout b2
S7_CACHE=$C/s7 S4_CACHE=$C/s4 S3_CACHE=$C/s3 ./gen-s7.sh                      # layout a'
node s8-arith.mjs                                                             # residue check, seconds
S3_CACHE=$C/s3 S4_CACHE=$C/s4 S5_CACHE=$C/s5 S7_CACHE=$C/s7 ./rerun-s8b.sh    # all node suites on cached proofs, about 2 h
node summary-t8.mjs                                                           # results/summary-t8.json
# soundness tables (bench, research/pq-stark/design-t8):
python3 params8.py && python3 params8.py --asbuilt $V/S2 $V/S4 $V/S5 $V/S7 $V/Z128 $V/P3   # V = prover/vectors
```

---

## Track 5 (2026-10-29): the first Plonky3 build

Date: 2026-10-29. Status: research. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json, and the website is unchanged. Two internal reviews were done: protocol/soundness (2 majors, 4 minors) and measurement (pass, 7 minors). All findings are fixed or stated as caveats below.

## 1. Question

Track 4 ([../pq-hash/REPORT.md](../pq-hash/REPORT.md)) measured a SHA-256 DEEP-FRI STARK verifier over Goldilocks for a toy MiMC statement, using our own prover. It left four things open. Track 5 asks whether the verifier can be made usable:

1. **Soundness:** does the per-round Fiat-Shamir condition hold, so that P100 and P128 are at target? Track 4's margins at P128 were 0.19-0.31 bits.
2. **Real prover:** can CashVM verify proofs from an off-the-shelf configurable prover (Plonky3 with SHA-256 and Goldilocks), for more than one AIR?
3. **Zero knowledge:** what does a hiding proof cost?
4. **Field cost:** field arithmetic was ~84% of op-cost. How much of it can be cut, and what does that buy?

Regimes, as in Track 4:
- **Today's standard rules:** 10,000 B unlocking per input, 201 B P2S locking, 100,000 B per transaction, base 41.
- **100 KB inputs:** TXv5, with 100,000 B items and scripts, base still 41.
- bch-spec (base 10,000) is given where it was measured.

BCHN-adjusted op-cost adds the OP_DEFINE body bytes that libauth does not charge. It is on the standard basis unless marked.

## 2. Soundness result

Details are in [soundness/SOUNDNESS.md](soundness/SOUNDNESS.md). The calculator is [soundness/params5.py](soundness/params5.py); it imports Track 4's params.py, and its output is in params5-output.txt and params5-output.json.

The open Fiat-Shamir condition holds. **Track 4's P100 and P128 are at target as built; no fix is needed.**

**Bound used:**
- Per-round errors come from Atapoor, Delpech de Saint Guilhem and Al Kindi (ADK, IACR CiC 3(2), ePrint 2024/1553):
  - Thm 2: DEEP-ALI with batched FRI, list decoding.
  - Thm 3: the unique-decoding version.
  - Thm 1: round-by-round soundness implies state-restoration soundness.
- These rest on BCIKS20: Thm 7.2/7.4, and Lemma 8.2 with §8.2.1 (one bad event per round).
- The Fiat-Shamir step is Block et al., ePrint 2023/1071, Cor. 5: ε_fs ≤ Q·ε_rbr + 3(Q²+1)/2^κ.
- Each per-round error is one summand of BCIKS20's combined ε_C. That is exactly the condition Track 4 left open.

**Grinding and digests:** grinding is charged per round. The digest term is 4h bits. The strict reading of Cor. 5's constant gives 4h − 0.79, which is reported alongside.

| set | ρ | queries | λ_IOP (bits) | binding round | proof B | note |
|---|---|--:|--:|---|--:|---|
| P100 (Track 4) | 2^-7 | 22 | 100.11 | query | 50,022 | commit 124.19; strict digest 99.21 at h = 25 (h = 26: 51,209 B) |
| P128 (Track 4) | 2^-5 | 43 | 128.19 | query (0.19 margin) | 91,468 | merged γ/β_1 round 128.65 (old model 128.31) |
| U100 (Track 4) | 2^-4 | 79 | 100.09 | - | 107,423 | unique decoding |
| U128g (Track 4) | - | - | 128.44 | - | 166,568 | unique decoding + g_c nonces |
| T5-100 (proposed) | 2^-8 | 19 | 100.77 | query | 46,010 | folds 4/16, no commit grinding |
| T5-128 (proposed) | 2^-8 | 26 | 128.12 | query | 70,288 | +12-bit PoW before γ/β_1, +5 before β_2 |
| P128-lite (proposed) | 2^-6 | 35 | 128.19 | query | 81,474 | +5-bit PoW before γ/β_1 |

- **Commit grinding is the useful knob.** With the per-round bound, grinding on individual commit challenges lets T5-128 use 26 queries instead of 43.
- **The proposed sets are not built.** T5-100 and T5-128 need a 2^24-row LDE in the prover. The T5 and P128-lite byte figures are calculator figures; they were not built in Track 4's format.
- **No 256-bit hash meets the strict digest reading at 128 bits.** "128" follows the usual birthday-bound convention. For S128 that means 128.17, or 127.21 under the strict reading.

**Plonky3's protocol is a different statement.** Plonky3 batches constraints and DEEP openings with powers of one challenge, not with independent γ_j.
- The batching term for that is a direct application of BCIKS Thm 7.2 (in place of 7.4 inside ADK Thm 2). The remaining FRI step is proved in [BATCHING-PROOF.md](BATCHING-PROOF.md) (SOUNDNESS.md §2.1 has the original sketch).
- **That proof is reviewed internally, not externally.** So every Plonky3 figure below is labelled "JB; powers batching by BCIKS20 Thm 7.2, FRI step proved in BATCHING-PROOF.md (internally reviewed, not externally)". Only Track 4-format sets rest entirely on published theorems.
- This term is close to binding for the S sets (batching round vs query round):
  - S100b: 100.66 vs 100.25.
  - S100z: 100.39 vs 100.21.
  - S128: 129.38 vs 128.17.
- If the bound needed a larger factor, raising Plonky3's batch PoW would restore these sets. That knob costs no proof bytes.

**Other Plonky3 findings:**
- **e = 2 cannot reach 128 bits.** This is the stock BinomialExtensionField<_,2>. The best is 125 bits:
  - uni-stark has no PoW site before the constraint-folding α.
  - So the ALI round is stuck at 128 − log2(L·#constraints), which is 126 in unique decoding.
  - At about 100 bits, e = 2 needs 79 queries (unique decoding, 148 KB).
- **e = 3 works with the stock CubicTrinomialExtensionField** (u^3 = u + 1). We checked that x^3 − x − 1 is irreducible over Goldilocks, so no patch is needed. The stock degree-5 extension also works (128.17 bits, 94.4 KB modelled).
- **Plonky3's own Johnson-regime estimator** relies on ePrint 2026/2056 (DKT26), which is not peer reviewed. It appears only as a sensitivity row.
- **Cross-check:** the unique-decoding Plonky3 terms match p3-security (commit 0d80373) term by term, checked by hand against the source. p3-security itself was not run.

## 3. Real prover: Plonky3

Sources are in groth16_cashscript main, [`research/pq-stark/prover/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark/prover):
- Cargo.toml pins Plonky3 0d803737b681774186cd283b1fd2d8e493655c82.
- src/{cfg,airs,sets,wire,main}.rs is the prover.
- FORMAT.md describes the wire format (p3s-v1).
- verify.mjs is a JS reference verifier.

**Configuration (stock parts only):**

| component | Plonky3 type |
|---|---|
| field | Goldilocks; challenges in CubicTrinomialExtensionField (e = 3) or BinomialExtensionField<_,2> (C100 only) |
| Merkle leaves | SerializingHasher<Sha256> (u64-LE row, plus salt in ZK) |
| Merkle nodes | CompressionFunctionFromHasher<Sha256,2,32>, i.e. SHA256(l‖r) |
| Fiat-Shamir and PoW | SerializingChallenger64<Goldilocks, HashChallenger<u8,Sha256,32>> |
| 25-byte digests | small custom TruncSha256 (src/cfg.rs) |
| ZK | HidingFriPcs + MerkleTreeHidingMmcs |
| AIRs | Fibonacci and MiMC, one trace, n = 2^16 rows |

**What did not work, or needed care:**
- **Node hashing:** `p3_sha256::Sha256Compress` must **not** be used for Merkle nodes. It is the raw compression function without padding, which OP_SHA256 cannot compute.
- **Cubic extension:** Plonky3 has no binomial cubic extension for Goldilocks, only degrees 2 and 5. The cubic trinomial fills the gap.
- **Proof size:** with Track 4's own parameters, Plonky3 proofs are **larger**:
  - P100: 58,183 B vs 50,022 (+16%).
  - P128: 110,765 B vs 91,468 (+21%).
  - The reason is that Plonky3 commits the combined DEEP polynomial as its own full-height FRI tree. Track 4 folds straight from coset-grouped trace leaves.
- **CPU load:** the Rust prover with 25-28 bits of PoW uses all 24 cores. It was not re-run after the first phase; everything later ran single-threaded under nice.

**Parameter sets built.** All use n = 2^16. The prover's sets.rs builds each one as `mk(ext, log_blowup, queries, query PoW, max_log_arity, log_final_poly_len)`, plus commit and batch PoW.

| set | e | log_blowup | queries | PoW q / c / b | max_log_arity | log_final | λ (bits, our bound) | mimc proof B |
|---|--:|--:|--:|---|--:|--:|---|--:|
| C100 | 2 | 3 | 27 | 21 / 0 / 0 | 3 | 5 | conjectured 100 only (JB 59.6) | 56,893 |
| C128 | 3 | 3 | 36 | 22 / 0 / 0 | 3 | 5 | conjectured 128 only (JB 74.9) | 81,717 |
| P100 (h = 25) | 3 | 7 | 22 | 28 / 0 / 0 | 3 | 5 | 100 (strict 99.21) | 58,183 |
| P128 | 3 | 5 | 43 | 28 / 0 / 0 | 3 | 5 | **125.94** (Plonky3 estimator 128) | 110,765 |
| S100 | 3 | 5 | 30 | 27 / 0 / 0 | 3 | 7 | 101.11 | 76,019 |
| S100b | 3 | 8 | 19 | 25 / 0 / 0 | 4 | 8 | 100.25 | 60,793 |
| S128 | 3 | 8 | 26 | 26 / 15 / 23 | 4 | 8 | 128.17 | **78,393** |
| S128b | 3 | 5 | 41 | 28 / 7 / 14 | 3 | 7 | 128 | 99,795 |
| S100z (ZK) | 3 | 8 | 19 | 25 / 0 / 3 | 4 | 6 | 100.21 | - (fib 85,853) |
| S128z (ZK) | 3 | 8 | 26 | 27 / 13 / 22 | 3 | 8 | 128 | - (fib 112,501) |

**Tests:**
- There are 45 valid proofs (fib and mimc, with a second statement for several sets) and 1,114 tampered variants: 1,159 cases in all.
- Both the JS verifier and Plonky3's own verifier give 0 unexpected results.
- Every SHA-256 transcript input of the JS verifier matches the one recorded inside Plonky3's verifier, byte for byte.
- Query indices are raw u64 bits, so they are uniform.

**Protocol as verified.** verify.mjs implements it, and the on-chain verifier mirrors it.
- **Transcript:** one running SHA-256 challenger, seeded with three domain-separator seeds. The seeds depend only on the verifying key, so they are baked in as constants and no Keccak is needed on chain.
- **Order:**
  1. Observe the trace root and public values, sample α.
  2. Observe the quotient root (and the random-polynomial root in ZK), sample ζ; require ζ^n ≠ 1.
  3. Observe the opened values, check the batch PoW, sample α'.
  4. For each FRI round: observe the root, check the commit PoW, sample β.
  5. Observe the final polynomial, check the query PoW, sample the indices.
- **Per query:**
  - Check the input Merkle openings.
  - Compute the reduced opening at x = 7·g^rev(idx).
  - Apply Lagrange folds over cosets of arity 8 or 16.
  - Check against the final polynomial.
- **AIR check at ζ:** unnormalised selectors, and the quotient recomposed over disjoint cosets.

## 4. Zero-knowledge result

**ZK works in Plonky3 at this commit** (HidingFriPcs with MerkleTreeHidingMmcs), and CashVM verifies the hiding proofs. The "zkmin" variant uses random codewords = D (the extension degree) and a 2-element salt (about 128 bits).

| set (fib unless noted) | plain B | ZK (zkmin) B | overhead | λ (bits) | fits one 100 KB input |
|---|--:|--:|--:|---|---|
| P128 fib / mimc | 108,213 / 110,765 | 158,751 / 175,047 | +47% / +58% | 124.15 / 123.41 | no |
| C128 fib / mimc | 79,677 / 81,717 | 121,431 / 128,135 | +52% / +57% | conjectured only | no |
| P100 fib / mimc | 58,259 / 58,183 | 98,055 / 102,695 | +68% / +77% | 103.7 / 103.59 | no |
| S100z vs S100b | 59,809 | **85,853** | +44% (params differ slightly) | 100.21 | **yes** (37% of budget) |
| S128z vs S128 | 78,337 | **112,501** | +44% (arity 8 vs 16) | 128 | no (126,183 B unlocking) |

- **Basis:** Haböck and Al Kindi, ePrint 2024/1037 §4.2, and Plonky3's HidingFriPcs design. ZK holds **by Plonky3's construction; it is not proven here.**
- **Conditions,** read from the Plonky3 source:
  - **Mask height:** n = 2^16 must be ≥ 2·(D·#points + Q). The worst case is P128, at 98 ≤ 65,536. Plonky3's prover and verifier both enforce this.
  - **Random codewords:** at least D.
  - **Salt:** 2 elements.
- **Not checked independently:** whether Plonky3's Q-count also covers the FRI-layer sibling openings.
- **The committed ZK vectors use a fixed StdRng seed (1000 + k)** so they can be reproduced. These particular proofs hide nothing; they are test vectors for size and verification only.
- **P100's overhead is larger** partly because the plain P100 proof uses 25-byte digests.

## 5. Field-cost result

These figures are measured on Track 4's own proofs and verifier. Proof bytes, Merkle checks and soundness are unchanged.
- **Generator:** groth16_cashscript main, [`research/pq-stark/field/verifier/gen.mjs`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark/field/verifier/gen.mjs).
- **Kernels:** [field/kernels](field/kernels).
- **Full write-up:** field/REPORT.md.

| | Track 4 | Track 5 field |
|---|---|---|
| P128-0, one 100 KB input, op-cost std | 71,541,117 | **50,053,779 (-30.0%)** |
| P128 share of base-41 budget | ~90% | 63.2-64.9% (P128-0..3) |
| P128-0 bch-spec | - | 58.8% |
| P100-0, one 100 KB input | 38,728,435 | 27,861,234 (-28.1%) |
| P128 per query | 1,403.7k | 894.1k (-36%) |
| P128-0 today standard | 19 inputs, 2 txs, 154,831 B, 91.7M | 19 inputs, 2 txs, 150,891 B, 81.2M (BCHN 81.5M) |
| P100-0 today standard | 10 inputs, 1 tx, 77,623 B | 10 inputs, 1 tx, 70,764 B |

**What worked** (saving per P128 query):
- Group-packed final polynomial, H = 8: 206k, but +321k once per proof to unpack.
- Packed DEEP numerators with lazy reduction: 136k.
- Packed folds, with F_p^3 values in 26-byte slots and packed rotation columns of β: 129k.
- x0 from runtime 4-bit window tables: 45k.

**Why packing pays:** OP_MUL is charged by operand length. One wide multiply plus one OP_MOD per slot replaces nine narrow multiplies. Most of the saving is fewer instructions and fewer stack fetches.

**Honest negative:** under today's standard rules **the input count does not drop.** Query inputs are byte-bound (3 queries per 10 KB input) and now use 81% of their op-cost budget. The only gain is less padding.

**Not applied:**
- **Witnessed inverses:** -18.5k per query, but +2.75 KB at P128, so the proof would no longer fit one input.
- **Packing H = 16:** worse than H = 8.
- **Degree-2 extension:** 2.1× cheaper per multiply, but §2 shows e = 2 cannot reach 128 bits in Plonky3.

After the change, Merkle is about 19% of op-cost and field arithmetic about 80%. The Plonky3 verifier in §6 reuses the same packed functions: PKL, UR, PAIRK, FOLD, DPK, the group-packed final polynomial and the window tables.

## 6. Verifier measurements (Plonky3 proofs on CashVM)

Sources are in groth16_cashscript main, [`research/pq-stark/verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark/verifier):
- air.mjs: the per-AIR constraint descriptions.
- model.mjs: a JS model of the on-chain algorithm.
- gen.mjs: layout (b).
- gen-a.mjs and layout-a.mjs: layout (a).

Full tables for all 45 vectors are in [verifier/results/tables.md](verifier/results/tables.md). Security per vector is in [verifier/security.json](verifier/security.json), produced by [verifier/security.py](verifier/security.py).

**Correctness:**
- All 45 valid proofs are accepted on the real libauth BCH 2026 VM, in both layouts.
- The JS model agrees with verify.mjs on all 1,159 cases.
- **One-input sweep (layout b):** 2,302 cases, 0 unexpected. That is 45 valid proofs, 1,114 tampered proofs rejected, and 1,143 witness manipulations rejected (most keep the item count and sizes).
- **Today's-rules sweep (layout a):** 417 cases on 8 representative vectors, 0 unexpected.
- **Encoder-only rejections:** 15 malformed-format cases in layout (a) are refused by the witness encoder, not by the script. These are a trailing byte, and an extra sibling with the count raised. Layout (a) carries full Merkle paths, so the script sees the valid proof inside them. The one-input script rejects them.

### 100 KB inputs (layout b, one input, TXv5, base 41)

| vector | λ (bits) | proof B | unlocking B | op-cost std | BCHN-adj. | % of budget | bch-spec % |
|---|---|--:|--:|--:|--:|--:|--:|
| mimc-S128-0 | 128 | 78,393 | 88,342 | 33.87M | 33.87M | **47.9%** | 43% |
| fib-S128-0 | 128 | 78,337 | 87,311 | 33.40M | 33.41M | 47.8% | 42.9% |
| mimc-S100b-0 | 100.25 | 60,793 | 70,392 | 25.64M | 25.65M | 45.5% | 39.9% |
| mimc-S100-0 | 101.11 | 76,019 | 86,270 | 30.58M | 30.58M | 44.3% | 39.7% |
| mimc-P100-0 (h = 25) | 100 (strict 99.21) | 58,183 | 68,380 | 23.83M | 23.83M | 43.5% | 38% |
| fib-S100z-zkmin-0 (ZK) | 100.21 | 85,853 | 99,376 | 29.42M | 29.42M | 37% | 33.6% |
| mimc-C128-0 | conjectured only | 81,717 | 92,435 | 33.85M | 33.85M | 45.8% | 41.3% |
| mimc-P128-0 | 125.94 | 110,765 | 122,057 | 42.05M | - | - | does not fit |
| mimc-S128b-0 | 128 | 99,795 | 110,710 | 40.62M | - | - | does not fit |
| fib-S128z-zkmin-0 (ZK) | 128 | 112,501 | 126,183 | 38.49M | - | - | does not fit |

23 of the 45 vectors fit one 100 KB input, and all of those are accepted on TXv5 (standard and consensus) and on bch-spec. The other 22 (P128, S128b and most ZK vectors) are too large. A two-input 100 KB layout was not built.

### Today's standard rules (layout a)

| vector | λ (bits) | txs | inputs | total B | op-cost std | BCHN-adj. |
|---|---|--:|--:|--:|--:|--:|
| mimc-S128-0 | 128 | 2 | **17** | 123,452 | 65.54M | 65.83M |
| mimc-S100b-0 | 100.25 | 1 | 12 | 83,515 | 48.09M | 48.28M |
| mimc-P100-0 | 100 | 1 | 13 | 85,649 | 41.62M | 41.84M |
| mimc-P128-0 | 125.94 | 2 | 26 | 185,338 | 82.21M | 82.66M |
| mimc-S128b-0 | 128 | 2 | 25 | 166,343 | 84.26M | 84.69M |
| fib-S100z-zkmin-0 (ZK) | 100.21 | 2 | 25 | 136,556 | 81.70M | 82.30M |
| fib-S128z-zkmin-0 (ZK) | 128 | 3 | 35 | 234,553 | 134.43M | 135.27M |
| mimc-P128-zkmin-0 (ZK) | 123.41 | 4 | 55 | 370,922 | 223.34M | 225.29M |

How layout (a) is split across inputs:
- One input holds the transcript part and checks the AIR.
- One or more inputs carry the code, loaded by a 59-236 B redeem.
- The remaining inputs each verify 1-2 queries, with full Merkle paths.
- Multi-transaction plans are linked by an NFT thread. Its commitment binds each transaction to the final transcript digest G.

Every input passes standard and consensus, and every transaction passes libauth's whole-transaction check.

### Where the op-cost goes (layout b)

| vector | queries | per query: x / DEEP / folds / final | Merkle (share) | AIR-specific op-cost | AIR-specific code |
|---|--:|---|--:|--:|--:|
| mimc-S128-0 | 26 | 13k / 89k / 505k / 277k | 8.30M (24.5%) | 259,790 (0.77%) | 664 B (7.5% of redeem) |
| fib-S128-0 | 26 | 13k / 80k / 505k / 276k | 8.44M (25.3%) | 131,177 (0.39%) | 332 B (4.2%) |
| mimc-P128-0 | 43 | 13k / 89k / 448k / 65k | 13.90M (33.1%) | 260,464 (0.62%) | 664 B (7.3%) |

The constraint evaluation generated from each AIR's description is only 0.2-1.1% of op-cost. The generic part dominates: folds are 57% of a query at arity 16, and Merkle checking is 25-40% of the total.

## 7. Comparison with Track 4

| | Track 4 P128 | Track 4 P128 + Track 5 field | Track 5 S128 (Plonky3) |
|---|---|---|---|
| prover | own MiMC prover | own MiMC prover | Plonky3 0d80373, any supported AIR (fib, mimc built) |
| soundness | 128.19, per-round bound now settled (published theorems) | same | 128.17 (powers batching by BCIKS20 Thm 7.2; FRI step internally reviewed, not externally) |
| proof | 91,468 B | 91,468 B | 78,393 B |
| one 100 KB input | 71.54M, ~90% | 50.05M, 64.9% | **33.87M, 47.9%** |
| today standard | 19 inputs, 2 txs, 154,831 B | 19 inputs, 2 txs, 150,891 B | **17 inputs, 2 txs, 123,452 B** |
| ZK | no | no | yes (S128z: 112,501 B, 3 txs today, not one input) |

| | Track 4 P100 | Track 4 P100 + field | Track 5 S100b | Track 5 P100 (Plonky3, h = 25) |
|---|---|---|---|---|
| proof | 50,022 B | 50,022 B | 60,793 B | 58,183 B |
| one 100 KB input | 38.73M | 27.86M (61.5%) | 25.64M (45.5%) | 23.83M (43.5%) |
| today standard | 10 inputs, 1 tx | 10 inputs, 1 tx, 70,764 B | 12 inputs, 1 tx, 83,515 B | 13 inputs, 1 tx, 85,649 B |

**At 128 bits, Plonky3's S128 beats Track 4 on every axis.** Against Track 4's P128, S128 has:
- a 14% smaller proof;
- 53% less op-cost in one input;
- 2 fewer inputs under today's rules.

**At 100 bits, Track 4's own format stays smaller** and needs fewer inputs today. Plonky3's extra DEEP tree costs bytes, and today's inputs are byte-bound.

## 8. Caveats

- **Plonky3 soundness rests on the powers-batching argument:** a direct application of BCIKS20 Thm 7.2, with the remaining FRI step proved in [BATCHING-PROOF.md](BATCHING-PROOF.md), reviewed internally but not externally. The S sets are close to binding on that term. Only the Track 4-format sets (P100, P128, T5-*) rest entirely on published theorems.
- **P128 in Plonky3 is not 128 bits** under our bound: 125.94 (mimc) and 126.31 (fib), and 123.2-124.2 for the ZK variants. 128 is Plonky3's own estimator only. Use S128 or S128b instead.
- **The C sets are conjectured secure only:** about 60 bits proven for C100 and 75 for C128.
- **"128 bits" follows the birthday-bound convention** for 256-bit digests. The strict reading of Cor. 5 is 4h − 0.79, which gives 127.21 for S128.
- **ZK is by construction, not proven here.** FRI-layer hiding was not checked independently, and the committed ZK vectors use a fixed seed and hide nothing.
- **The on-chain verifier deviates from Plonky3 in two ways:**
  - A challenge sample ≥ p is rejected rather than redrawn. That costs about 2^-32 of completeness per sample and has no soundness effect.
  - Leaf, OOD and final-polynomial values are not range-checked. This is language-level malleability with no soundness impact, because a non-canonical twin is a different oracle query. The check was not built or measured.
- **The on-chain verifier supports a limited AIR shape:** one trace, committed matrices of equal height, no preprocessed columns, no lookups. Unequal heights would change the soundness charge (arity a, not a − 1).
- **Some byte figures are calculator figures, not builds:** T5-*, P128-lite and the Plonky3 "full-path" model sizes. The model's dedup column does match measurements (S128: 79,704 B modelled vs 78,393 B measured).
- **Most ZK proofs, and P128/S128b, do not fit one 100 KB input.** A two-input 100 KB layout is the next build.
- **Reproduction requirements:**
  - The untracked `node_modules` link to Track 4's libauth 3.1.0-next.8 install.
  - `PQ_FIELD_SRC` for the field kernels.
  - Run node single-threaded under nice; the Rust prover with high PoW uses every core.
- **BCHN node run (Track 8a, [node-check](../node-check/README.md)):** on stock BCHN 29.1.0 the today's-rules txs of mimc-S128-0, mimc-S100b-0, fib-S100z-zkmin-0 and fib-S128z-zkmin-0 are accepted, and the sampled rejection cases rejected, matching libauth. A default-policy node allows every tx (`testmempoolaccept`), including the chained ones. Verify time is 7–13 ms per tx. The 100 KB-input layouts can't run on BCHN today.

## 9. Sources

Research files in this folder:
- [soundness/](soundness/): SOUNDNESS.md, params5.py and params5-output.{txt,json}.
- [verifier/](verifier/): security.py, security.json, README.md and results/ (layout-a.json, layout-b.json, profile-b.json, tables.md, logs).
- [field/](field/): kernels/k-field5.mjs, run.mjs, results/k-field5.json and REPORT.md.

Verifier and prover sources are in groth16_cashscript, to be merged to main by the maintainer:
- [`research/pq-stark/prover/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark/prover) (Plonky3 prover, FORMAT.md, verify.mjs, vectors/).
- [`research/pq-stark/field/verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark/field/verifier) (Track 4 generator with packed field functions).
- [`research/pq-stark/verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark/verifier) (CashVM verifier for Plonky3 proofs, both layouts).

References:
- ADK, ePrint 2024/1553.
- BCIKS20, ECCC TR20-083 rev 3.
- Block, Garreta, Katz, Thaler, Tiwari, Zając, ePrint 2023/1071.
- Haböck and Al Kindi, ePrint 2024/1037.
- DKT26, ePrint 2026/2056 (sensitivity row only).
- Plonky3 commit 0d803737b681774186cd283b1fd2d8e493655c82.
