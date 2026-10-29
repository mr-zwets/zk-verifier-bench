# Track 5: a usable post-quantum SHA-256 STARK verifier on CashVM

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
- The batching term for that is our own adaptation: BCIKS Thm 7.2 used in place of 7.4 inside ADK Thm 2. SOUNDNESS.md §2.1 has a proof sketch.
- **It is not peer reviewed.** So every Plonky3 figure below is labelled "JB, powers-batching adaptation, unpublished". Only Track 4-format sets rest on published theorems.
- This term is close to binding for the S sets (batching round vs query round):
  - S100b: 100.66 vs 100.25.
  - S100z: 100.39 vs 100.21.
  - S128: 129.38 vs 128.17.
- If the adaptation needed a larger factor, raising Plonky3's batch PoW would restore these sets. That knob costs no proof bytes.

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
| soundness | 128.19, per-round bound now settled (published theorems) | same | 128.17 (powers-batching adaptation, unpublished) |
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

- **Plonky3 soundness rests on our unpublished powers-batching adaptation** (SOUNDNESS.md §2.1, a sketch that is not peer reviewed). The S sets are close to binding on that term. Only the Track 4-format sets (P100, P128, T5-*) rest on published theorems.
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
- **No BCHN timing was measured.**

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
