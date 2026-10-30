# Track 8 design: making the STARK verifier usable

Status: this is a design. Nothing has been built or proved yet. Plonky3 claims were checked against the source at pin 0d80373 (`~/.cargo/git/checkouts/plonky3-7d8a3b21a665a86f/0d80373`). Sizes were recomputed with a byte model that reproduces design A's figures to within 10 B. The model is `/tmp/claude-1000/-home-mrzwets-BCH-projects-verifier-cash/cee4e8ef-c674-4939-b1b7-b1ff05774a8a/scratchpad/syn.py`.

## 0. Decisions

1. **Pin.** Stay at 0d80373 and use `p3-batch-stark` as the only protocol.
   - Checked at the pin:
     - single-instance proving: `test_single_instance`;
     - periodic columns with ZK: `test_periodic_air_zk`;
     - mixed heights: `test_three_instances_mixed_sizes`;
     - preprocessed columns: `test_mixed_preprocessed`;
     - LogUp lookups: `p3-lookup` with `check_multiplicity_height_bound`.
   - Merkle caps (`cap_height`, `MerkleCap`) are available in both `MerkleTreeMmcs` and `MerkleTreeHidingMmcs`.
   - A one-table statement is the N = 1 case of the same verifier. That leaves one transcript, one wire format and one generator.
2. **Verifier.** A generator (from design A) compiles a verifying key into the script, and all shape logic is fixed at generation time. The verifying key is the batch shape exported from Plonky3: tables, heights, widths, preprocessed columns, periodic columns, lookups and the symbolic constraint DAG from `batch-stark/src/symbolic.rs`.
3. **Statement: M1** (from design B, with corrections). A fixed-denomination, zero-knowledge spend:
   - Merkle membership at depth 30 plus a nullifier;
   - context binding (CTX);
   - one table, Poseidon2-Goldilocks width 8 with one round per row: 17 columns, n = 2^10, constraint degree 4, 8 ZK quotient chunks.
   - A's 57-column degree-2 AIR loses on every axis:

     | | opened values | proof, lb8/Q26 | proof, lb10/Q21 |
     |---|--:|--:|--:|
     | A's AIR | 150 | 79.2 KB | 71.5 KB |
     | B's AIR | 94 | 76.2 KB | 68.5 KB |
4. **Generality vector: M2** (from design A, rebuilt on B's AIR). The same relation split into:
   - `T_hash` at 2^10 rows;
   - `T_ctl`, a short control table;
   - preprocessed level and mode tags;
   - a global LogUp bus.

   M2 is a required test vector for Goal 1, not the production statement. It runs in the two-input layout.
5. **Parameter set Z128** (from design B):
   - D = 3 (cubic trinomial), log_blowup 9, one arity-8 fold (LDE 2^20 → 2^17), final polynomial of length 256;
   - Q = 24; PoW: query 24, commit 2, batch **20** (B had 12, which leaves the batch round at 128.33, too close to the target);
   - rc = 3, salt 2.
   - Cap: 0 for the 100 KB layouts and 5 for today's-rules layout. Each deployment picks one.
   - M2 uses **Z128-g**: the same set with final polynomial length 2^5, so that heights 20 and 17 lie on the arity-8 grid (see §2.3).
6. **Regimes and corrected targets** (models, before building):

   | regime | M1 | M2 |
   |---|---|---|
   | one 100 KB input (TXv5), cap 0 | proof ≈ 73.4 KB, unlocking ≈ 89–94 KB, ≈ 32M op-cost (≈ 42%) | does not fit |
   | two 100 KB inputs | ≈ 60 + 37 KB, which is about the 100,000 B transaction limit | ≈ 100–120 KB proof, needs TXv5 transaction size |
   | today's rules, cap 5 | baseline 2 transactions, ≈ 14 inputs, ≈ 115–120 KB; 1 transaction (12 inputs, ≈ 101–103 KB) is a stretch goal | out of scope |

   For comparison, Track 5's toy S128z needed 3 transactions, 35 inputs and 234.5 KB.

## 1. Scope

**In Track 8:**
- A batch-stark prover crate at the pin and the p3b-v1 wire format.
- A JS reference verifier and the generator.
- On-chain verification of M1 in all three layouts (one input, two inputs, today's rules).
- On-chain verification of M2 and of Plonky3's own batch test AIRs in the two-input layout.
- Context binding of ROOT, NF and CTX. Every public value is range-checked (< p).
- SOUNDNESS-T8.md and params8.py.
- Three reviews.
- A Track 8 section in REPORT.

**Out of Track 8:**
- The pool covenant itself: deposits with an in-Script Poseidon2 root update, a nullifier set or accumulator (double-spend prevention), root history. These are a candidate Track 9. An optional microbenchmark is in S9.
- Notes that carry a value: +1 permutation, which means depth 29 or n = 2^11.
- Width-12 / 6-element digests for 128-bit quantum collision resistance.
- An indexed-Merkle nullifier tree in the circuit.
- `multi-stark`, GKR, WHIR and STIR.
- A pin bump.
- A ZK proof (ZK stays "by construction"), FRI-layer hiding analysis, and wallet or phone provers.
- BCHN timing.
- LogUp inside the production statement. It appears only in M2.

## 2. Plonky3 facts the design relies on (checked at 0d80373)

1. **Salts are per matrix per query** (`hiding_mmcs.rs`: `salts[q][m]`). Each quotient chunk is its own matrix with D + rc = 6 columns (`hiding_pcs.rs` around line 541). The FRI MMCS is the hiding MMCS, so FRI leaves are also salted (Track 5 `cfg.rs`). Per-query leaf bytes for M1:

   | leaf | bytes |
   |---|--:|
   | trace | 176 |
   | quotient | 8 × 64 = 512 |
   | random | 64 |
   | fri0 | 184 |
   | **total** | **936** |

   B assumed 400 B for the quotient leaf, which is 2.7 KB too low over 24 queries.
2. **Quotient chunks**: `2^zk · 2^ceil(log2(max(d+zk,2)−1))`. In ZK, degree 2 gives 4 chunks and degree 3 or 4 gives 8 (`uni-stark/src/symbolic.rs:126`; batch-stark computes the same per instance).
3. **FRI input heights.** `validate_input_height` requires log_LDE_height > log_final_poly_len + log_blowup, a strict inequality. A wrote "≥". The arity of a round is capped so that each round lands on every input height. Consequences:
   - Under Z128, every table needs n_i ≥ 2^8.
   - A's `T_ctl` at 2^6 is invalid even under A's own parameters.
   - Z128-g (final length 2^5) accepts n_ctl = 2^7 at LDE height 17, with clean folds 20→17→14.
4. **Hiding budget**: n_i ≥ 2(D·points + Q) per matrix. At Q = 24 and 2 points that is 60. The random matrix is checked at domain.size()/2.
5. **Mixed heights in p3-security.** `security/src/fri.rs` lines 41 and 58: the bounds "assume every committed word has the largest height" and "callers that commit words of several heights must not use these bounds". Our own accounting is therefore required (§6).
6. **Caps**: the effective cap height is reduced so that every injected matrix sits at or below the cap. M1 has one height, so this does not apply. For M2 the generator must use the effective cap height.

## 3. Statement M1

**Public values** (12 elements, all canonical, < p):
- ROOT[4];
- NF[4];
- CTX[4] = SHA-256(serialized outputs) split into four 56-bit chunks, computed by the script through introspection.

**Witness:** nk[4], r[4], bits b_1..b_30, siblings S_1..S_30.

**Relation.** P is Poseidon2-Gl-8 from the stock p3-goldilocks constants (4+4 full rounds, 22 partial rounds, x^7), and T keeps the first 4 lanes.
- NF = T(P(nk‖0,0,0,TAG_NF))
- leaf = T(P(NF‖r))
- node_i = T(P(swap_{b_i}(node_{i−1}, S_i)))
- ROOT = node_30

A fixed depth of 30, enforced by the trace height, removes leaf/internal-node confusion. For one leaf there is exactly one NF unless T∘P has a collision.

**AIR**, 32 slots of 32 rows each:
- Slot 0 computes NF, slot 1 the leaf, slots 2..31 the path.
- Within a slot: row 0 is the input (L row); row 0→1 applies M_E; rows 1–4 and 27–30 are full rounds (F), rows 5–26 partial rounds (Pt); row 31 is the chain row (C).
- Main columns (17): s[8] (state), u[8] (cube registers; on C rows u0..u3 hold the sibling and u4 the bit), and z.
- Periodic columns (period 32, 11): rc[8], F, Pt, C. L = 1 − F − Pt − C.

**Constraints**, written explicitly because B's draft was ambiguous here:
- **S-box:** σ_i·(u_i − (s_i+rc_i)^3) = 0, with σ_0 = F + Pt and σ_{i≥1} = F.
- **Round:** (1 − C)·next_j − [F·Σ ME_{j,i}·u_i²(s_i+rc_i) + Pt·(MI_{j,0}·u_0²(s_0+rc_0) + Σ_{i≥1} MI_{j,i}·s_i) + L·Σ ME_{j,i}·s_i] = 0. The (1 − C) factor is needed; without it this constraint would force next = 0 on chain rows.
- **Chain:** is_transition·C·(next_j − swap_{u4}(s[0..4], u[0..4])_j) = 0.
- **Bit:** C·u4·(u4 − 1) = 0.
- **z:** is_first_row·(z − 1) = 0, and is_transition·(z′ − (1 − C)·z) = 0. The is_transition gate is needed because the last row wraps to row 0. Also C·z·u4 = 0.
- **Initial lanes:** is_first_row·(s_{4..7} − (0,0,0,TAG_NF)) = 0.
- **Nullifier:** C·z·(s_j − NF_j) = 0.
- **Root:** is_last_row·(s_j − ROOT_j) = 0.

That is about 32 constraints, maximum degree 4. Opened values: t = 2·(17+3) + 8·(3+3) + (3+3) = 94.

The production AIR must be checked against Plonky3's exact round order: `add_rc → sbox → M` for both round types, with the initial M_E applied before round 1.

## 4. M2 generality vector

- **T_hash:** 2^10 rows. M1's 17 columns plus an 8-column carried input. It receives (in[8], out[4]) on a global bus, with multiplicity C.
- **T_ctl:** 2^7 rows under Z128-g. It holds the level index, the sibling and the bit, and sends one tuple per used row. The padding rows have multiplicity 0.
- **Preprocessed:** a level tag and the null/leaf mode flags. The commitment is transparent and can be recomputed from the AIR.
- **Coverage:** two heights, injection, roll-in, preprocessed columns, the permutation tree, terminals that sum to 0, and the lookup PoW.
- **Size** is estimated at 100–120 KB (A modelled 118–128 KB with a wider AIR; B modelled 97 KB). It is recomputed in S0.

## 5. Layouts

**b, one 100 KB input (TXv5), M1 Z128 cap 0.**
- Witness, bottom first: per-query blobs (rows, salts, fri0 siblings, the T_q hint), then pruned Merkle records for 4 trees, then PT (roots, 94 OOD values, PoW witnesses, final polynomial), then the redeem.
- Op-cost model: ≈ 0.70M per query, Merkle ≈ 7.1M, fixed ≈ 6.3M; total ≈ 30–32M.

**b2, two 100 KB inputs.**
- Input 0 holds the redeem, PT and queries [0, Q_A), runs the transcript and the AIR check, and pins the graph: exactly 2 inputs with the expected locking.
- Input 1 holds queries [Q_A, Q). Its loader reads input 0's unlocking with OP_INPUTBYTECODE, checks the code hash, OP_DEFINEs the code, and re-derives the transcript and constants.
  - The loader must be ≤ 201 B if it is the P2S locking script; otherwise it is a P2SH32 redeem. A's loader is about 240 B, so it needs P2SH32.
- Splitting the multiproof costs about +3.2 KB. M1 is about 97 KB in total, which is at the 100,000 B transaction limit. M2 needs TXv5's raised transaction size.

**a′, today's rules, M1 Z128 cap 5.**
- Roles:

  | role | inputs | content | size |
  |---|--:|---|---|
  | HEAD | 1 | caps (4 × 32 digests), OOD values, PoW; runs the transcript and AIR check | ≈ 6.4 KB |
  | FIN | 1 | final polynomial and the packed α′ table, which it checks | ≈ 8.5 KB |
  | CODE | 2 | code | ≈ 7.5–9 KB each |
  | QRY | 8 | 3 queries each at 2,768 B per query (cap-truncated paths) | ≈ 8.6 KB each |

- QRY inputs read HEAD and FIN by introspection, a pattern A and B both proposed.
- The total is ≈ 101–103 KB plus transaction overhead, which is over the 100,000 B limit. The baseline is therefore 2 transactions linked by Track 5's NFT thread, with the commitment binding H(consts). That is ≈ 14 inputs and ≈ 115–120 KB.
- The 1-transaction stretch combines: Q = 23 with query PoW 28 (−2.8 KB), smaller code inputs, and a cap of 6 if the model favours it.

## 6. Soundness-argument plan (SOUNDNESS-T8.md + params8.py)

**Base.** Unchanged from Track 5:
- ADK Thm 2 per round, built on BCIKS Lemma 8.2 and Thm 7.2/7.4;
- Block et al. Cor. 5 for Fiat-Shamir;
- the powers-batching adaptation, still unpublished and labelled as such.

**New charges, each written as a lemma with its own term in params8.py:**
1. **Multi-table ALI:** Σ_i L·(|C_i| − 1)/|F|, a union bound over tables.
2. **DEEP:** one shared ζ; Σ_i L²·num_i/|F|. The check ζ^{n_max} ≠ 1 (and ≠ −1 under ZK) covers every H_i, because n_i divides n_max.
3. **Batching per height:** each height has its own α′ ladder. Charge Σ_h ε_batch(t_h), at most log2(#heights) extra bits. This is A's conservative bound; B's "unchanged" claim needs a proof before it can be used.
4. **Roll-in rounds:** folding plus β^a·ro_h is a curve of degree a, so BCIKS Thm 7.2 is charged with a instead of a − 1. Queries use the reduced index idx ≫ (top − h). The verifying key must enforce the strict height rule and heights on the arity grid.
5. **LogUp:** ε ≤ L·N·(W + 2)/|EF| (Haböck 2022/1530; p3-security `logup.rs`), with N = Σ interactions × rows.
   - The challenges are sampled after the main and preprocessed commitments, behind the lookup PoW.
   - Multiplicities cannot wrap: Σ w·h < p.
   - Buses are separated by injective offsets.
   - The terminal-sum check is exact.
6. **Preprocessed columns:** the root is verifying-key data, observed before any challenge. It adds to t and adds no round.
7. **Caps and mixed-height injection:** binding reduces to SHA-256 collision resistance. Dimensions come from the verifying key, never from the proof. The whole cap is observed in the transcript.
8. **AIR ⇒ relation lemma for M1**, row type by row type:
   - the selectors partition every slot;
   - the S-box constraints make each transition exactly one Poseidon2 round;
   - chaining and swap are correct, and the bit is boolean;
   - z is 1 exactly on slot 0;
   - the first and last rows fix NF's input and ROOT.

   M2 gets a matching lemma that uses the bus.
9. **Chain lemmas** (Track 7 Lemma 3 pattern):
   - b2: input 1 reads exactly input 0's PT bytes, and the graph is pinned.
   - a′: the constants HEAD and FIN publish are bound by their own checks plus the NFT-thread hash.
10. **Statement-level:**
    - collision resistance of truncated Poseidon2-8;
    - NF is a deterministic function of nk, which gives uniqueness;
    - the leaf hides through the 256-bit r;
    - the public values are canonical.

**Stated limits:**
- 128 bits is classical, using the birthday convention (strict reading 127.21).
- Generic quantum collision search (BHT) is about 85 bits, for both the in-circuit digest and SHA-256.
- ZK holds by construction (2024/1037); FRI-layer hiding remains open.

## 7. Build stages (each stage can be run as a workflow step)

**S0 – Specification and calculators**
- Inputs: this document, params5.py, syn.py.
- Outputs:
  - AIR-SPEC.md, the single source for the Rust AIR and the JS AIR;
  - params8.py;
  - bytes8.py (per-matrix salts, caps, heights, fold_schedule);
  - λ and size tables for Z128 cap 0, Z128 cap 5 and Z128-g/M2.
- Acceptance:
  - bytes8.py reproduces Track 5 S128 (78,393 B) and S128z (112,501 B) to within 1%;
  - Z128 gives λ ≥ 128 with batch PoW 20;
  - M2's shape passes the strict-height and hiding-budget checks.

**S1 – Batch prover crate** (`research/pq-stark-batch/prover`, at the pin)
- Inputs: Track 5 `cfg.rs` with `cap_height` as a parameter, and `p3-batch-stark`.
- Outputs:
  - the p3b-v1 wire format and FORMAT.md;
  - shape and constraint-DAG JSON export;
  - logs of transcript hash inputs.
- Acceptance: `verify_batch` passes for Plonky3's single_instance, three_instances_mixed_sizes, mixed_preprocessed, both_lookups_zk and periodic_air_zk, each reconfigured to SHA-256 / Goldilocks / cubic trinomial.

**S2 – Statement AIRs** (M1, then M2)
- Outputs: the AIRs, a witness generator and vectors (depth 30; leaf indices 0, 2^30 − 1 and random).
- Acceptance:
  - Poseidon2 differential test against p3-goldilocks;
  - check_constraints passes;
  - a mutation test: every single-cell mutation fails some constraint;
  - forced unsatisfying traces are rejected by `verify_batch`;
  - sizes within ±3% of S0;
  - prover time and RAM recorded.

**S3 – JS reference verify-batch.mjs**
- Covers N tables, injection, per-height ladders, roll-ins, LogUp, caps and ZK.
- Acceptance: transcript bytes identical to Rust's, and verdicts identical on every valid case and on the tampered set (Track 5 families extended to the new fields).

**S4 – Generator and layout b for M1**
- Acceptance:
  - libauth BCH 2026, TXv5, standard and consensus, plus bch-spec;
  - unlocking ≤ 100 KB;
  - op-cost within ±15% of the model;
  - the full tamper and witness-manipulation sweep: 0 unexpected results.

**S5 – Multi-height and LogUp on chain**
- Adds INJ records, the per-height x, ladders and roll-ins, LogUp at ζ, and the terminal sum.
- Acceptance: M2 and the S1 Plonky3 vectors pass the S3 agreement suite, and their scripts verify (in b2).

**S6 – Layout b2** (M1 and M2)
- Acceptance:
  - both inputs accepted;
  - rejected: mismatched proofs across the inputs, a third input, a different locking, a tampered loader blob.

**S7 – Layout a′** (M1, cap 5)
- Acceptance:
  - every input standard;
  - every transaction ≤ 100,000 B;
  - libauth's whole-transaction verification passes;
  - the 2-transaction baseline is accepted, and the 1-transaction stretch result is recorded either way;
  - rejected: tampered HEAD/FIN constants, replays.

**S8 – Soundness and reviews**
- SOUNDNESS-T8.md, then three reviews (protocol/soundness; AIR/statement; measurement), fixes and re-review.
- Then the Track 8 section of REPORT, with its caveats.

**S9 (optional) – Poseidon2-Gl-8 permutation in CashVM**
- An op-cost microbenchmark for the Track 9 pool covenant (deposit root update).

## 8. Test matrix

- **Valid:** M1 (more than 20 statements, cap 0 and cap 5), M2, and the Plonky3 batch AIRs. Each with several seeds, plus a CSPRNG check that two proofs of one witness differ.
- **Tampered:** every header byte, root or cap digest, OOD value, terminal, PoW witness, final coefficient, row and salt (including injected short-table rows) and sibling; truncation, extension, non-canonical encodings.
- **Statement:**
  - stale or foreign ROOT;
  - NF ± 1, NF + p;
  - changed outputs (so CTX differs);
  - permuted public values;
  - a proof made for another verifying key (depth 29 or other parameters).
- **Layout:**
  - a wrong T_q hint;
  - moved or duplicated INJ records;
  - cross-input or cross-transaction mixing;
  - a wrong FIN table.

## 9. Corrections applied to the input designs

| design | claim | correction |
|---|---|---|
| B | proof 70.8 KB | 73.4 KB (per-matrix quotient salts) |
| B | 1-transaction today | 2-transaction baseline |
| B | round and z constraints | (1 − C) gate and is_transition gate added |
| B | batch PoW 12 | 20 |
| A | n_i ≥ 2^6 and "≥ log_final + lb" | strict ">"; T_ctl ≥ 2^7, on the arity grid |
| A | 57-column degree-2 AIR | replaced by the 17-column degree-4 AIR |
| A | two-input M1 at 102 KB under today's transaction limit | needs TXv5 transaction size |
| A | 240 B loader in a P2S locking script | P2SH32 |

## Maintainer decisions (2026-10-30)

1. **Fixed-denomination notes.** M1 has no value field. Notes that carry a value are for a later track.
2. **Post-quantum meaning.** 4-element Poseidon2-Goldilocks digests plus SHA-256 commitments: 128-bit classical, about 85-bit generic quantum collision resistance (BHT). That is the same level as SHA-256 itself, so it is accepted. The report must state it plainly, and no 6-element digests are needed.
3. **Two-input 100 KB layout.** Report it as relay/standardness limits raised: per-input unlocking and, where needed, transaction size. Say for each layout which standardness limit it needs. Don't use the label "TXv5".
4. **Prover budget.** Z128 (log_blowup 9, 2^20 LDE) is accepted. Run the prover under nice with RAYON_NUM_THREADS=4, one heavy job at a time.
5. **Merkle cap per deployment.** Each layout's verifying key picks its own cap (0 for the 100 KB layouts, 5 for today's rules).
6. **Today's rules.** The 2-transaction baseline is an acceptable result, and 1 transaction is a stretch goal. Do not trade below 128 bits to reach it.
7. **Pool covenant** (nullifier set, root updates) is Track 9. The Poseidon2-in-CashVM microbenchmark (S9) is optional; run it only if it is cheap.
