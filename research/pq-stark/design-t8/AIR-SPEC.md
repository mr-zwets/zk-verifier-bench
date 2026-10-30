# Track 8 AIR specification (M1 and M2)

Status: S0 specification. Nothing here has been proved with Plonky3 yet. This file is the single source for:
- the Rust AIRs (S2, `research/pq-stark-batch/`);
- the JS AIR evaluator (S3, `verify-batch.mjs`);
- the generator's constraint code (S4/S5).

If Rust, JS and this file disagree, this file is fixed first and the change is recorded in PROGRESS.md.

**Executable companion: [air8_ref.py](air8_ref.py).** It implements every constraint below, in the order given here, in plain Python, and checks:
- Poseidon2-Gl-8 against Plonky3's test vector;
- that honest traces satisfy all constraints (M1 at leaf indices 0, 2^30 − 1 and a random index; M2 likewise);
- that NF and ROOT in the trace equal a native computation of the relation;
- single-cell mutation completeness: every main-trace cell, changed alone, breaks some constraint;
- each constraint's Plonky3 degree, against the shapes in [bytes8.py](bytes8.py).

Current result: **ALL PASS**, in `air8_ref-output.json`. M1 catches 17,408 of 17,408 mutated cells; M2 catches 24,576 of 24,576 (T_hash) and 1,664 of 1,664 (T_ctl).

Pin: Plonky3 0d803737b681774186cd283b1fd2d8e493655c82. Source paths below are relative to its checkout.

## 1. Conventions

- **Field and extension.**
  - The field is Goldilocks, p = 2^64 − 2^32 + 1. Every value is a canonical u64 below p.
  - The challenge field is `CubicTrinomialExtensionField<Goldilocks>`, with u^3 = u + 1 and D = 3.
- **Rows.**
  - Rows are numbered 0..n−1. "next" (written x′) is row r+1, and the last row wraps to row 0.
  - Plonky3 opens the whole main row at ζ·g whenever an AIR declares any next-row column (`validate_trace_next`).
- **Selectors.** Use Plonky3's two-adic, unnormalised selectors at ζ, with Z_H(ζ) = ζ^n − 1:
  - is_first_row = Z_H(ζ)/(ζ − 1);
  - is_last_row = Z_H(ζ)/(ζ − g^−1);
  - is_transition = ζ − g^−1;
  - the vanishing inverse is 1/Z_H(ζ).

  These are the same as in Track 5's `verify.mjs`. On the trace itself:
  - is_first_row is nonzero only on row 0;
  - is_last_row is nonzero only on row n−1;
  - is_transition is zero only on row n−1.
- **Constraint folding.**
  - The verifier folder is Horner: `acc = acc·α + C_k`, in **emission order** (`uni-stark/src/folder.rs`, VerifierConstraintFolder).
  - The order of the lists below is therefore normative.
  - With lookups, the LogUp gadget's constraints come after the AIR's own constraints (`LogUpGadget::eval_air_and_lookups`, batch-stark `verifier/data.rs`).
- **Degree rule.** This is what Plonky3 uses for the quotient chunk count (`air/src/symbolic/variable.rs` and `constraints.rs`, `builder.rs` `constraint_degree_from_poly_degree`).
  - The polynomial degree of a constraint is the maximum over its terms of the sum of the factor degrees:

    | factor | degree |
    |---|---|
    | main or preprocessed column | n − 1 |
    | periodic column of period P | n − n/P |
    | is_first_row, is_last_row | n − 1 |
    | is_transition | 1 |

  - The constraint degree is ⌈(poly − 1)/(n − 1)⌉.
  - Under ZK the number of quotient chunks is 2 · 2^⌈log2(max(d+1, 2) − 1)⌉.
- **Public values.** These are observed in the transcript in `main_phase`, in the order given. The script checks every public value < p (DESIGN §1).

## 2. Poseidon2-Gl-8 (P) and the 2-to-1 compression

- **Source:** `goldilocks/src/poseidon2.rs` (`default_goldilocks_poseidon2_8`), with `poseidon2/src/external.rs` and `internal.rs`.
- **Constants:** extracted verbatim into [poseidon2-gl8-constants.json](poseidon2-gl8-constants.json):

  | constant | contents |
  |---|---|
  | `external_initial` | 4 × 8 |
  | `external_final` | 4 × 8 |
  | `internal` | 22 |
  | `matrix_diag_8` | 8: −2, 1, 2, 1/2, 3, −1/2, −3, −4 |

- **S-box:** x ↦ x^7.
- **External matrix M_E** (`mds_light_permutation`, width 8). M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] (`MDSMat4`, `apply_mat4`). M_E = [[2·M4, M4], [M4, 2·M4]], so ME[i][j] = M4[i mod 4][j mod 4] · (2 if ⌊i/4⌋ = ⌊j/4⌋ else 1).
- **Internal matrix M_I** = diag(DG) + J, where J is the all-ones matrix: y_i = DG_i·x_i + Σ_k x_k (`internal_layer_mat_mul_goldilocks_8`). So MI[i][j] = DG_i·[i = j] + 1.
- **Round order.** Plonky3 uses `add_rc → sbox → M` for both round types:
  1. x ← M_E·x (the initial linear layer, applied before round 1);
  2. 4 full rounds: x ← M_E·(x + rc_init[r])^7, element-wise;
  3. 22 partial rounds: x_0 ← (x_0 + rc_int[r])^7, then x ← M_I·x;
  4. 4 full rounds with rc_final.
- **Test vector:** P(0, 1, …, 7) = (0x020cf04a1b214d14, 0x84e14aaaeacaed25, 0x1ae0f640e81c7457, 0xa4d204cbaeb0d8a5, 0x0cf637b627b3a7ff, 0x788d304d948b486b, 0x7327133ea1949af4, 0xf415abb924da395b). This is `test_default_goldilocks_poseidon2_width_8`; air8_ref.py reproduces it.
- **Truncation and compression:** T(x) = (x_0, x_1, x_2, x_3). The 2-to-1 compression is H(a, b) = T(P(a ‖ b)), with a and b of 4 elements each.
- **TAG_NF** = 0x76632E6E66763031 (ASCII "vc.nfv01"; < p). IV_NF = (0, 0, 0, TAG_NF).

## 3. M1: fixed-denomination spend (one table)

### 3.1 Statement

- **Public values** (12, in this order): ROOT[0..4], NF[0..4], CTX[0..4].
- **Witness:**
  - nk[4] and r[4] (canonical);
  - bits b_1..b_30, where the leaf index is ℓ = Σ b_i·2^{i−1}, so b_1 is the LSB at the leaf level;
  - siblings S_1..S_30, of 4 elements each.
- **Relation:**
  - NF = T(P(nk ‖ IV_NF)), with nk the 4-element nullifier key;
  - leaf = H(NF, r);
  - node_0 = leaf;
  - node_i = H(swap_{b_i}(node_{i−1}, S_i)), where swap_0(x, S) = (x, S) and swap_1(x, S) = (S, x);
  - ROOT = node_30.
- **CTX.** CTX_k = the little-endian integer of bytes [7k, 7k+7) of SHA-256(serialized outputs), so each CTX_k < 2^56.
  - The AIR does not constrain CTX. It is bound by the transcript: public values are observed before α, so a proof for one CTX does not verify for another (§6, item 1).
  - The exact output serialization is fixed by the generator (S4) and recorded in FORMAT.md. The proposal is BCH's output serialization in order: value u64-LE ‖ token prefix ‖ compact-size length ‖ locking bytecode.
  - The script recomputes CTX by introspection and checks each CTX_k < 2^56.

### 3.2 Trace layout

n = 2^10 = 32 slots × 32 rows.
- Slot 0 computes NF.
- Slot 1 computes the leaf.
- Slots 2..31 compute node_1..node_30.

**Main columns (width 17):**

| col | name | meaning |
|---|---|---|
| 0..7 | s0..s7 | permutation state at the start of the row's round |
| 8..15 | u0..u7 | S-box cube registers (F rows: u_i = (s_i + rc_i)^3; Pt rows: u_0 only). On the C row: u0..u3 = sibling (or r in slot 0), u4 = bit. |
| 16 | z | 1 on slot 0 (rows 0..31), 0 elsewhere |

**Row type within a slot** (r = row mod 32):

| r | type | transition r → r+1 |
|---|---|---|
| 0 | L (load) | s′ = M_E·s |
| 1..4 | F (full, rc_init[r−1]) | s′ = M_E·(s + rc)^7 |
| 5..26 | Pt (partial, rc_int[r−5] on lane 0) | s′ = M_I·((s_0 + rc_0)^7, s_1, …, s_7) |
| 27..30 | F (full, rc_final[r−27]) | s′ = M_E·(s + rc)^7 |
| 31 | C (chain) | next slot row 0: s′ = swap_{u4}(s_0..s_3, u_0..u_3) |

So row 31 of slot k holds P(input_k).

**C-row contents (u0..u4):**
- slot 0: (r, 0);
- slot k for 1 ≤ k ≤ 30: (S_k, b_k);
- slot 31, which is the last row: (0, 0, 0, 0, 0).

**Unused cells are 0:**
- u0 on L rows;
- u1..u4 on Pt and L rows;
- u5..u7 on Pt, L and C rows;
- u0..u4 on the last row.

This is what makes the mutation test complete.

### 3.3 Periodic columns (11, period 32)

Index order:

| index | column | value at slot row r |
|---|---|---|
| 0..7 | rc0..rc7 | r = 1..4: rc_init[r−1]; r = 27..30: rc_final[r−27]; r = 5..26: (rc_int[r−5], 0, …, 0); 0 otherwise |
| 8 | F | 1 on r ∈ 1..4 ∪ 27..30 |
| 9 | Pt | 1 on r ∈ 5..26 |
| 10 | C | 1 on r = 31 |

Derived: L = 1 − F − Pt − C, which is 1 exactly on r = 0.

The verifier evaluates each periodic column at ζ as g_c(ζ^{n/32}), where g_c interpolates the 32 values over the order-32 subgroup (`evaluate_periodic_columns_at`). The generator bakes in either the 11 × 32 values or their coefficients.

### 3.4 Constraints (emission order; 53 in total)

Notation: σ_0 = F + Pt, σ_{i≥1} = F. Every value is local unless primed.

| # | id | constraint | count | Plonky3 degree |
|---|---|---|--:|--:|
| 1–8 | A_i | σ_i · (u_i − (s_i + rc_i)^3), i = 0..7 | 8 | 4 |
| 9–16 | B_i | τ_i · u_i, with τ_0 = L, τ_{1..4} = Pt + L, τ_{5..7} = Pt + L + C | 8 | 2 |
| 17–24 | C_j | (1 − C)·s′_j − [F·Σ_i ME_{j,i}·u_i²·(s_i + rc_i) + Pt·(MI_{j,0}·u_0²·(s_0 + rc_0) + Σ_{i≥1} MI_{j,i}·s_i) + L·Σ_i ME_{j,i}·s_i], j = 0..7 | 8 | 4 |
| 25–32 | D_j | is_transition · C · (s′_j − w_j), where w_j = s_j + u4·(u_j − s_j) for j < 4 and w_j = u_{j−4} + u4·(s_{j−4} − u_{j−4}) for j ≥ 4 | 8 | 3 |
| 33 | E | C · u4 · (u4 − 1) | 1 | 3 |
| 34 | F0 | is_first_row · (z − 1) | 1 | 2 |
| 35 | F1 | is_transition · (z′ − (1 − C)·z) | 1 | 2 |
| 36 | F2 | C · z · u4 | 1 | 3 |
| 37–40 | G_k | is_first_row · (s_{4+k} − IV_NF[k]), k = 0..3 | 4 | 2 |
| 41–44 | H_j | C · z · (s_j − NF_j), j = 0..3 | 4 | 3 |
| 45–48 | I_j | is_last_row · (s_j − ROOT_j), j = 0..3 | 4 | 2 |
| 49–53 | J_i | is_last_row · u_i, i = 0..4 | 5 | 2 |

Notes on the constraints:
- **C_j.** The (1 − C) factor is required: without it, chain rows would force s′ = 0. On C rows F = Pt = L = 0, so C_j vanishes there.
  - u_i²·(s_i + rc_i) = (s_i + rc_i)^7 once A_i holds.
  - On Pt rows rc_{1..7} = 0.
- **D_j, F1.** The is_transition gate excludes the wrap from row n−1 to row 0. Row n−1 is slot 31's C row.
- **H_j** fires only on row 31, where C = z = 1. **F2** forces b = 0 there, so the leaf input is (NF, r).

**Degree summary.** The maximum is 4 (A, C: 992 + 3·1023 = 4061 → 4), which gives **8 ZK quotient chunks** (log 2, ×2). Per group: A 4, B 2, C 4, D 3, E 3, F 3, G 2, H 3, I 2, J 2. air8_ref.py computes these numbers.

**Plonky3 declarations:**

| item | value |
|---|---|
| `BaseAir::width` | 17 |
| public values | 12 |
| periodic columns | 11 with period 32 |
| preprocessed | none |
| next-row columns | s0..s7 and z (columns 0..7, 16); Plonky3 still opens the full row |
| `max_constraint_degree` hint | none (the symbolic degree is 4) |
| `public_boundary_io` | empty, as batch-stark requires; public values enter only through G/H/I and the transcript |

### 3.5 Shape (Z128)

| item | value |
|---|---|
| trace domain | 2^10 |
| ZK extended domain | 2^11 |
| LDE height | 2^20 |
| opened values t | 2·(17+3) + 8·(3+3) + (3+3) = **94** |
| main leaf | 17 + 3 random + 2 salt = 22 elements (176 B) |
| quotient | 8 matrices × (6 + 2) = 512 B |
| random | 64 B |
| FRI round-0 leaf | 7 ext + salt = 184 B |
| per-query leaf total | **936 B** |
| proof (bytes8.py) | **73,434 B** (cap 0) and **75,967 B** (cap 5), expected values |

### 3.6 AIR ⇒ relation (sketch for S8, SOUNDNESS-T8 lemma 8)

1. **Selectors partition every slot.** The periodic F, Pt, C and L are 0/1 with exactly one equal to 1 on every row.
2. **One row type = one Poseidon2 round.** On F rows A forces u_i = (s_i + rc_i)^3 for all i, so C gives s′ = M_E·(s + rc)^7. On Pt rows A forces u_0, so C gives the partial round. On the L row C gives s′ = M_E·s.
   - So for each slot, row 31 = P(row 0's state), following Plonky3's round order (§2).
3. **Chaining.** D links the C row of slot k to row 0 of slot k+1 through swap_{u4}, and E makes u4 boolean.
4. **z = 1 exactly on slot 0** (F0, F1). So H pins row 31 = NF, and F2 pins b = 0 there. G pins slot 0's lanes 4..7 to IV_NF.
5. **Root.** I pins row 1023 (slot 31's output) = ROOT.
6. **Result.** NF = T(P(nk ‖ IV_NF)) with nk = row 0's lanes 0..3; leaf = T(P(NF ‖ r)); the 30 path steps follow; ROOT = node_30.

The fixed depth (trace height, slot count) removes leaf/internal-node confusion. B and J constrain no relation value; they only remove free cells.

## 4. M2: generality vector (two tables, preprocessed columns, one global LogUp bus)

The relation is the same as M1's. The batch order is **instance 0 = T_hash, instance 1 = T_ctl**; this order is normative for the transcript, for `degree_bits` and for the ladders. Parameters: **Z128-g** (final polynomial 2^5); see §5 for the required commit-PoW correction.

### 4.1 T_hash (n = 2^10): 32 independent permutations

- **Main (24):** s0..s7 (cols 0..7), u0..u7 (cols 8..15), in0..in7 (cols 16..23). Here `in` is the slot's input, carried down the slot.
- **Periodic:** the same 11 columns as M1 (§3.3).
- **Preprocessed (1):** lvl_h = k on every row of slot k.
- **Public values:** none.

M1's z, chain and bit logic moves to T_ctl, so the width is 24, not the design's "17 + 8 = 25". M1's column z has no role here.

Constraints (AIR, emission order; 40):

| # | id | constraint | count | degree |
|---|---|---|--:|--:|
| 1–8 | A_i | as M1 | 8 | 4 |
| 9–16 | B′_i | τ′_i · u_i, with τ′_0 = L + C, τ′_{1..7} = Pt + L + C (u is never used on C rows here) | 8 | 2 |
| 17–24 | C_j | as M1 | 8 | 4 |
| 25–32 | K_j | L · (s_j − in_j) (load) | 8 | 2 |
| 33–40 | M_j | (1 − C) · (in′_j − in_j) (carry within the slot) | 8 | 2 |

**Lookup (one, global bus `P2`)**, emitted after the AIR constraints by the gadget:
- **receive** tuple (lvl_h, in0..in7, s0..s3) with multiplicity −C, evaluated on the C row;
- the payload width is **W = 13**;
- `count_weight` = 1 (C ∈ {0, 1} is periodic).

The LogUp gadget adds 1 fraction constraint (degree 2) and 3 accumulator constraints (first, transition and last row; degree ≤ 2). That makes **44 constraints, maximum degree 4, and 8 ZK chunks**. The permutation trace has (1+1)·3 = 6 base columns, plus 3 random columns.

### 4.2 T_ctl (n = 2^7 = 128): the control table

- **Main (13):** in0..in7 (cols 0..7), out0..out3 (cols 8..11), b (col 12).
- **Preprocessed (5):**

  | column | value |
  |---|---|
  | lvl | k on rows 0..31, else 0 |
  | f_null | 1 on row 0 |
  | f_leaf | 1 on row 1 |
  | f_root | 1 on row 31 |
  | f_used | 1 on rows 0..31 |

- **Public values (12):** ROOT, NF, CTX, as in M1.

**Rows:**
- row 0: in = (nk ‖ IV_NF), b = 0;
- row 1: in = (NF ‖ r), b = 0;
- row k for 2 ≤ k ≤ 31: in = swap_{b_{k−1}}(out_{k−1}, S_{k−1}) and b = b_{k−1};
- out_k = T(P(in_k)) on every used row;
- row 32: in = (ROOT, 0, 0, 0, 0), out = 0, b = 0;
- rows 33..127: all 0.

Constraints (AIR, emission order; 31; every one has degree 2):

| # | id | constraint | count |
|---|---|---|--:|
| 1–4 | N1_k | f_null · (in_{4+k} − IV_NF[k]) | 4 |
| 5–8 | N2_j | f_null · (out_j − NF_j) | 4 |
| 9–12 | N3_j | f_root · (out_j − ROOT_j) | 4 |
| 13 | N4 | (f_null + f_leaf) · b | 1 |
| 14 | N5 | b · (b − 1) | 1 |
| 15–18 | N6_j | is_transition · (1 − b′) · (in′_j − out_j) | 4 |
| 19–22 | N7_j | is_transition · b′ · (in′_{4+j} − out_j) | 4 |
| 23–26 | N8_j | (1 − f_used) · out_j | 4 |
| 27 | N8_4 | (1 − f_used) · b | 1 |
| 28–31 | N8_{5+j} | (1 − f_used) · in_{4+j} | 4 |

**Lookup (one, bus `P2`):**
- **send** tuple (lvl, in0..in7, out0..out3) with multiplicity +f_used;
- W = 13; `count_weight` = 1.

Adding the LogUp constraints gives **35 constraints, maximum degree 2, and 4 ZK chunks**.

The multiplicity bound Σ w·h = 1·2^10 + 1·2^7 is far below p (`check_multiplicity_height_bound`). The terminals of the two AIRs must sum to 0.

### 4.3 Coverage and shape (Z128-g)

| item | value |
|---|---|
| heights (LDE) | T_hash 2^20, T_ctl 2^17 |
| fold schedule | 20 → 17 (roll-in of T_ctl) → 14 |
| final polynomial length | 32 |

Every commitment has matrices at both heights: random, main, quotient (8 + 4 chunks), preprocessed (1 + 5 columns, in the verifying key) and permutation (9 + 9 columns). So injection is exercised in every input tree.

| ladder | value |
|---|---|
| t_20 (T_hash) | 54 + 48 + 6 + 1 + 18 = 127 |
| t_17 (T_ctl) | 32 + 24 + 6 + 5 + 18 = 85 |
| total t | 212 |
| lookup terminals | 2 |
| proof (bytes8.py, expected) | 122,993 B |

Checks (bytes8.py `checks`, all pass):
- **strict heights:** 20, 17 > 14;
- **arity grid:** [3, 3];
- **hiding budget:** the minimum mask 128 is ≥ 2·(3·2 + 24) = 60.

Under plain Z128 (final 2^8), T_ctl's 17 is not > 17, so that set is rejected. This is the negative check.

**Preprocessed commitment.** The preprocessed root sits in the verifying key, but `HidingFriPcs::commit_preprocessing` commits through the hiding MMCS. Its salts are random (`hiding_mmcs.rs` `commit`), so the root is **not** recomputable from the AIR alone.
- S1 must export the salts, or the RNG seed, with the verifying key, so that anyone can recompute the root.
- Otherwise the root is a trusted-setup value. DESIGN §4 calls it "transparent"; that holds only with the salts published.

## 5. Parameters this specification is checked against (params8.py and bytes8.py)

| set | used by | λ_IOP (JB, powers-batching adaptation, unpublished) | binding round |
|---|---|---|---|
| Z128 (lb 9, arity 8, final 2^8, Q 24; PoW q 24 / c 2 / batch 20; rc 3; salt 2) | M1, cap 0 and 5 | **128.06** (m = 5) | fold1 |
| Z128, batch PoW 12 (design B) | – | 128.06; batch round 128.33 | – |
| Z128-s (Q 23, query PoW 28) | M1 a′ stretch | 128.06 | fold1 (query 128.34) |
| Z128-g as designed (final 2^5, commit PoW 2, lookup PoW 8) | M2 | **127.92: SHORT by 0.08** | query (m = 4); fold1 with roll-in is 127.87 at m = 5 |
| **Z128-g with commit PoW 3** | M2 | **128.70** (m = 5) | query |

**The roll-in charge (DESIGN §6.4) costs M2 0.19 bits on fold1.** Z128-g therefore needs commit PoW 3 instead of 2. That costs no proof bytes and 8 commit grinds per round. S1/S2 should build M2 with `commit_proof_of_work_bits = 3`.

## 6. Open items handed to later stages

1. **CTX binding** is through the transcript only (Plonky3 observes public values before α). SOUNDNESS-T8 (S8) must state this as a lemma: Fiat-Shamir binding of public inputs, with the ZK caveat. S3's tamper set covers changed outputs (CTX differs).
2. **Preprocessed salts** (§4.3): S1 exports them, and the M2 verifying key records how the root was made.
3. **Constraint order** (§1): Rust `eval` must emit exactly the order of §3.4 and §4. S3 checks this by comparing the folded constraint value at ζ against Rust on every vector.
4. **p3b-v1 format (S1 FORMAT.md).** It omits zero-bit PoW witnesses, and the decoder inserts 0. degree_bits are verifying-key data, so the proof has no header byte. bytes8 follows this.
   - Against S1's 28 real p3b-v1 proofs, every deterministic section matches exactly, and so do the fold schedules (`s1-crosscheck.json`).
   - **Periodic columns are not bound by batch-stark's transcript** (S1 finding), so the 11 × 32 periodic values of §3.3 are verifying-key constants and must be compiled into the script.
   - **Lookup PoW:** S1 currently uses 0 bits. The LogUp round is 166.5 bits even without PoW. params8 uses 8 bits for M2 to cover the lookup-PoW site (DESIGN §4). Either value keeps λ.
5. **Sizes are expected values.** A single proof's sibling count varies. Over Track 5's 45 vectors the deviation had a standard deviation of 1.2% and a maximum of 3.6%. M1's p99 is about +2.0%. S2's "within ±3% of S0" should be read against these expected values, with that spread.
6. **Changes against DESIGN-T8 §3–4,** which are details within the design:
   - M1 has 53 constraints, not "about 32": B and J were added for mutation completeness, and the remaining constraints are written out explicitly.
   - T_hash has 24 columns (no z).
   - The level tag appears in both tables, so preprocessed columns exist at both heights.
   - Z128-g needs commit PoW 3.
