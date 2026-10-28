# pq-hash: a SHA-256 STARK verifier on CashVM (design spec)

Track: pq-hash (post-quantum, hash-based proof verification on BCH). Phase: Design. Date: 2026-10-28.
Branch: `wip/pq-hash-design` (zk-verifier-bench), worktree `work/pq-hash/design`. **Research only: not a leaderboard entry.** Nothing here touches REGISTRY, results.json or score-history.json.

Calculator: [research/pq-hash/params.py](research/pq-hash/params.py). It is the single source for every number below. Its outputs are [params-output.txt](research/pq-hash/params-output.txt) and [params-output.json](research/pq-hash/params-output.json).
- Bytes are exact for the proof format in section 3. Multiproof sizes are expectations over uniform query indices.
- Op-cost figures are a rough kernel model, used only for feasibility. The Kernels phase replaces them with measurements (section 8).

## 0. Summary

| | choice |
|---|---|
| protocol | DEEP-ALI STARK with batched DEEP-FRI (ethSTARK structure). FRI was chosen over STIR/WHIR; reasons in §1.3. |
| field | Goldilocks p = 2^64 − 2^32 + 1; challenges and FRI layers ≥ 1 in F_{p^3} = F_p[u]/(u^3 − 7) |
| hash | SHA-256 (native OP_SHA256) for Merkle trees, Fiat-Shamir and grinding; Merkle nodes truncated to h bytes (h = 25 at 100 bits, 32 at 128) |
| statement | MiMC-7 chain over F_p with an 8-constant periodic schedule; trace 2 columns × n = 2^16 rows; y = F^(n−1)(x); 4 constraints, degree 3 |
| soundness | provable, Johnson regime: BCIKS20 Thm 8.3 batched FRI with list-size DEEP-ALI; round-by-round Fiat-Shamir with grinding; ZK out of scope |
| P100 | ρ = 2^−7, folds [4, 8, 8], final degree < 2^8, m = 3, **s = 22 queries**, g = 28, h = 25: λ = 100; **≈ 50.0 KB proof** |
| P128 | ρ = 2^−5, folds [4, 8, 8], final degree < 2^8, m = 4, **s = 43 queries**, g = 28, h = 32: λ = 128; **≈ 91.5 KB proof** |
| layout (a), today's standard rules | P100: **1 transaction, 6 inputs, ≈ 57 KB**. P128: **2 transactions, 14 inputs, ≈ 120 KB**, with an NFT thread between them |
| layout (b), one input (TXv5 / bch-spec) | P100: ≈ 54 KB unlocking. P128: ≈ 95.6 KB unlocking, which fits the 100,000 B standard transaction with ≈ 4 KB to spare |

Headline expectation, to be confirmed by Build:
- A **128-bit provably sound** post-quantum STARK verifier fits **one TXv5 input**.
- A **100-bit** one fits **one standard BCH transaction today** (6 inputs).
- Op-cost is not the binding limit overall: the model puts the verifier at about 40–60% of the byte-tied budget. Bytes bind, as `beyond-groth16.tsx` predicts. Per input the picture is more nuanced (§6.4).

## 1. Scope and protocol choice

### 1.1 What this track measures
The goal is to turn the site's "BCH VM fit" estimates on `/beyond-groth16` into numbers:
- proof bytes, inputs and transactions;
- op-cost (libauth standard and consensus, plus BCHN-adjusted);
- hash iterations, for a hash-based verifier with a native hash;
- kernel costs that settle the emulated-hash and binary-field claims (§8).

It is constructive throughout:
- Accept tests on honest proofs and rejection tests on tampered proofs.
- No attack construction.

### 1.2 Out of scope
- **Zero-knowledge.** The prover adds no masking or randomizer polynomials, so opened trace values leak. The statement here is fully public, so nothing secret leaks. A ZK variant would add one random masking column and a randomized composition: one more trace column per opened row, plus 1–2 OOD values. That is about +4·k0·8 B per query; we note it and do not build it.
- Prover performance. The prover is a Python/JS reference, single-threaded, and need not be fast. Grinding 2^28 SHA-256 calls is a few seconds of CPU.

### 1.3 Why FRI and not STIR or WHIR (for the first build)
- **Verifier shape.** FRI's query phase is one uniform loop: open, hash up, fold, repeat. It shards cleanly over inputs with fixed byte offsets. STIR adds per-round out-of-domain samples, degree correction and quotient evaluations. WHIR is multilinear: a sumcheck per round, many more F_{p^3} operations and transcript rounds.
- **Bytes.** In the provable (Johnson) regime, FRI with grinding already reaches 50/91 KB at n = 2^16. STIR's advantage grows with degree and security (O(log d + λ·log log d) queries against FRI's O(λ·log d)). At d = 2^16 it is a modest saving that we do not need to fit the targets.
- **Assumptions.** STIR's and WHIR's provable analyses rest on the same BCIKS20 correlated-agreement theorems, so they add no new trust.
- **Follow-up.** Once FRI kernels are measured, STIR's byte model can be added to params.py and its extra kernels costed. It is listed as a stretch item (§9).

### 1.4 Field choice (by CashVM cost)
On BCH 2026, OP_MUL costs 100 + 2·len(out) + len(a)·len(b), and OP_MOD the same with its own operands. At Goldilocks size (8–9-byte operands) the 100 base cost per instruction dominates. Field cost is therefore mostly an instruction count, and the bytes in the proof decide the field.

| candidate | q for challenges | trace value bytes | F_q mul instructions (schoolbook) | Johnson 128-bit feasible? |
|---|---|---|---|---|
| BabyBear/M31 + deg-4 ext | ≈ 2^124 | 4 | 16 MUL + reductions | no (q too small, see §4); would need deg ≥ 6 |
| Goldilocks + deg-2 | ≈ 2^128 | 8 | 4 MUL + 2 MOD | no: BCIKS20 Johnson error ≈ 2^64/q; only unique decoding (2× queries) or commit-phase grinding (U128g, §5) |
| **Goldilocks + deg-3** | ≈ 2^192 | 8 | 9 MUL + 3 MOD | **yes**, with 128.3 bits of commit-phase margin at P128 |
| one 192-bit prime (no extension) | 2^192 | 24 | 1 MUL + 1 MOD on 24-byte operands | yes, but trace leaves are 3× larger (+128 B per query at k0 = 4). Cheaper op-cost; kernel K19 measures it in case op-cost ever binds |

Goldilocks facts (checked in params.py's preamble):
- 2-adicity is 32;
- 7 generates F_p^*;
- 7 is a quadratic non-residue and a non-cube, so u^2 − 7 and u^3 − 7 are irreducible;
- gcd(7, p − 1) = 1, so x ↦ x^7 is a permutation.

## 2. Statement: the AIR

**MiMC-7 chain with periodic round constants.**
- Trace: n = 2^16 rows, 2 columns (X, Y) over F_p.
- Round constant: c(i) = C[i mod 8], with C[j] = SHA256("verifier.cash/pq-hash/rc" ‖ u8(j)) mod p (nothing up our sleeve).
- Trace domain: H = ⟨ω⟩ with ω of order n (ω = 7^((p−1)/n)). The row i point is ω^i.

Constraints, with s_i := X_i + c(i):

| id | kind | rows | polynomial | degree |
|---|---|---|---|---|
| C1 | transition | 0 … n−2 | Y_i − s_i^3 | 3 |
| C2 | transition | 0 … n−2 | X_{i+1} − Y_i^2 · s_i | 3 |
| B1 | boundary | 0 | X_0 − x_in | 1 |
| B2 | boundary | n−1 | X_{n−1} − y_out | 1 |

- The public statement is (x_in, y_out) ∈ F_p^2, with y_out = F^{n−1}(x_in) where F(x) = (x + c)^7.
- Recomputing it directly costs about 3·(n−1) ≈ 196,600 mulmods, roughly 120M op-cost by the §6 model. That is more than the STARK verifier spends (24–45M), so the proof is succinct on chain too.
- Y_{n−1} is unconstrained. The honest prover fills it with s_{n−1}^3.

**Periodic column.** c(X) = P_c(X^{n/8}), where P_c has degree < 8 and P_c(ω_8^j) = C[j] with ω_8 = ω^{n/8}. Its 8 coefficients are baked VK constants, asserted against C at build time.

**Composition.** Four independent challenges α_1..α_4 ∈ F_{p^3}, with Z_T(X) = (X^n − 1)/(X − ω^{n−1}):

```
H(X) = (α1·C1 + α2·C2)(X) · (X − ω^{n−1}) / (X^n − 1)  +  α3·(X(X) − x_in)/(X − 1)  +  α4·(X(X) − y_out)/(X − ω^{n−1})
```

- deg H ≤ 2n − 2.
- The prover commits H = H0(X) + X^n·H1(X), with deg H0, H1 < n.
- These are F_{p^3}-valued, stored as 3 base coefficients each: 6 base values per point.

**AIR check at z, without inversion.** Let den = (z^n − 1)(z − 1)(z − ω^{n−1}). The verifier requires

```
(H0(z) + z^n·H1(z)) · den  ==  (α1·C1(z) + α2·C2(z))·(z − ω^{n−1})^2·(z − 1)
                               + α3·(X(z) − x_in)·(z^n − 1)·(z − ω^{n−1})
                               + α4·(X(z) − y_out)·(z^n − 1)·(z − 1)
```

Here C1(z) = Y(z) − (X(z) + c(z))^3 and C2(z) = X(ωz) − Y(z)^2·(X(z) + c(z)).

**OOD values** (5 elements of F_{p^3}): X(z), Y(z), X(ωz), H0(z), H1(z).

**DEEP polynomial.** Five independent γ_1..γ_5 ∈ F_{p^3}, batched as in BCIKS20 §8.2:

```
f0(x) = [γ1(X(x)−X(z)) + γ2(Y(x)−Y(z)) + γ4(H0(x)−H0(z)) + γ5(H1(x)−H1(z))] / (x − z)  +  γ3 (X(x) − X(ωz)) / (x − ωz)
```

FRI tests f0 against RS[F_{p^3}, L0, n], where L0 = 7·⟨ω_N⟩ and N = n/ρ.

The verifier requires **z ∉ F_p**, i.e. (z1, z2) ≠ (0, 0). Then x − z and x − ωz are nonzero for every x ∈ F_p, and z avoids H and L0. The honest prover is rejected with probability 2^−128.

## 3. Proof format and transcript

### 3.1 Encodings
- A base element is 8-byte little-endian. It is decoded unsigned: `BIN2NUM(b ‖ 0x00)`.
- An F_{p^3} element is its 3 coefficients (c0, c1, c2), 24 B.
- **No range checks on committed or transcript-bound values.** Every value the verifier uses is bound by a hash before any challenge that depends on it. The map bytes → F_p (reduce mod p) is deterministic, so a non-canonical encoding is just another committed value. This is unlike the Groth16 handovers, which need `< p` because they compare computed values byte-exactly.
- The **statement** (x_in, y_out) is required canonical (< p), so that a statement has one encoding.

### 3.2 Domains, folding and leaves
- L_0 = 7·⟨ω_N⟩. Position u ↦ 7·ω_N^u. The fold arities are a_0 = k0 = 4, a_1 = a_2 = 8 (both sets).
- L_{i+1} = L_i^{a_i}, with size N_{i+1} = N_i/a_i and shift 7^{a_0···a_i}.
- The **coset of position v ∈ L_{i+1}** is {u = v + j·N_{i+1} : j < a_i}. Its points are x_j = x0·ω_{a_i}^j, where x0 = shift_i·ω_{N_i}^v.
- **Leaves.** Leaf v of a layer-i tree holds the a_i coset values in j order:
  - trace tree: X, Y per point (a_0·16 B = 64 B);
  - composition tree: H0, H1 per point (a_0·48 B = 192 B);
  - FRI tree i ≥ 1: f_i per point (a_i·24 B = 192 B).
- **Fold.** With v_j = f_i(x_j) and β = β_{i+1}:

  ```
  f_{i+1}(x0^{a}) = (1/a) · Σ_{t<a} (β·x0^{-1})^t · V_t,   V_t = Σ_j v_j·ω_a^{-jt}
  ```

  This is an inverse DFT with base-field twiddles, then Horner in β·x0^{−1}.
- **Next position.** The value at position v of L_{i+1} sits in leaf v mod N_{i+2}, slot v div N_{i+2}.
- **Final layer.** After the last fold, f_r has degree < 2^8 on L_r and is sent as **256 F_{p^3} coefficients**. The verifier evaluates it at the query's point of L_r (base field point, F_{p^3} coefficients).

### 3.3 Merkle commitments (SHA-256)
- leaf hash = SHA256(tag_t ‖ leaf bytes)[0:h], with a 1-byte tag per tree. The tag is not needed for soundness, because depth and leaf length are fixed per tree. It costs about 100 op per leaf, and it removes any reviewer doubt.
- node = SHA256(left ‖ right)[0:h], untagged.
- Index bits go LSB-first from the leaf (bit ℓ set means the node is a right child at level ℓ).
- Roots are h bytes.
- Collision security is 4h bits (an attacker making Q queries succeeds with probability Q^2/2^{8h}). So h = 25 gives 100 bits and h = 32 gives 128.
- Field challenges are always derived from full 32-byte digests.

### 3.4 Fiat-Shamir transcript (SHA-256, full digests)

```
TAG  = "verifier.cash/pq-hash/v1" ‖ param-id (1 B: P100=1, P128=2) ‖ SHA256(baked constants: C[], P_c, roots-of-unity, arities, n, N, s, g, h, m)
t0   = SHA256(TAG ‖ x_in ‖ y_out)
t1   = SHA256(t0 ‖ root_trace);       α_j  = E(SHA256(t1 ‖ "a" ‖ u8 j)), j = 1..4
t2   = SHA256(t1 ‖ root_comp);        z    = E(SHA256(t2 ‖ "z"))              (require z ∉ F_p)
t3   = SHA256(t2 ‖ OOD[5×24 B]);      γ_j  = E(SHA256(t3 ‖ "g" ‖ u8 j)), j = 1..5;   β_1 = E(SHA256(t3 ‖ "b"))
t4   = SHA256(t3 ‖ root_fri1);        β_2  = E(SHA256(t4 ‖ "b"))
t5   = SHA256(t4 ‖ root_fri2);        β_3  = E(SHA256(t5 ‖ "b"))
t6   = SHA256(t5 ‖ final[256×24 B])
G    = SHA256(t6 ‖ nonce[8 B]);       require the top g = 28 bits of G be zero (first 3 bytes 0, 4th byte < 0x10)
idx_i = (LE uint of SHA256(G ‖ u16 i)) mod (N / k0),  i = 0..s−1   (position in L_1, i.e. the coset index; uniform, N/k0 a power of 2)
```

- E(d) maps a digest to F_{p^3}: v = BIN2NUM(d ‖ 0x00) < 2^256, then c0 = v mod p, c1 = (v div p) mod p, c2 = (v div p^2) mod p.
  - It is v mod p^3, written in base p.
  - Every challenge value has probability at most (1 + p^3/2^256)/p^3 ≤ (1 + 2^−64)/q. So any bad-event bound loses a factor of 1 + 2^−64, which is negligible.
- Each challenge is drawn after every message it must be independent of:
  - α after the trace;
  - z after H;
  - γ and β_1 after the OOD values (f0 is then fixed);
  - β_{i+1} after f_i's root;
  - query indices after the final polynomial and the grinding nonce.
- Duplicate indices are allowed. They are sampled with replacement, which the query bound assumes.

### 3.5 Proof contents and sizes (calculator, `proof_bytes`)

| part | P100 | P128 |
|---|--:|--:|
| PT: statement 16; roots 4·h; OOD 120; final polynomial 6,144; nonce 8 | 6,388 | 6,416 |
| leaves, per query: trace 64 + comp 192 + fri1 192 + fri2 192 = 640 B | 14,080 (22 q) | 27,520 (43 q) |
| Merkle siblings, deduplicated multiproof (expected) | 29,554 | 57,532 |
| **total, single input** | **50,022** | **91,468** |
| same with plain per-query paths (no dedup) | 61,718 | 126,128 |
| same with optimisation O1: FRI leaves omit the derived value (7 of 8 values) | 48,966 | 89,404 |

Tree depths:
- P100 (N = 2^23): trace and comp 21, fri1 18, fri2 15.
- P128 (N = 2^21): 19, 19, 16, 13.

## 4. Soundness (provable regime)

### 4.1 Bounds used
Notation: q = p^3 ≈ 2^191.999, N = |L_0|, ρ = n/N, m ≥ 3 the Johnson parameter, L = (m + ½)/√ρ the Guruswami–Sudan list-size bound (BCIKS20 eq. 5.6, D_Y < (m+½)/√ρ).

| round | error bound (per round, interactive) | source |
|---|---|---|
| ALI (α) | L·M_C/q, M_C = 4 | ethSTARK v1.2 DEEP-ALI, list-decoding form |
| DEEP (z) | L^2·(D·n + 2N)/q (the 2N covers z or ωz landing in L_0) | ethSTARK v1.2; DEEP-FRI (BGKS20) |
| batching + all FRI folds (γ, β_1..β_r) | ε_C = (m+½)^7·N^2 / (2ρ^{3/2}·q) + (2m+1)(N+1)/√ρ · Σ a_i / q | **BCIKS20 Thm 8.3** (batched FRI, independent batching coefficients x_1..x_t, D_0 a coset of a 2-smooth group, ρ = 2^−R, m ≥ 3) |
| query (s queries, g grinding bits) | (√ρ·(1 + 1/(2m)))^s · 2^−g | BCIKS20 Thm 8.3 plus proof-of-work |

Fiat-Shamir:
- STARK-with-FRI is round-by-round sound with per-round errors bounded by the table (Block, Garreta, Katz, Thaler, Tiwari, Zajac, ePrint 2023/1071; ethSTARK v1.2 §6).
- The SHA-256 random-oracle compilation then gives an attacker with Q hash queries a success probability ≤ Q·2^−λ_IOP + O(Q^2/2^{8h}), where λ_IOP = min over rounds of (−log2 ε_round + grinding_round).
- We report **λ = min(λ_IOP, 4h)**: the work, in SHA-256 calls, needed for constant success probability.
- Grinding enters only the query round (g = 28). The commit rounds need none at q ≈ 2^192.
- The Analysis phase must check one inequality against ePrint 2023/1071's list-decoding RBR theorem: that every per-round commit error is ≤ ε_C. If their constant is larger, s grows by 1–2 queries (about 2 KB at P128).

### 4.2 Results (calculator, `soundness`)

| set | ρ | m | s | g | h | ALI | DEEP | batch+folds | query | λ_IOP | **λ** |
|---|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| P100 | 2^−7 | 3 | 22 | 28 | 25 | 184.7 | 157.4 | 123.9 | 100.1 | 100.1 | **100** (digest) |
| P128 | 2^−5 | 4 | 43 | 28 | 32 | 185.3 | 160.6 | **128.3** | 128.2 | 128.2 | **128** |

P128's commit-phase margin is thin (128.3 bits). m = 4 is chosen for it; m = 3 would need s = 44.

### 4.3 Comparison regimes (clearly not the main sets)

| set | regime | q | s | proof bytes | note |
|---|---|---|--:|--:|---|
| U100 | unique decoding (BCIKS20 Thm 1.2/1.5/1.6: ε_U = n/q per line, (a−1)·n/q per fold) | p^2 | 79 | 107,423 | per-query factor (1+ρ)/2, so ≤ 1 bit per query |
| U128g | unique decoding + 24-bit grinding on every commit challenge | p^2 | 121 | 166,568 | per-round commit grinding (as Plonky3 does) is sound in the RO model but costs 6 PoW nonces; listed only to show that deg-2 cannot reach 128 cheaply |
| B128 | **sensitivity only**: BCHKS25 Thm 1.5 (ePrint 2025/2055) Johnson gap linear in n, applied per round | p^3 | 30 | 75,450 | the theorem is for lines; its extension to curves and weighted agreement (needed for FRI folding) is not established here, so no set uses it |
| C100 | **conjectured** (ethSTARK-style, 1 bit per query per blowup bit) | p^2 | 11 | 23,940 | the up-to-capacity conjectures were disproved for some parameters in 2025 (Crites–Stewart ePrint 2025/2046; Diamond–Gruen ePrint 2025/2010; Krachun–Kazanin–Haböck ePrint 2026/782). For comparison only |
| C128 | conjectured | p^3 | 15 | 41,748 | as above |

2026 preprints claim above-Johnson provable FRI bounds (ePrint 2026/858, 2026/861). They are not peer-reviewed and are not used here.

### 4.4 Sensitivity (calculator)
- **Trace length.** These are optimum dedup bytes for the provable sets (each re-optimised over ρ, m, arities and final degree):

  | n | 100-bit | 128-bit |
  |---|--:|--:|
  | 2^12 | 30.8 KB | 47.5 KB |
  | 2^14 | 40.8 KB | 66.2 KB |
  | 2^16 | 50.0 KB | 91.5 KB |
  | 2^18 | 60.4 KB | 138.1 KB |
  | 2^20 | 71.6 KB | 209.0 KB |

  - At 128 bits the N^2 term of Thm 8.3 forces smaller blowup as n grows, so more queries are needed.
  - P128 fits one TXv5 input up to n = 2^16.
- **Grinding** (P128 shape): 98.6 / 95.0 / 91.5 / 89.7 KB at g = 20 / 24 / 28 / 32. About 0.9 KB per bit near g = 28. Prover cost doubles per bit.
- **Final degree** trades bytes for op-cost. At P128, 2^5 instead of 2^8 costs +8.1 KB (99.6 KB, no longer fits one TXv5 input) and saves about 0.3M op per query. P100: +2.6 KB.

## 5. Parameter sets (for the Build phase)

| name | regime | e | n | ρ | folds | final deg | m | s | g | h | λ | proof B (dedup) |
|---|---|--:|---|---|---|---|--:|--:|--:|--:|--:|--:|
| **P100** | provable, Johnson (BCIKS20 Thm 8.3) | 3 | 2^16 | 2^−7 | 4, 8, 8 | < 2^8 | 3 | 22 | 28 | 25 | 100 | 50,022 |
| **P128** | provable, Johnson (BCIKS20 Thm 8.3) | 3 | 2^16 | 2^−5 | 4, 8, 8 | < 2^8 | 4 | 43 | 28 | 32 | 128 | 91,468 |
| C100 (optional, labelled CONJECTURED) | conjectured | 2 | 2^16 | 2^−7 | 8, 16, 8 | < 2^6 | – | 11 | 28 | 25 | 100* | 23,940 |

- P100 and P128 share the code. Only baked constants (TAG, n, N, ω_N, shifts, s, g, h, query split) differ.
- C100 needs F_{p^2} kernels and arity-16 folding. Build it only if time allows, and always label it conjectured.

## 6. Layout (a): today's standard rules

Rules:
- ≤ 10,000 B unlocking per input;
- ≤ 201 B P2S locking (we use P2SH32: 35 B);
- ≤ 100,000 B per transaction;
- op-cost budget (41 + unlocking)·800 per input;
- hash iterations ≤ 0.5·(41 + unlocking) standard.

### 6.1 Patterns reused (cite, do not reinvent)
From `groth16_cashscript/chunked/bn254/bn-native-sound/README.md` (reviewed 2026-10-26) and `chunked/bls12-381/bls-native-sound/` (code in `script.mjs`, `transaction.mjs`, `layout.mjs`):
- **One redeem R in every input** (P2SH32, ≈ 65–80 B). R reads the code pieces from fixed byte ranges of fixed inputs with `OP_INPUTBYTECODE`, concatenates them, checks `OP_SHA256 == K_code`, then `OP_DEFINE` and invoke. The code then dispatches with `OP_INPUTINDEX <base> OP_ADD OP_INVOKE`: function-id dispatch, because unexecuted branches still cost op-cost.
- **Graph pin.** `OP_TXINPUTCOUNT == I` and `OP_UTXOBYTECODE(j) == OP_UTXOBYTECODE(OP_INPUTINDEX)` for every j. Every input runs the same authenticated code; the role is the index.
- **Own-layout pin** in every input: DEPTH, every item size, the raw unlocking size. Fillers are all zero (compared with `NUM2BIN(0, SIZE)`) and come after every range another input reads. **Push-header checks** go before every remote read.
- **No handed-over challenges.** Every input re-derives the transcript (§3.4) from the PT bytes it reads. This is cheap: about 300 hash iterations, mostly the 6.1 KB final polynomial.
- **Handover by byte equality** between a value computed in one input and bytes pushed in another. Here that is the pruned-cap nodes (§6.2).

Cross-transaction state rides an NFT, as in the grouped constructions:
- See `chunked/grouped/README.md` ("Across groups: the running state rides a CashToken NFT commitment") and `chunked/intratx/transform.mjs` (`covInHash`, `epilogueMode`).
- The BLS grouped-residue README notes its thread "requires a mutable NFT, excludes same-category sibling inputs, and requires the terminal transaction to burn the thread token".
- Caution: the BN `grouped` entries are withdrawn for F1 (no exact-length gate, STATUS-MAP rows 61–62). Every input here must pin its own layout exactly.

### 6.2 Roles inside one transaction
Each tree t is opened with a **pruned cap at level c_t = depth_t − b**:
- A **query** blob carries the leaves and the b lowest siblings for each tree.
- A **TOP_t** blob carries:
  1. the level-c_t node of every query of this transaction, in query order (s_tx·h B; duplicates allowed, and they must be equal);
  2. the deduplicated multiproof siblings above level c_t, in canonical order. The algorithm: sort the distinct level-c_t positions, go up one level at a time, combine a node with its sibling if present, otherwise consume the next proof sibling.
- Each query's computed level-c_t node must equal its entry in TOP_t (remote read, fixed offset). The TOP_t owner merges up to root_t.
- b is chosen per transaction to minimise bytes under the op-cost rule in §6.4.

| role | carried bytes | work |
|---|---|---|
| HEAD (input 0) | PT (6.4 KB) and, if room, code pieces | statement canonical; transcript, grinding; AIR identity at z; tx-thread rules (§6.3) |
| TOP_t (one or more inputs, packed with others) | TOP_t blob | derive this transaction's indices; check that duplicate prefixes carry equal nodes; multiproof merge to root_t |
| CODE | code pieces (≈ 4 KB in total, estimate) | none (hosted) |
| QRY (the remaining space) | per query: 4 leaves + 4·b siblings (P100: 1,643 B; P128: 1,667 B) | x0 and x0^−1; leaf hashes; paths to c_t; compare with TOP_t; batched DEEP inversion; f0 at k0 points; 3 folds with consistency checks; final polynomial at y_r |

**Packing rule (Build).** Data blobs (PT, TOP_t, CODE) may be split across inputs; a query is atomic. Fill inputs to ≤ 10,000 B. Each input must satisfy op-cost ≤ 94% of its own budget (bn-native-sound's liveness margin). An input short of budget gets an all-zero filler.

**Model output (`layout_standard`):**

| set | tx | inputs | bytes | b | TOP bytes (trace / comp / fri1 / fri2) | queries per tx | op total / budget total |
|---|--:|--:|--:|--:|---|---|---|
| P100 | 1 | 6 | 57,450 | 10 | 3,682 / 3,682 / 2,070 / 693 | 22 | 24.5M / 45.9M |
| P128 | 2 | 7 + 7 = 14 | 61,071 + 58,981 = 120,052 | 8 | 4,712 / 4,712 / 2,650 / 886 per tx | 22 + 21 | 24.5M / 48.7M and 23.5M / 47.0M |

P128 does not fit one standard transaction at n = 2^16:
- The model gives 102–104 KB in one transaction (100.1 KB with O1 and g = 32).
- At n ≤ 2^15 it fits one transaction (91.1 KB, 11 inputs).

### 6.3 Two transactions for P128 (the NFT thread)
Deployment:
- Choose a funding outpoint. Its txid is category **CAT**, baked into the code (so K_code depends on the deployment; there is no cycle, since CAT does not depend on R).
- The genesis transaction locks CAT's **minting NFT ("baton")** at P2SH32(R).

**tx 0 (queries [0, 22)).** Selected because input 0 holds the baton. Its HEAD additionally requires:
- output 0 returns the baton to P2SH32(R) unchanged;
- output 1 is an immutable CAT NFT at P2SH32(R) with commitment `SHA256("pq-hash/thread" ‖ G ‖ 0x01)`;
- no other output carries CAT.

**tx 1 (queries [22, 43)).** Selected because input 0 holds an immutable CAT NFT. Its HEAD requires:
- that NFT's commitment equals `SHA256("pq-hash/thread" ‖ G ‖ 0x01)`, where G is recomputed from tx 1's own PT;
- no other input carries CAT (so the baton cannot be present);
- no output carries CAT (the thread token is burned);
- tx 1 is where the verdict holds, and application output rules go here.

Why this binds:
- Only a transaction spending P2SH32(R) can move the baton, and every such transaction runs the verifier. So a CAT thread NFT with commitment D exists only if some tx 0 verified queries [0, 22) for the transcript with digest G.
- G commits to the entire PT (statement, roots, OOD values, final polynomial, nonce), up to a SHA-256 collision.
- tx 1 recomputes G and all query indices from its own PT copy. Splicing tx 0 of proof A with tx 1 of proof B changes G and fails.
- Each transaction verifies its own TOP blobs against the same roots.

The PT (6.4 KB) and the code are re-sent in tx 1. The model includes this.

### 6.4 Op-cost per input: a nuance for the page
- Totals are comfortable: 24.5M of 45.9M at P100.
- An input that carries **only** leaves can be op-short. At 643 B per query (leaves only), its bytes buy 0.48M of budget, against about 1.0M of verifier work per query in the model. Of that 1.0M, the 256-coefficient final polynomial is about 0.46M and DEEP about 0.21M.
- The packer therefore keeps b ≥ 8–10 levels of siblings inside each query blob (siblings bring op budget and cost little to verify), rather than moving all siblings to the TOP blobs.
- At small n the bytes-optimal parameters even need fillers. With n = 2^10, P100 needs 16 inputs; in that regime op-cost binds.
- So "bytes bind" holds for the whole proof but not per input. The Kernels numbers decide b.

## 7. Layout (b): one input (TXv5-as-written and libauth bch-spec)

Unlocking:

```
[PT] [leaves block: s × 640 B] [multiproof siblings, tree by tree] [push(code-as-redeem)]
```

- P2SH32 of the code. The code is ≤ 100,000 B under TXv5 (stack items ≤ 100,000 B) and uses OP_DEFINE internally for its functions.
- One input, one output; standard transaction ≤ 100,000 B.
- All queries are in one place, so every tree uses a full deduplicated multiproof from leaf hashes (c_t = depth_t).

| set | unlocking | tx | op (model) | TXv5-as-written budget (41 + L)·800 | bch-spec budget (10,000 + L)·800 | hash iterations (est. / std limit) |
|---|--:|--:|--:|--:|--:|---|
| P100 | 54,115 | 54,214 | 23.8M (55%) | 43.3M | 51.3M | ≈ 3.5k / 27k |
| P128 | 95,624 | 95,723 | 45.0M (59%) | 76.5M | 84.5M | ≈ 5k / 47.8k |

- P128's margin to the 100,000 B transaction cap is about 4.3 KB. That covers code up to about 8 KB; the code is estimated at 4 KB.
- If the measured op-cost exceeds the base-41 budget, Build reports the TXv5 zero padding needed (the harness's `txv5.ts` least-fixpoint padding) next to the bch-spec grade.

## 8. Kernels the Kernels phase must measure

Each kernel is measured on libauth BCH_2026 in standard and consensus mode, with op-cost, bytes and hash iterations.
- When OP_DEFINE is used, report the **BCHN-adjusted** op-cost (+ body bytes per OP_DEFINE).
- Optionally, report BCHN ns per op-cost on the opcost-timing rig. It must stay local-only: `listen=0`, `rpcbind=127.0.0.1`.
- Report per call and per iteration, and mark looped vs unrolled code bytes.

**Field arithmetic (Goldilocks and F_{p^3}).**
- K1. Base mulmod a·b mod p (8–9-byte operands). Compare:
  - lazy accumulation (no reduction for 2–4 terms);
  - OP_MOD against a special-form reduction using 2^64 ≡ 2^32 − 1 with OP_RSHIFTNUM / OP_LSHIFTNUM.
- K2. F_{p^3} mul (u^3 = 7), square, ×F_p, add/sub. Compare:
  - schoolbook limbs with lazy reduction;
  - Karatsuba-style;
  - Kronecker-packed (one OP_MUL on packed ≈ 26-byte integers, then unpacking with 2026 shift opcodes).
- K3. F_{p^3} inversion: norm to F_p plus an F_p inversion by an addition chain for p − 2. Also the per-element cost of Montgomery batch inversion.
- K4. ω_N^v and 7·ω_N^v for a 21–23-bit v: square-and-multiply vs 4-bit windowed tables (code bytes against op-cost).
- K5. Digest → F_{p^3} (E(d)), digest → index (mask), grinding check (top 28 bits zero).

**Hashing and Merkle.**
- K6. Merkle level (cur, sibling, bit) → parent, h = 32 and h = 25 (truncation): branch vs branchless. Per level: standard 192, consensus 64 per iteration.
- K7. Leaf hash + parse for 64 B and 192 B leaves, including the tag byte and 8 unsigned decodes.
- K8. Multiproof merge loop per node, with the sorted-prefix bookkeeping and duplicate check.
- K9. Transcript absorption of PT (6.4 KB) and per-challenge hashes; introspection reads (`OP_INPUTBYTECODE` of a 10 KB sibling + SPLIT, push-header checks); R's code load-hash-define (the fixed per-input cost).

**STARK steps.**
- K10. DEEP at one coset point (given batched inverses).
- K11. FRI fold arity 4 and 8 (IDFT + Horner). Also arity 16 (C100), and the O1 variant (re-encode the derived value with NUM2BIN and splice it in before hashing).
- K12. Final polynomial: Horner of 256 F_{p^3} coefficients at a base point (reduction cadence).
- K13. AIR identity at z: z^n by squarings, P_c(z^{n/8}), cross-multiplied check.
- K14. Loop and call overhead: OP_BEGIN/OP_UNTIL per iteration, OP_INVOKE, unexecuted-branch cost.

**Settling the page's "BCH VM fit" column.**
- K15. **GF(2^128) multiplication** (Magnetar's field). Measure four variants:
  - shift-and-XOR with OP_LSHIFTBIN/OP_RSHIFTBIN/OP_XOR/OP_AND;
  - a 4-bit or 8-bit windowed table;
  - Karatsuba over 64-bit halves;
  - reduction by x^128 + x^7 + x^2 + x + 1.

  Report the ratio to K2 (F_{p^3}) and to an F_{p^2} mul. The page claims "tens to over a hundred times".
- K16. **Emulated algebraic and other hashes**, op-cost per 32-byte digest compared with the 25,600 standard op-cost a 32-byte node's bytes buy:
  - one RPO permutation (Miden: Goldilocks width 12, x^7 and x^{1/7} S-boxes, MDS);
  - one Tip5 permutation (Triton: split-and-lookup S-boxes);
  - one Blake2s compression (Stwo; 32-bit adds via mask, rotations via shifts/OR).

  The page claims ~100× for RPO/Tip5 and ~10–30× for Blake2s.
- K17. Native SHA-256 per 64-byte node, standard and consensus. This is the baseline for K16 and the page's "a 32-byte node buys 16 hash iterations, checking costs 2".
- K18. Optional, lattice: one Module-SIS inner-product step at Akita-like parameters (the page says "transcript hash and lattice-check cost not yet assessed"). Not required for this track.
- K19. One 192-bit prime field mulmod (no extension), for the field choice in §1.4.

## 9. Build plan, measurement and acceptance

- **Sources.** `groth16_cashscript`, branch `wip/pq-hash-build`, folder `pq-hash/fri-sha256/`. Contents:
  - `prover.mjs` (reference prover, deterministic, grinding);
  - `protocol.mjs` (transcript, value-level verifier mirror);
  - `asm.mjs`/`kernels.mjs` (reuse the bn-native-sound symbolic assembler if practical);
  - `script.mjs`, `transaction.mjs` (layouts a and b), `redteam.mjs`, `sweep.mjs`.
- **Harness glue and research.** `zk-verifier-bench` `research/pq-hash/`, with vectors and a REPORT.md. It is not registered.
- **Gates:**
  - honest proofs accepted (P100 and P128, ≥ 4 statements each, plus different nonces);
  - consensus and standard;
  - BCHN-adjusted op-cost.
- **Rejection tests (plain tampering only):**
  - flipped leaf, sibling, root, OOD, final coefficient or nonce bytes;
  - wrong statement;
  - query blob swapped between proofs;
  - TOP entry swapped;
  - PT mismatch between tx 0 and tx 1;
  - thread token with a wrong commitment;
  - extra, missing or reordered inputs;
  - nonzero filler.
- **Liveness sweep.** Op-cost depends on data only through dedup counts and duplicate queries, so the sweep covers many honest proofs. The worst per-input op-cost must stay ≤ 94% of budget.
- **Report.** For each set: bytes, inputs, transactions, op-cost (standard/consensus/BCHN-adjusted), hash iterations, and the measured vs modelled numbers.
- **Stretch:**
  - O1;
  - C100;
  - a STIR byte model;
  - P128 in one standard transaction at n = 2^15.

### Page implications (for the Report phase, not this phase)
- "about 100 KB": a 128-bit provable proof at n = 2^16 is ≈ 91.5 KB (SHA-256, Goldilocks^3). At 100 bits it is ≈ 50 KB.
- "a dozen or so inputs across at least two transactions": P128 needs 14 inputs in 2 transactions; P100 needs 6 inputs in 1 transaction.
- "up to about 90 KB fits in one TXv5 input with its verifier": consistent (P128 is 95.6 KB with code).
- The "BCH VM fit" entries for Magnetar (GF(2^128)), Miden (RPO), Triton (Tip5) and Stwo (Blake2s) are settled by K15 and K16.

## References
- BCIKS20: Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, *Proximity Gaps for Reed–Solomon Codes*, FOCS 2020 / ECCC TR20-083 (Thm 1.2, 1.5, 1.6, Lemma 8.2, **Thm 8.3**).
- BCHKS25: Ben-Sasson, Carmon, Haböck, Kopparty, Saraf, *On Proximity Gaps for Reed–Solomon Codes*, ePrint 2025/2055 / ECCC TR25-169 (Thm 1.3, 1.5; used only for sensitivity).
- ethSTARK Documentation v1.2, StarkWare, ePrint 2021/582 (DEEP-ALI, RBR, grinding).
- Block, Garreta, Katz, Thaler, Tiwari, Zajac, *Fiat–Shamir Security of FRI and Related SNARKs*, ePrint 2023/1071.
- Haböck, *A summary on the FRI low degree test*, ePrint 2022/1216.
- Crites, Stewart, *On Reed–Solomon Proximity Gaps Conjectures*, ePrint 2025/2046; Diamond, Gruen, ePrint 2025/2010; Krachun, Kazanin, Haböck, ePrint 2026/782 (conjecture counterexamples).
- Chai, Fan, ePrint 2026/858; ePrint 2026/861 (above-Johnson claims, preprints, not used).
