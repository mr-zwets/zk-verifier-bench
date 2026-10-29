# Track 5 / Soundness: per-round Fiat-Shamir soundness of the DEEP-FRI STARK

Date: 2026-10-29. Branch `wip/pq-stark-soundness` (zk-verifier-bench). Research only, not a leaderboard entry.
Calculator: [params5.py](params5.py) (`python3 params5.py --json`). It imports Track 4's byte model from `../../pq-hash/params.py`. Outputs: [params5-output.txt](params5-output.txt), [params5-output.json](params5-output.json).

## 1. Result

- **The open condition from Track 4 holds.** Track 4 assumed that every per-round Fiat-Shamir commit error is at most the combined BCIKS20 Thm 8.3 error ε_C. In the published per-round bound (§2), each round's error is a single summand of ε_C, so that assumption is satisfied.
- **P100 and P128 are provably at target as built.**
  - P100: λ_IOP = 100.11.
  - P128: λ_IOP = 128.19.
  - In both, the query round binds; no fix is needed.
  - P128's commit round has 128.65 bits, which is 0.34 bits more than Track 4's combined-ε_C model (128.31). Its query round has a 0.19-bit margin, the same as in Track 4.
- **Digest term.** λ = min(λ_IOP, 4h) uses the usual convention. With the constant from BGKTTZ Cor. 5, 3(Q²+1)/2^{8h}, the strict reading is λ ≤ 4h − 0.79:
  - h = 25 gives 99.2 bits. P100 needs h = 26 under this reading (+1,187 B).
  - At 128 bits the strict reading cannot be met by any 256-bit hash. "128-bit" here means the birthday bound of SHA-256, as in Track 4, ethSTARK and Plonky3.
- **Cheaper sets.** The per-round bound gives a clear knob: grinding on individual commit challenges (one 8-byte nonce each). Proposed Track 5 sets in Track 4's format:
  - T5-128: 26 queries instead of 43, 70.3 KB instead of 91.5 KB.
  - T5-100: 19 queries instead of 22, 46.0 KB instead of 50.0 KB.
  - Both are §4.
- **Plonky3 with Goldilocks and a degree-2 extension (q ≈ 2^128) is a poor fit for provable soundness.**
  - ~100 bits works, but needs 79 queries (unique decoding) or 93 (Johnson). That is about 148 KB in CashVM format.
  - 128 bits is unreachable: the best is 125 bits, with 16–28-bit grinding at four sites.
  - The ceiling comes from the ALI round. uni-stark has no proof-of-work site before the constraint-folding challenge, so that round is stuck at 128 − log2(L·#constraints).
  - Recommendation: a degree-3 extension. Plonky3's stock `CubicTrinomialExtensionField` (u³ = u + 1) works with no patch (§5, condition 2); the shipped degree-5 extension also works (§5).
- **Status of the Plonky3 figures.** Plonky3 batches with powers of one challenge. The batching term for that, (t−1)(A0 + B1), is our adaptation of [ADK] Thm 2 (sketch in §2.1). It is not a published statement, so every Plonky3 figure here is labelled "JB, powers-batching adaptation, unpublished", not "proven". Only the Track 4-format sets (P100, P128, U*, T5-*), which draw independent γ_j, rest on [ADK] Thm 2 as published.

## 2. The bound used (with theorem numbers)

Each paper was read in the version listed below. Theorem numbers refer to those versions.

| ref | paper | used for |
|---|---|---|
| [ADK] | Atapoor, Delpech de Saint Guilhem, Kindi, *STARK-Based Signatures from the RPO Permutation*, IACR CiC 3(2) (ePrint 2024/1553) | **Thm 2**: RBR (knowledge) soundness of DEEP-ALI + batched FRI, list decoding, with per-round errors ε_1..ε_k. **Thm 3**: the unique-decoding version. **Thm 1** (= Chiesa–Yogev Thm 31.3.1): RBR ⇒ state-restoration soundness |
| [BCIKS] | Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, *Proximity Gaps for RS Codes*, ECCC TR20-083 rev. 3 (= ePrint 2020/654, J. ACM) | Thm 1.2 / 1.5 / 1.6 (UD: ε_U = n/q, curves l·ε). **Thm 7.2 / 7.4** (weighted, Johnson, explicit m). **Lemma 8.2 and its proof (§8.2.1)**: one bad event E^(0) for batching and one E^(i+1) per fold, each bounded separately |
| [BGKTTZ] | Block, Garreta, Katz, Thaler, Tiwari, Zając, *Fiat-Shamir Security of FRI and Related SNARKs*, ASIACRYPT 2023 (ePrint 2023/1071) | **Thm 7**: batched-FRI RBR error max{(m+½)^7·\|L0\|²/(3ρ^{3/2}\|F\|), (1−δ)^ℓ}, for binary folding to a constant. **Cor. 5** (BCS): ε_fs ≤ Q·ε_rbr + 3(Q²+1)/2^κ. **Thm 8 / Lemma 1**: the outer (DEEP-ALI) round errors pay the list size 1/(2η√ρ) ≈ m/ρ |

**Per-round errors** (q = |F_ext|, N = |L0|, ρ = n/N, L = m/(ρ − 2m/N)):

| round | list decoding ([ADK] Thm 2) | unique decoding ([ADK] Thm 3) |
|---|---|---|
| ALI, independent α_j | L/q (Plonky3, powers of α: L·#constraints/q) | 1/q (#constraints/q) |
| DEEP z | L²·max{d(k⁺−1)+(k−1), k+(f−1)ℓ+(k⁺−1)}/(q − \|D∪H\|), with k⁺ = k+2 | the same with L = 1 |
| batching, independent γ (BCIKS Thm 7.4) | A0 + B1, where A0 = (m+½)^7·N²/(3ρ^{3/2}q) and B1 = (2m+1)(N+1)/(√ρ·q) | N/q |
| batching, powers of one α (Plonky3; BCIKS Thm 7.2, curve of degree t−1) | (t−1)(A0 + B1) | (t−1)N/q |
| fold i, arity a_i | (a_i−1)·A0·(N_{i+1}/N)² + a_i·B1 | (a_i−1)(N+1)/q |
| query, s times | (√ρ·(1+1/2m))^s | ((1+ρ⁺)/2)^s, with ρ⁺ = (k+2)/N |

- **Composition.** λ_IOP = min over rounds of (−log2 ε_round + grinding bits sited before that round's challenge). The bound is then ε(Q) ≤ Q·2^−λ_IOP + 3(Q²+1)/2^{8h}, by [BGKTTZ] Cor. 5, or (t+k)·ε_RBR by [ADK] Thm 1.
- **Grinding** adds g bits to exactly the round whose challenge it precedes. Each RO query yields at most one candidate challenge, and that candidate passes the PoW with probability 2^−g.
- **Why the open condition holds.** The proof of [BCIKS] Lemma 8.2 bounds each bad event on its own:
  - Pr[E^(0)] ≤ A0 (eq. 8.8).
  - Pr[E^(i+1)] ≤ (l−1)ε^(i) + B-term, where ε^(i) uses the folded domain size squared.
  - "Doomed" (weighted agreement ≤ α) is a function of the transcript. Eq. 8.10 holds for every next prover message, so this is exactly an RBR state function, which is the argument of [BGKTTZ] §2.2.
  - ε_C is the sum of these terms, made looser (½ in place of ⅓, Σa_i·B1), so every per-round error is ≤ ε_C.
- **Conservative choices made here:**
  - DEEP is charged L² (as [ADK]), not L.
  - Fold rounds use a_i·B1, not B1.
  - L is m/ρ ([ADK], [BGKTTZ] Lemma 1), not the tighter (m+½)/√ρ that Track 4 and Plonky3 use.
  - z is drawn from F_q \ F_p.
### 2.1 Powers batching (Plonky3): proof sketch of the adaptation (ours, not peer reviewed)

Plonky3 combines the t DEEP quotients u_0..u_{t−1} as f0 = Σ_j α'^j·u_j (one challenge α'), where [ADK] Protocol 1 uses f0 = Σ_j γ_j·u_j with independent γ_j. The sketch below says why only the batching-round error changes, and by the factor t−1. It has not been checked by anyone outside this project.

1. **Where independence is used.** In the proof of [ADK] Thm 2, the batching round's bad event is the [BCIKS] Lemma 8.2 event E^(0): the u_j have no correlated agreement of weight above the Johnson threshold α, yet the sampled combination f0 has agreement above α. Its probability is bounded by applying the correlated-agreement theorem to the family {Σ_j γ_j u_j}. That is the only place where the distribution of the batching challenge enters. The later rounds (folds, query) and the RBR state function look only at f0 and its agreement set, not at how f0 was formed.
2. **The curve version.** With powers, the family is the curve z ↦ Σ_j z^j u_j of degree t−1 in z. [BCIKS] Thm 7.2 (weighted, Johnson range, explicit m) states correlated agreement for such curves with the error multiplied by the curve degree: if Pr_z[agreement of u_z > α] > (t−1)·ε, then the u_j have correlated agreement. In the proof, each count of bad z values comes from a nonzero polynomial in z, whose degree grows from 1 (line) to t−1 (curve). That is the source of the factor.
3. **Substitution.** Using Thm 7.2 in place of Thm 7.4 bounds Pr[E^(0)] by (t−1)(A0 + B1) instead of A0 + B1. The other per-round errors are unchanged, so the [ADK] Thm 1 / [BGKTTZ] Cor. 5 composition goes through as before, with this one summand replaced.
4. **ALI with powers of α.** For each of the at most L codewords in the list, the combined constraint is a nonzero polynomial in α of degree #constraints−1 unless every constraint vanishes. Schwartz-Zippel then gives L·#constraints/q (charged with #constraints, not #constraints−1).

Until this sketch is written out as a proof and checked, the Plonky3 figures (S*, and the P*/C* rows of the verifier phase, which are all Plonky3 proofs) are reported as "JB, powers-batching adaptation, unpublished". The factor (t−1) is already charged in every Plonky3 figure (log2(t−1) ≈ 3.9 bits at t = 16), and the S sets depend on it materially: their batching round sits close to the binding query round (per-vector security.json: S100b batch 100.66 vs query 100.25; S100z 100.39 vs 100.21; S128 129.38 vs 128.17, with 23 bits of batch PoW). If the adaptation needed a larger factor, these sets would drop below target unless batch PoW is raised. Batch PoW is a free knob in Plonky3 (`batch_proof_of_work_bits`), so the fix would be cheap.

- **How Track 4 departs from [ADK]'s Protocol 1, and why each departure is safe:**
  - No ZK mask. The mask is prover-chosen, and R = 0 is allowed.
  - γ_1..5 and β_1 are drawn in one round, because f0 is virtual and nothing is committed in between. That merged round is charged batch + fold1 (union bound).
  - The final polynomial is sent as coefficients, so f^(r) ∈ RS. This matches the premise of [BCIKS] Claim 8.5.
  - Queries sample a coset index on L1, which induces the same uniform chains.
- **Cross-check.** The unique-decoding Plonky3 terms equal p3-security's (commit 0d80373) term by term: ALI 126.00, DEEP 109.68, batch 104.54, fold 104.09 and query 0.9125 bits per query for P3-100u. This was checked against the source by hand, not by running it; building p3-security was not allowed in this session.

## 3. Track 4 sets under the per-round bound

| set | regime | ALI | DEEP | batch+fold1 | fold2 | fold3 | query | λ_IOP | λ (4h) | strict 4h−0.79 | bytes |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| P100 (ρ 2^−7, m 3, s 22, g 28, h 25) | JB | 183.4 | 156.8 | 124.2 | 131.6 | 137.6 | **100.11** | 100.11 | **100** | 99.21 | 50,022 |
| P128 (ρ 2^−5, m 4, s 43, g 28, h 32) | JB | 185.0 | 160.0 | 128.65 | 136.1 | 142.1 | **128.19** | 128.19 | **128** | 127.21 | 91,468 |
| U100 (e=2, ρ 2^−4, s 79) | UD | 128.0 | 110.0 | 106.0 | 105.2 | 105.2 | **100.09** | 100.09 | **100** | 99.21 | 107,423 |
| U128g (e=2, ρ 2^−3, s 121, g_c 24 on α, z, γ/β) | UD | 152.0 | 134.0 | 131.0 | 130.2 | 130.2 | **128.44** | 128.44 | **128** | 127.21 | 166,568 |

**Fixes.** None is needed for the stated targets. For extra margin on P128, the cheapest changes found by the search (`P128 safety margins` in the output) are:
- ρ = 2^−6, m = 5, s = 35, and a 5-bit nonce before γ/β_1: this is 10.0 KB *smaller* than P128 at the same 128.19 bits (P128-lite, §4).
- The same shape with s = 36 and an 8-bit nonce gives +2 bits.

If the strict digest reading is wanted at 100 bits, use h = 26: 51,209 B instead of 50,022.

## 4. Recommended Track 5 sets (Track 4 proof format, n = 2^16, e = 3)

| set | ρ | folds | final deg | m | s | g (query) | commit grinding | h | rounds before grinding | λ_IOP | proof B |
|---|---|---|---|--:|--:|--:|---|--:|---|--:|--:|
| **T5-100** | 2^−8 | 4, 16 | < 2^7 | 4 | 19 | 28 | none | 25 | ALI 182.0, DEEP 154.0, γβ1 118.2, β2 126.5, query 72.8 | 100.77 | **46,010** |
| **T5-128** | 2^−8 | 4, 8, 8 | < 2^8 | 5 | 26 | 28 | **12 bits before γ/β_1, 5 bits before β_2** (2 nonces) | 32 | ALI 181.7, DEEP 153.4, γβ1 116.1, β2 123.6, β3 129.6, query 100.4 | 128.12 | **70,288** |
| P128-lite (smaller LDE) | 2^−6 | 4, 8, 8 | < 2^8 | 5 | 35 | 28 | 5 bits before γ/β_1 (1 nonce) | 32 | ALI 183.7, DEEP 157.4, γβ1 123.1, β2 130.6, β3 136.6, query 100.2 | 128.19 | 81,474 |

- **Effect.** Fewer queries cut the field work, which is ~84% of op-cost and scales with s:
  - 43 → 26 queries is about 40% less query work at 128 bits.
  - The Merkle trees are 3 levels deeper, roughly +12 path levels per query at about 2k op each. That is small next to the roughly 1.4M op-cost per query.
- **Cost.** The prover's LDE grows to 2^24 rows. Grinding work is 2^28 + 2^12 + 2^5 SHA-256 calls.
- **Measured?** These are calculator figures. Neither the prover nor the verifier has been built for them.

## 5. Plonky3 FriParameters (Goldilocks, SHA-256 MMCS, 32-byte digests)

**Assumptions.**
- Plonky3 main as of 0d80373 (2026-10-26). `FriParameters` has `log_blowup`, `log_final_poly_len`, `max_log_arity`, `num_queries`, `batch_proof_of_work_bits`, `commit_proof_of_work_bits` and `query_proof_of_work_bits`; uni-stark adds `ood_pow_bits`.
- m is an analysis parameter, not a Plonky3 knob.
- Reference AIR (used for the tables in this section only): Track 4's MiMC-7 in a planning shape that differs from the AIR the Prover phase finally built (width 3, 5 constraints, degree 3). The per-vector figures for the AIRs as built are in zk-verifier-bench `wip/pq-stark-verifier`, `research/pq-stark/verifier/security.json` (S128 128.17, S100b 100.25, mimc-P128 125.94). The planning shape was:
  - width 2;
  - 4 constraints of degree 4 including the selectors;
  - 4 quotient chunks (8 under ZK);
  - max_combo 2;
  - t = 12 batched openings at e = 2 (16 at e = 3).
- PoW cap: 28 bits per site.
- Bytes are reported two ways, both from the byte model (not measured):
  - "full-path" (labelled `native` in params5.py): every query carries its full Merkle paths with no sharing. This **overstates** Plonky3's real proofs, whose multiproofs are already pruned;
  - "dedup": deduplicated multiproofs. This is the column that matches measured Plonky3 proofs: the S128 row (model 79,704 B) was measured at 78,393 B (mimc-S128-0), and the e = 3 JB lb 8 ~100 row (model 61,174 B) at 60,793 B (mimc-S100b-0). Use the Prover phase's measured bytes wherever a vector exists.

| target | field | regime | log_blowup | max_log_arity | log_final_poly_len | num_queries | query / commit / batch / ood PoW | m | λ_IOP (binding) | full-path B (model) | dedup B (model) |
|---|---|---|--:|--:|--:|--:|---|--:|---|--:|--:|
| ~100 | e=2 (stock) | UD | 4 | 4 | 8 | 79 | 28 / 0 / 0 / 0 | – | 100.09 (query) | 220,600 | 148,025 |
| ~100 | e=2 (stock) | JB | 2 | 3 | 8 | 93 | 28 / 19 / 26 / 0 | 3 | 100.13 (fold1) | 254,480 | 144,556 |
| **~100** | **e=3 (stock trinomial)** | JB | 5 | 3 | 7 | 30 | 27 / 0 / 0 / 0 | 12 | 100.23 (query) | 105,664 | 77,966 |
| ~100 | e=3 (stock trinomial) | JB | 8 | 4 | 8 | 19 | 25 / 0 / 0 / 0 | 16 | 100.16 (query) | 73,576 | 61,174 |
| ~100 | e=5 (stock) | JB | 8 | 3 | 7 | 19 | 25 / 0 / 0 / 0 | 16 | 100.16 | 87,608 | 72,106 |
| 128 | e=2 (stock) | – | **not reachable**: best is 125 (UD, lb 4, a 2^4, 107 queries, PoW 28/21/21/16; ALI ceiling 126) | | | | | | | 297,208 | 192,921 |
| **128** | **e=3 (stock trinomial)** | JB | 8 | 4 | 8 | 26 | 26 / 15 / 23 / 0 | 10 | 128.17 (query) | 98,216 | 79,704 |
| 128 | e=3 (stock trinomial) | JB | 5 | 3 | 7 | 41 | 28 / 7 / 14 / 0 | 12 | 128.09 (query) | 143,064 | 102,218 |
| 128 | e=5 (stock) | JB | 8 | 3 | 7 | 26 | 26 / 0 / 0 / 0 | 10 | 128.17 (query) | 117,568 | 94,429 |
| 128 | e=5 (stock) | JB | 5 | 3 | 8 | 41 | 28 / 0 / 0 / 0 | 12 | 128.09 | 161,960 | 121,104 |

**ZK** (HidingFriPcs with `num_random_codewords = e`, the minimum Plonky3 allows; the trace domain doubles):

| target | field | regime | log_blowup | max_log_arity | log_final_poly_len | num_queries | query / commit / batch / ood PoW | λ_IOP | full-path B (model) | dedup B (model) |
|---|---|---|--:|--:|--:|--:|---|--:|--:|--:|
| ~100 | e=3 | JB | 8 | 4 | 6 | 19 | 25 / 0 / 3 / 0 | 100.16 | 106,368 | 87,765 |
| ~100 | e=2 | JB | 1 | 3 | 8 | 260 | 28 / 18 / 26 / 0 | 100.01 | 924,400 | 486,117 |
| 128 | e=3 | JB | 8 | 3 | 8 | 26 | 27 / 13 / 22 / 0 | 128.00 | 143,120 | 115,352 |
| 128 | e=5 | JB | 8 | 3 | 8 | 26 | 26 / 0 / 0 / 0 | 128.17 | 166,480 | 138,712 |

**Conditions for the Prover/Verifier phases:**
1. **Keep every committed matrix at the same height.** A shorter input joins a later fold multiplied by β^a, a curve of degree a rather than a−1. The bounds above assume it does not; p3-security's `FriRegime` doc says the same.
2. **e = 3 needs no patch.** The stock `CubicTrinomialExtensionField` (u³ = u + 1) works, and the Prover phase used it. x³ − x − 1 is irreducible over Goldilocks: x^p ≠ x mod f (no root in F_p) and x^(p³) = x mod f, checked in this phase. The bound depends only on |F| = p³, so the choice of irreducible polynomial does not change any figure. The binomial u³ = 7 used by Track 4 would need a `BinomiallyExtendable<3>` patch; that is not required.
3. **The ALI round has no PoW site.** This is what caps e = 2 at about 121 bits (JB) or 126 bits (UD).
4. **Check query-index uniformity** of `SerializingChallenger64` + `HashChallenger<Sha256>` `sample_bits` in the Verifier phase. The bounds assume uniform indices.
5. **Plonky3's own `p3-security` JB numbers are higher** because it uses the 2026 linear-in-n line count (ePrint 2026/2056, DKT26, Thm 5.12). We list that only as sensitivity, not peer reviewed:
   - e = 2 at 100 bits would drop to 19 queries / 54 KB dedup;
   - e = 2 at 128 bits is still unreachable (123 bits).

## 6. Unique-decoding-only option (fully provable, conservative)

UD uses only the tight UD parts of BCIKS (Thm 1.2/1.5/1.6), with no list sizes.

| set | field | params | λ_IOP | bytes |
|---|---|---|--:|--:|
| U100 (Track 4 format) | e=2 | ρ 2^−4, folds 4, 8, 8, s 79, g 28, h 25 | 100.09 | 107,423 |
| U128 (Track 4 format) | e=3 | ρ 2^−4, folds 4, 8, 8, s 110, g 28, h 32 | 128.38 | 190,817 |
| U128g (Track 4 format) | e=2 | ρ 2^−3, s 121, g 28, g_c 24 on every non-query round | 128.44 | 166,568 |
| P3-100u | e=2 | lb 4, arity 2^4, lfp 8, 79 queries, query_pow 28 | 100.09 | 220,600 native / 148,025 dedup |
| P3-128u | e=3 | lb 3, arity 2^3, lfp 8, 121 queries, query_pow 28 | 128.44 | 371,672 / 221,040 |

UD costs roughly 2–3× the bytes of the Johnson-regime sets: about 1 bit per query, against 2.3–4.

## 7. What is not settled / caveats

- **Thm 2 is applied, not re-proved.** [ADK] Thm 2 is applied to Track 4's protocol with the departures listed in §2. The powers-batching variant (Plonky3) swaps BCIKS Thm 7.4 for Thm 7.2 inside the same proof; this is our adaptation, not a published statement. §2.1 gives a sketch only. Every Plonky3 figure is therefore labelled "JB, powers-batching adaptation, unpublished".
- **The bound is classical.** Quantum: see Track 4 SPEC §4.5. Roughly half the bits.
- **Large-m sets are large-LDE sets.** The cheapest sets use ρ = 2^−8 and m = 10–16. That is allowed, since [ADK] Thm 2 needs only 3 ≤ m < k/2, but it costs a 2^24-row LDE.
- **Not used.** Above-Johnson preprints (ePrint 2026/858, 2026/861) and DKT26 (2026/2056) are excluded. The conjectured regime is excluded as well.
- **Bytes are model figures.** The full-path bytes follow our serializer model (full paths, sibling values, OOD, final poly, PoW witnesses) and overstate real Plonky3 proofs; the dedup bytes match the measured proofs to within 2%. Measured sizes are in the Prover phase's vectors.

## 8. Reproduce

```
cd research/pq-stark/soundness && python3 params5.py --json > params5-output.txt
```

It needs the standard library only, and runs in about 10 s.
