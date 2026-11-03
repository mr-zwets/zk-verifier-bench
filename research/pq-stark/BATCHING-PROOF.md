# Powers batching in Plonky3's FRI: statement, proof and the numbers it gives Tracks 5 and 8

Date: 2026-11-03. Branch `wip/batching-proof` (zk-verifier-bench). Research only. This document is internal and has
not been reviewed outside the project.
Calculator: [design-t8/batching8.py](design-t8/batching8.py) (`python3 batching8.py`), output
[design-t8/batching8-output.json](design-t8/batching8-output.json).

## 0. Summary

Every λ figure in Track 5 (Plonky3 sets) and Track 8 carries the label **"JB, powers-batching adaptation,
unpublished"**. This document writes that adaptation out as a statement and a proof.

1. **The batching step itself is a published theorem.** Plonky3 batches the opened quotients of one LDE height as
   Σ_j α′^j·u_j, which is a parameterized curve of degree t − 1 in α′. For curves, [BCIKS20] Thm 7.2 (the weighted
   Johnson-regime curve theorem) gives exactly the factor t − 1 that Track 5 charges. Independent coefficients use
   Thm 7.4 instead. Lemma 1 (§3) is Thm 7.2 restated as a bound on a probability, with a short proof.
2. **The FRI part is proved here (Theorem 2, §4).** It covers what Plonky3 does and what Track 8 builds on: one α′
   ladder per LDE height, roll-ins at shorter heights with factor β^a, arity-a folds, a committed f^(0), and a final
   polynomial sent as coefficients. The proof follows the proof of [BCIKS20] Lemma 8.2 step by step, with an explicit
   round-by-round state function. It uses no result except Thm 7.2.
   - The batching round's error is **max_h (t_h − 1)·ε_J(N_h)**. Track 8 charges Σ_h (t_h − 1)(A0 + B1) at N_max,
     which is at least as large.
   - A roll-in fold's error is **a·ε_J**, which is the charge in Track 8 Lemma 4.
   - A plain fold's error is (a − 1)·ε_J. Track 8 charges (a − 1)·A0′ + a·B1, which is at least as large.
3. **What is still a reduction, not a proof (§5).** The DEEP-ALI front end is inherited from [ADK] Thm 2 and was not
   re-proved here. That covers the multi-table ALI, the shared ζ, the list sizes, knowledge extraction and the
   Fiat–Shamir step. [ADK]'s own proof is "the analysis of [Sta21] Thm 5 applies as is", and [Sta21] could not be read
   in this session (§7). The interface we need from it is narrow: if the instance is false, the DEEP quotients of at
   least one LDE height have no joint (correlated) agreement above α0. That event happens before α′ is drawn, so it
   cannot depend on how α′ is used.
4. **Numbers (§6).** The batching rounds Track 8 reports are reproduced exactly: M1 136.33 and M2 135.15 bits with
   batch PoW 20 (raw 116.33 and 115.15). Under the exact form of Theorem 2 they are 136.33 and 135.89. M1's λ_IOP is
   128.06 (binding round fold1), M2's is 128.70 (binding round query), and neither changes.
   - Neither binding round uses the factor that is new in this document. M1 fold1 is a plain fold, which [ADK] Thm 2
     covers directly. M2's roll-in fold (128.87, margin 0.87) is now covered by Theorem 2.
   - Sensitivity only, not used: [BCHKS25] Thm 4.2 (curves with a linear-in-n bound) would put the batching round at
     155.6 (M1) and 155.2 (M2). Its §4 proofs are sketches in a preprint.

**Proposed label** (for the maintainer to decide; this branch does not edit other documents): replace
"JB, powers-batching adaptation, unpublished" with **"JB; powers batching by [BCIKS20] Thm 7.2, proof in
BATCHING-PROOF.md (internal, not externally reviewed); DEEP-ALI front end per [ADK] Thm 2"**.

## 1. The statement being proved

Track 5 SOUNDNESS §2.1 (zk-verifier-bench `main`, 6302a2c, `research/pq-stark/soundness/SOUNDNESS.md`) states:

> Plonky3 combines the t DEEP quotients u_0..u_{t−1} as f0 = Σ_j α'^j·u_j (one challenge α') … Using Thm 7.2 in
> place of Thm 7.4 bounds Pr[E^(0)] by (t−1)(A0 + B1) instead of A0 + B1. The other per-round errors are unchanged.

SOUNDNESS-T8 (groth16_cashscript `main`, 31f06b2, `research/pq-stark-batch/SOUNDNESS-T8.md`) extends it twice:
- **Lemma 3 (per-height batching):** ε_batch ≤ Σ_h (t_h − 1)(A0(N_max) + B1(N_max)), with one α′ ladder per LDE height.
- **Lemma 4 (roll-in folds):** a fold round that lands on a height carrying inputs is a curve of degree a in β_r, and
  is charged a·A0·(N_{r+1}/N)² + a·B1.

SOUNDNESS-T8 §13 item 2 asks for these three claims to be written as a proof. Here:

| claim | where | status after this document |
|---|---|---|
| powers batching: factor t − 1 on the batching round | Lemma 1, Theorem 2 (T0) | proved from [BCIKS20] Thm 7.2 |
| per-height ladders: each height batched separately, same α′ | Theorem 2 (T0) | proved; the exact error is max_h, not Σ_h |
| roll-in fold: curve of degree a | Theorem 2 (T2) | proved from [BCIKS20] Thm 7.2 |
| "the other per-round errors are unchanged" | Theorem 2 (T1, T3) and §5 | FRI rounds proved; the DEEP-ALI rounds are a reduction to [ADK] Thm 2 |
| ALI with powers of α (Track 5 §2.1 item 4) | §5.3 | elementary (Schwartz–Zippel), proved |

Constants, as in params5.py (`A0`, `B1`) and params8.py:
- A0(N) = (m + ½)^7·N² / (3ρ^{3/2}·q)
- B1(N) = (2m + 1)(N + 1) / (√ρ·q)
- Notation used below: **ε_J(n, Mn) := max((m + ½)^7·n² / (3ρ^{3/2}), (2m + 1)(Mn + 1)/√ρ) / q.**

## 2. Setting and notation

**Field and codes.**
- p = 2^64 − 2^32 + 1 (Goldilocks). The challenges live in F_q with q = p³ (cubic trinomial extension), so
  log2 q = 191.99999999899.
- For an LDE height h, D_h ⊂ F_p is the size-N_h = 2^h coset on which Plonky3 evaluates. V_h = RS[F_q, D_h, K_h] is
  the Reed–Solomon code of polynomials of degree < K_h = ρ·N_h, with ρ = 2^−9 (blowup 2^9).
- These are [BCIKS20]'s conventions: dimension k + 1 = K_h and rate ρ = (k + 1)/n.
- The words u_j are F_q-valued because the DEEP quotients use ζ ∈ F_q. The code is taken over F_q with D_h ⊂ F_p ⊂ F_q,
  so the theorems apply directly with field F_q (no extension-field remark is needed).

**Agreement** ([BCIKS20] §7).
- For µ : D → [0, 1], agree_µ(f, v) = (1/|D|)·Σ_{x : f(x) = v(x)} µ(x), and agree_µ(f, V) = max_{v∈V} agree_µ(f, v).
- corr-agree_µ(u_0, …, u_l; V) is the largest µ(D′) = (1/|D|)·Σ_{x∈D′} µ(x) over sets D′ ⊆ D on which every u_i
  coincides with some codeword of V.
- With no subscript, µ ≡ 1.
- Two facts are used throughout:
  - (F1) if µ ≤ µ′ pointwise, then agree_µ ≤ agree_µ′;
  - (F2) the correlated agreement of a tuple is at most the correlated agreement of any sub-tuple, and in particular
    at most the agreement of any single member.

**Johnson parameter.** m ≥ 3 is an integer, and α0 := √ρ·(1 + 1/(2m)). Track 8 uses m = 5 (params8's optimum for
both statements), so α0 = 0.048614 and the proximity is 1 − α0 = 0.951386. The Johnson radius is 1 − √ρ = 0.955806.

**The protocol, as Plonky3 0d80373 implements it.** Source: `~/.cargo/git/checkouts/plonky3-*/0d80373/fri/src`.
- *Batching.* `verifier.rs`, `open_input`, around lines 1320–1460: "within one `log_height`, the powers of `alpha`
  form a ladder that advances once per opened column", with offsets starting at 0 for each height.
  - So for each height h ∈ H (the set of LDE heights that carry committed inputs), the reduced opening is
    ro_h = Σ_{j=0}^{t_h − 1} α′^j·u_{h,j}.
  - Here u_{h,j}(x) = (p(x) − p(z))/(x − z), one term per (commitment, matrix, opening point, column) at that height.
  - The hiding PCS adds `num_random_codewords` random columns to each committed matrix (`hiding_pcs.rs`, lines
    270–276), so they count in t_h.
  - The powers are contiguous from α′^0 up to α′^{t_h − 1}, so ro_h is a curve of degree exactly t_h − 1.
- *Order.* All u_{h,j} are fixed before α′: the opened values are observed in transcript step 5, and α′ is drawn in
  step 6 behind the batch PoW (SOUNDNESS-T8 §4).
- *Commit phase.* For r = 0, …, R − 1:
  - the prover commits f^(r) on D_{H_r}, with H_0 = h0 = max H. f^(0) is the prover's claimed ro_{h0}; Plonky3
    commits it;
  - the verifier draws β_r;
  - honestly, f^(r+1) = Fold_{a_r}(f^(r); β_r) + [H_{r+1} ∈ H]·β_r^{a_r}·ro_{H_{r+1}}, where H_{r+1} = H_r − log a_r.
  - The roll-in factor is `beta.exp_power_of_2(log_arity)` = β^a, at `verifier.rs` around lines 1094–1100.
  - Fold_a(f; β)(y) is the interpolant of f on the a-coset over y, evaluated at β (`two_adic_pcs.rs` `fold_row`,
    Lagrange or IFFT at β). Writing f(x) = Σ_{i<a} x^i·f_i(x^a), this is Σ_{i<a} β^i·f_i(y): a curve of degree a − 1
    in β with components f_i : D_{H_{r+1}} → F_q. (Plonky3 indexes the fold over the subgroup; this is the
    degree-preserving reparametrization x ↦ s·x of the coset and changes nothing below.)
  - The final word f^(R) is sent as coefficients of degree < K_{H_R}, so f^(R) ∈ V_{H_R}.
- *Shape conditions.* These are enforced by `vkxN` at generation time (SOUNDNESS-T8 Lemma 4):
  - every h ∈ H \ {h0} equals H_i for some 1 ≤ i ≤ R;
  - the schedule ends exactly at the final height. Plonky3 also errors if any reduced opening is left over
    (`verifier.rs`, "If ro_iter is not empty").
- *Query.* The index g^(0) ∈ D_{h0} is uniform, and g^(r+1) = (g^(r))^{a_r}. Starting from ro_{h0}(g^(0)), the verifier
  keeps a running value.
  - In each round it inserts the running value at g^(r)'s slot of f^(r)'s committed coset row, so the Merkle check
    forces f^(r)(g^(r)) to equal it. It then folds that row at β_r and adds β_r^{a_r}·ro_{H_{r+1}}(g^(r+1)) on a
    roll-in.
  - At the end it compares the running value with f^(R)(g^(R)).
  - Under Merkle binding (the digest term, outside this document), one query accepts if and only if
    f^(j)(g^(j)) = w^(j)(g^(j)) for every j = 0, …, R. Here w^(j) is defined in §4, and the ro values are computed
    from the opened (authenticated) column values.

## 3. The batching lemma

**[BCIKS20] Theorem 7.2** (ECCC TR20-083 revision 3, 2021-07-03, p. 32; verbatim up to typesetting). Let
V = RS[F_q, D, k], ρ = (k + 1)/n and u = {u_0, …, u_l} ⊂ F_q^D. Let µ : D → [0, 1] be weights whose values all have
denominator M. Let m ≥ 3 and α ≥ α0(ρ, m) := √ρ + √ρ/(2m). Let S = {z ∈ F_q : agree_µ(u_0 + z·u_1 + ⋯ + z^l·u_l, V) ≥ α}
and suppose

  |S| > max( (1 + 1/(2m))^7·m^7 / (3ρ^{3/2}) · n²·l , (2m + 1)/√ρ · (M·n + 1)·l ).          (7.1)

Then u_0, …, u_l have at least α correlated µ-agreement with V.

(Note that (1 + 1/(2m))^7·m^7 = (m + ½)^7.) **Theorem 7.4** is the same statement for the affine space
u_0 + span{u_1, …, u_l}, with uniformly random coefficients, and it has **no factor l**: its right-hand side is the
l = 1 bound divided by q.

**Lemma 1 (curve batching).** Let u_0, …, u_l : D → F_q with l ≥ 1. Let µ be a weight function with common
denominator M, and let α ≥ α0. If corr-agree_µ(u_0, …, u_l; V) ≤ α, then

  Pr_{z ← F_q}[ agree_µ(Σ_{j=0}^{l} z^j·u_j, V) > α ] ≤ l·ε_J(n, M·n).

*Proof.*
- Let S = {z : agree_µ(u_z, V) > α}, with u_z = Σ z^j·u_j. If S is empty there is nothing to prove.
- Otherwise let α* := min_{z∈S} agree_µ(u_z, V). Then α* > α ≥ α0, and S = {z : agree_µ(u_z, V) ≥ α*}.
- If |S| exceeded the right-hand side of (7.1), Thm 7.2 at threshold α* would give correlated µ-agreement ≥ α* > α,
  which contradicts the hypothesis.
- Hence |S| ≤ l·q·ε_J(n, Mn), and the probability is |S|/q. ∎

**Remark (what "the adaptation" was).** Track 5 §2.1 described the step as "replacing Thm 7.4 by Thm 7.2 inside the
[ADK] proof". Lemma 1 shows that this replacement is a direct application of a theorem that is in the published paper.
- [BCIKS20] appeared at FOCS 2020 and in J. ACM in 2023. We read and cite the ECCC rev. 3 numbering; we did not check
  the J. ACM numbering.
- In [BCIKS20], Thm 7.2's proof is given as the changes needed to the proofs of Thms 6.1/6.2 (§7.1). We did not
  re-check it.
- What [BCIKS20] does not contain is the FRI wrapper with powers. Its §8.2 (Lemma 8.2 and Theorem 8.3) batches with
  independent x_i and uses Thm 7.4 for E^(0) (its eq. 8.8). §4 supplies the wrapper.
- [BCHKS25] §4.1 names powers batching as "of particular importance in practice … since it requires only a single
  randomness z", and states the curve version of its own bounds (Thm 4.2, Cor. 4.4).

## 4. Theorem 2: batched FRI with per-height powers ladders and roll-ins

**Weights and virtual words** (this generalizes [BCIKS20] §8.2.1).
- ν^(0) :≡ 1 on D_{h0}, and w^(0) := ro_{h0}.
- For j = 0, …, R:
  - µ^(j)(g) := ν^(j)(g) if f^(j)(g) = w^(j)(g), and 0 otherwise;
  - ν^(j+1)(g) := E_{g′ ∈ C_g} µ^(j)(g′), where C_g ⊂ D_{H_j} is the a_j-coset over g ∈ D_{H_{j+1}};
  - w^(j+1) := Fold_{a_j}(f^(j); β_j) + [H_{j+1} ∈ H]·β_j^{a_j}·ro_{H_{j+1}}.
- By induction, ν^(j) and µ^(j) take values in (1/M_j)·ℤ ∩ [0, 1] with M_j = N_{h0}/N_{H_j}, so M_j·N_{H_j} = N_{h0}.

**Claim A (acceptance = weight).** Let ε_Q be the probability that one query accepts, given the full transcript.
Then ε_Q = E_{g∈D_{H_R}}[µ^(R)(g)].

*Proof.* This is [BCIKS20] Claim 8.5, by the same induction.
- E_{g^(j)}[µ^(j)(g^(j))] is the probability that the checks j′ ≤ j along the chain accept, when g^(j) is uniform and
  each g^(j′−1) is uniform in the coset over g^(j′).
- By §2, the checks are exactly f^(j)(g^(j)) = w^(j)(g^(j)).
- A uniform g^(0) with g^(j+1) = (g^(j))^{a_j} induces this distribution. ∎

**State function.**
- Pending_j := {h ∈ H : h = H_i for some i > j} is the set of heights still to be rolled in after state j. By the
  shape conditions, Pending_0 = H \ {h0} and Pending_R = ∅.
- Ψ_j := agree_{ν^(j)}(w^(j), V_{H_j}). This is a function of the transcript up to β_{j−1} (up to α′ for j = 0).
- Before α′: **pre is doomed** :⇔ there is an h ∈ H with corr-agree(u_{h,0}, …, u_{h,t_h−1}; V_h) ≤ α0.
- After α′ (j = 0) and after β_{j−1} (j ≥ 1): **S_j is doomed** :⇔ Ψ_j ≤ α0, or there is an h ∈ Pending_j with
  agree(ro_h, V_h) ≤ α0.

**Theorem 2.** For every prover strategy:
- (T0, batching) If pre is doomed, Pr_{α′}[S_0 not doomed] ≤ max_{h∈H} (t_h − 1)·ε_J(N_h, N_h).
- (T1, plain fold) If S_j is doomed and H_{j+1} ∉ H, then for every message f^(j),
  Pr_{β_j}[S_{j+1} not doomed] ≤ (a_j − 1)·ε_J(N_{H_{j+1}}, N_{h0}).
- (T2, roll-in fold) If S_j is doomed and H_{j+1} ∈ H, then for every message f^(j),
  Pr_{β_j}[S_{j+1} not doomed] ≤ a_j·ε_J(N_{H_{j+1}}, N_{h0}).
- (T3, query) If S_R is doomed, then for every final f^(R) ∈ V_{H_R}, s independent queries all accept with
  probability ≤ α0^s.

So the batched FRI sub-protocol is round-by-round sound from state "pre", with these errors. Summed (plain soundness):
Pr[accept ∧ pre doomed] ≤ ε_batch + Σ_j ε_fold,j + α0^s.

*Proof.*

(T0)
- Fix h* with corr-agree(u_{h*,·}; V_{h*}) ≤ α0. If S_0 is not doomed, then agree(ro_{h*}, V_{h*}) > α0:
  - if h* = h0, this is Ψ_0 = agree(ro_{h0}, V_{h0}), since ν^(0) ≡ 1 and w^(0) = ro_{h0};
  - otherwise h* ∈ Pending_0.
- ro_{h*} = Σ_{j<t_{h*}} α′^j·u_{h*,j} is a curve of degree t_{h*} − 1 in α′, with components fixed before α′.
  Lemma 1 (µ ≡ 1, M = 1, n = N_{h*}) gives probability ≤ (t_{h*} − 1)·ε_J(N_{h*}, N_{h*}) ≤ max_h.
- Only one far height is needed. The same α′ serving every height is therefore harmless, and no union over heights is
  required.

**(Sub-claim: folding preserves farness.)** Let u^(j)_0, …, u^(j)_{a−1} : D_{H_{j+1}} → F_q be the fold components of
f^(j), so that Fold_a(f^(j); β) = Σ_{i<a} β^i·u^(j)_i. Then:

  corr-agree_{ν^(j+1)}(u^(j); V_{H_{j+1}}) ≤ agree_{µ^(j)}(f^(j), V_{H_j}) ≤ Ψ_j.

*Proof of the first inequality.* This is the h^(i) step of [BCIKS20] Lemma 8.2's proof.
- Take D′ ⊆ D_{H_{j+1}} and v_i ∈ V_{H_{j+1}} (degree < K_{H_j}/a) with v_i = u^(j)_i on D′.
- Then P(x) := Σ_{i<a} x^i·v_i(x^a) has degree < K_{H_j}, so P ∈ V_{H_j}, and P = f^(j) on every coset C_g with
  g ∈ D′ (the interpolation map is invertible).
- Hence agree_{µ^(j)}(f^(j), P) ≥ (1/N_{H_j})·Σ_{g∈D′} Σ_{g′∈C_g} µ^(j)(g′) = (1/N_{H_{j+1}})·Σ_{g∈D′} ν^(j+1)(g)
  = ν^(j+1)(D′).

*Proof of the second inequality.* µ^(j) equals ν^(j) where f^(j) = w^(j) and is 0 elsewhere. So for every v,
agree_{µ^(j)}(f^(j), v) ≤ agree_{ν^(j)}(w^(j), v). ∎

**(Sub-claim: next-state bound.)** Ψ_{j+1} = agree_{ν^(j+1)}(w^(j+1), V_{H_{j+1}}), by definition, where w^(j+1) is a
curve in β_j:
- with components u^(j) (degree a − 1) on a plain fold;
- with components (u^(j)_0, …, u^(j)_{a−1}, ro_{H_{j+1}}) (degree a) on a roll-in.
All the components are fixed before β_j: f^(j) is committed before β_j, and ro_h is fixed at α′.

(T1)
- If S_j is doomed by some h ∈ Pending_j, then h ≠ H_{j+1} (because H_{j+1} ∉ H), so h ∈ Pending_{j+1} and S_{j+1} is
  doomed with probability 1.
- Otherwise Ψ_j ≤ α0. By the first sub-claim, corr-agree_{ν^(j+1)}(u^(j)) ≤ α0.
- Lemma 1 with l = a − 1, weights ν^(j+1), M_{j+1}·n = N_{h0} gives Pr[Ψ_{j+1} > α0] ≤ (a − 1)·ε_J(N_{H_{j+1}}, N_{h0}).

(T2) Let h = H_{j+1}.
- If S_j is doomed by some h′ ∈ Pending_j with h′ ≠ h, then h′ ∈ Pending_{j+1}: probability 1.
- Otherwise Ψ_j ≤ α0 or agree(ro_h, V_h) ≤ α0. By (F2), (F1) (ν^(j+1) ≤ 1) and the first sub-claim:
  corr-agree_{ν^(j+1)}(u^(j), ro_h) ≤ min(corr-agree_{ν^(j+1)}(u^(j)), agree_{ν^(j+1)}(ro_h)) ≤ min(Ψ_j, agree(ro_h, V_h)) ≤ α0.
- Lemma 1 with l = a gives Pr[Ψ_{j+1} > α0] ≤ a·ε_J(N_h, N_{h0}).
- S_{j+1} not doomed implies Ψ_{j+1} > α0, so the same bound holds for Pr[S_{j+1} not doomed].

(T3)
- Pending_R = ∅, so Ψ_R ≤ α0.
- Since f^(R) ∈ V_{H_R}, Claim A gives ε_Q = E_g µ^(R)(g) = agree_{ν^(R)}(w^(R), f^(R)) ≤ Ψ_R ≤ α0.
- The s query indices are independent and uniform, so all s accept with probability ≤ α0^s. ∎

**How Theorem 2 relates to what Tracks 5 and 8 charge** (all per round, before grinding):

| round | Theorem 2 (exact) | Track 5/8 charge | relation |
|---|---|---|---|
| batching | max_h (t_h − 1)·max(A0(N_h), B1(N_h)) | Σ_h (t_h − 1)(A0(N_max) + B1(N_max)) | charge ≥ exact (max ≤ Σ, max ≤ +, A0 increases with N) |
| plain fold, arity a | (a − 1)·max(A0(N_{r+1}), B1(N_0)) | (a − 1)·A0(N_0)·(N_{r+1}/N_0)² + a·B1(N_0) | charge ≥ exact; A0(N_{r+1}) = A0(N_0)(N_{r+1}/N_0)² |
| roll-in fold | a·max(A0(N_{r+1}), B1(N_0)) | a·A0(N_0)(N_{r+1}/N_0)² + a·B1(N_0) | charge ≥ exact |
| query | α0^s | (√ρ(1 + 1/2m))^s | equal |

So every figure Track 8 reports is at least as large as the exact error of Theorem 2, rather than a heuristic.

**Comparison with [ADK] Thm 2.**
- [ADK]'s ε_3 (the batching round, with independent γ_i, δ_j and a mask R with coefficient 1) is
  (m + ½)^7·|D|² / (3ρ^{3/2}·|G|) = A0 alone. That is the case M = 1 of Thm 7.4, where max(A0, B) = A0 at these
  sizes.
- [ADK]'s ε_i for the folds is (t_{i−4} − 1)·ε_3·Π_j t_j^{−2} + (2m + 1)(|D| + 1)/(√ρ·|G|). This keeps the B term
  without the factor l, as in [BCIKS20]'s proof of Lemma 8.2. Thm 7.2 as stated multiplies the B term by l as well.
- Track 5 charges a·B1. That is ≥ l·B1 for l = a − 1 and = l·B1 for l = a, so Track 5's charge is safe under either
  reading.

## 5. Reduction to [ADK] Thm 2 for the full protocol

### 5.1 Theorem-by-theorem correspondence

| [ADK] Thm 2 (CiC 3(2), DOI 10.62056/absgbn-3y; proof App. B.1) | ingredient in [ADK] | here / Track 8 | changed by powers batching? |
|---|---|---|---|
| ε_1 = L/\|G\| (ALI, independent λ_i) | Schwartz–Zippel per list element | Track 8 Lemma 1: Σ_i L_i·\|C_i\|/q (powers of α, §5.3) | ALI uses powers of α too; §5.3 |
| ε_2 (DEEP, L² × degree / (\|G\| − \|D ∪ H\|)) | [Sta21] Thm 5 | Track 8 Lemma 2 (shared ζ, per table) | no: the round precedes α′ |
| ε_3 (batching) = A0 | [BCIKS20] Thm 7.4, Lemma 8.2 eq. 8.8 | **Lemma 1 + Theorem 2 (T0)**: [BCIKS20] Thm 7.2, l = t_h − 1, per height | **yes: this is the only change** |
| ε_i, 4 ≤ i ≤ k − 1 (folds) | [BCIKS20] Thm 7.2 inside Lemma 8.2 | Theorem 2 (T1); (T2) for roll-ins, which [ADK] does not have | plain folds: no; roll-ins: new, proved in (T2) |
| ε_k = (√ρ(1 + 1/2m))^{n_FRI} (query) | [BCIKS20] Thm 8.3, Claim 8.5 | Theorem 2 (T3), Claim A | no |
| RBR ⇒ state restoration (Thm 1 = [CY24] Thm 31.3.1); RBR knowledge per [BGKTTZ] §2.5 | | Track 5 §2 ([BGKTTZ] Cor. 5, grinding rule) | no |

### 5.2 The interface, and why it does not depend on the batching method

[ADK]'s round-by-round argument has the following shape. Before the batching challenge, its state is doomed exactly
when the DEEP quotients (trace at z and g·z, quotient segments, the mask) have no correlated agreement above α with the
code. After the challenge, the state is "f^(0) is α-far", as in [BCIKS20] Lemma 8.2's event E^(0).
- Every round before the batching challenge (ALI, DEEP) is analysed in [ADK]/[Sta21] without reference to the batching
  coefficients, because they have not been drawn yet.
- Every round after it is a function of f^(0) and later messages only. Theorem 2 re-proves this part for Plonky3's
  shape.
- So the one place where the distribution of the batching coefficients enters is the transition across the batching
  challenge. Lemma 1 bounds that transition for powers.

For batch-stark with several tables we need one thing from the front end: **(I) if the statement is false and the
transcript up to the opened values is doomed for DEEP-ALI, then pre is doomed**, i.e. some height's tuple
(u_{h,0}, …, u_{h,t_h−1}) has correlated agreement ≤ α0.
- In [ADK]'s single-table proof this is how the DEEP state is defined (via [Sta21] Thm 5).
- For several tables we argue it table by table. A table's main, preprocessed, permutation and quotient columns and
  its random codewords all live at that table's LDE height.
- If every height's tuple had correlated agreement > α0, then every table's tuple would too, by (F2). [ADK]'s DEEP
  step then makes every table's claimed openings consistent with list codewords, so the per-table DEEP state is not
  doomed.
- **Status of (I): argued, inherited, not proved here.** It rests on [ADK] App. B.1 and on [Sta21] Thm 5, which we
  could not open in this session, and on Track 8 Lemmas 1, 2 and 5. Powers batching cannot affect (I), because (I)
  is about objects fixed before α′.

The parameter condition is that [ADK] Thm 2 needs 3 ≤ m < k/2 and η = √ρ(1 + 1/2m) − √ρ⁺ > 0, with
ρ⁺ = (k + 2)/|D|. At M1 (k = 2^11, |D| = 2^20, m = 5), η ≈ 0.0044 > 0. Lemma 1 and Theorem 2 need only m ≥ 3.

### 5.3 ALI with powers of α (Track 5 §2.1 item 4)

The Track 8 table also lists this round as dependent on the adaptation. It is elementary.
- Fix one element of the (≤ L) list of codeword tuples for the committed trace. Suppose some constraint c_i fails to
  vanish on H for that element.
- Then c(α) := Σ_i α^i·c_i, viewed at any point of H where some c_i ≠ 0, is a nonzero polynomial in α of degree
  ≤ |C| − 1.
- So it vanishes at that point for at most |C| − 1 values of α. A union bound over the list gives L·(|C| − 1)/q,
  and Track 8 charges L·|C|/q.
- How this enters [ADK]'s state function (ε_1 is the same kind of event with independent λ_i) is inherited, as in
  §5.2. Its margin is 46 bits (174.94).

## 6. Parameters and the resulting per-round errors

**Regime.** Johnson-bound list decoding: proximity 1 − α0 = 0.95139 against the Johnson radius 0.95581, with m = 5.
Unique decoding is not usable at Track 8's shape:
- at ρ = 2^−9 and Q = 24, the UD query round ((1 + ρ)/2)^24 gives 47.93 bits even with query PoW 24;
- the UD batching round alone ((t − 1)·N/q, [BCIKS20] Thm 6.1) would be 165.46 bits.
Track 5 §6 lists the UD alternative (about 2–3× the bytes).

| quantity | M1 / Z128 | M2 / Z128-g (cpow 3, lpow 8) |
|---|---|---|
| field q | p³, log2 q = 192.00 | same |
| rate ρ, m, α0 | 2^−9, 5, 0.048614 | same |
| LDE heights N_h | 2^20 | 2^20 (T_hash), 2^17 (T_ctl) |
| batched polynomials t_h (as built) | 94 | 127 at 2^20, 85 at 2^17 |
| curve degree t_h − 1 | 93 | 126, 84 |
| folds | one arity-8 fold, 2^20 → 2^17 (plain) | [8, 8]: 2^20 → 2^17 (roll-in of T_ctl, curve degree 8) → 2^14 |
| PoW: batch / commit / query | 20 / 2 / 24 | 20 / 3 / 24 |

**Per-round results (bits, with PoW; raw = before PoW)** from `batching8.py`. The ALI, DEEP and LogUp columns of
Track 8 are unaffected and are not repeated.

| round | M1 | M2 |
|---|--:|--:|
| batching, Track 8 charge (Σ_h, N_max, A0 + B1) | **136.33** (raw 116.33) | **135.15** (raw 115.15) |
| batching, Theorem 2 exact (max_h, own N_h) | 136.33 (raw 116.33) | 135.89 (raw 115.89; per height 115.89 at 2^20, 122.48 at 2^17) |
| batching with independent coefficients, for comparison | 142.87 | 141.87 (Track 8 accounting) |
| cost of powers (log2(t − 1) under Track 8's charge) | 6.54 | 6.71 |
| fold1, Track 8 charge | **128.06** (plain, l = 7) | **128.87** (roll-in, l = 8) |
| fold1, Theorem 2 exact | 128.06 | 128.87 |
| query (√ρ(1 + 1/2m))^24 + PoW 24 | 128.70 | **128.70** |
| λ_IOP (min over all Track 8 rounds) | **128.06** (fold1) | **128.70** (query) |

- **How Track 8's numbers follow.** λ_IOP = min over rounds (SOUNDNESS-T8 §5 table). The batching rows above are
  Track 8's exactly, and every other row is unchanged. With [BGKTTZ] Cor. 5, λ = min(λ_IOP, 128) = 128 (strict
  127.21) for both statements, as Track 8 states.
- **What this document changes in that chain.**
  - The batching rows (margins 8.33 and 7.15 over 128) and M2's roll-in fold (margin 0.87) now rest on Lemma 1 and
    Theorem 2, which are written out here, rather than on a sketch.
  - M1's binding round (fold1, a plain fold) never depended on the powers factor.
- **M2's tightest round.** The roll-in charge a·ε_J is exactly what Theorem 2 (T2) gives, so there is no hidden
  slack: 0.87 bits stays 0.87 bits. If (T2) were wrong, the fix is commit PoW +1 (no byte cost), as SOUNDNESS-T8 §6
  says.
- **Sensitivity, not used:** [BCHKS25] (ECCC TR25-169 / ePrint 2025/2055, preprint, Nov 2025).
  - Thm 4.2 bounds the curve case by M·[(2(m + ½)^5 + 3(m + ½)γρ)/(3ρ^{3/2})·n + (m + ½)/√ρ] (linear in n).
  - Applied at the same proximity γ = 1 − α0, with ρ = (k − 1)/n as that paper defines it, it gives a batching round
    of **155.58 (M1) and 155.15 (M2)**, raw 135.58 / 135.15.
  - That uses m = ⌈√ρ/η⌉ = 10, as printed in Thm 4.2. Thm 1.5's m = ⌈√ρ/(2η)⌉ = 5 would give 160.25 / 159.81.
    The two statements in the paper differ here; we take the larger, printed one.
  - The weighted form (Cor. 4.4) would put the folds at 144.31 (M1 fold1) and 145.11 (M2 fold1). M1 would then bind
    at the query round (128.70).
  - We do not use any of this. Section 4 of that paper gives its curve and weighted proofs as sketches ("In a
    nutshell …"), and the paper is a preprint.

## 7. What is not proven, and what was not checked

1. **The DEEP-ALI front end (interface (I), §5.2) and knowledge extraction are inherited.** They come from [ADK] Thm 2
   (App. B.1), whose proof defers to [Sta21] Thm 5 (the ethSTARK documentation, ePrint 2021/582) and to [BGKTTZ] §2.5.
   - We could not fetch [Sta21] (ePrint returned HTTP 403), so we did not re-read it.
   - Track 8 Lemmas 1, 2 and 5 (multi-table ALI, shared ζ, LogUp) remain arguments, as SOUNDNESS-T8 labels them.
2. **The [BCIKS20] theorems are used as stated.** We read Thm 7.2, Thm 7.4, Lemma 8.2 with its proof and Claim 8.5 in
   ECCC TR20-083 rev. 3. We did not re-verify Thm 7.2's own proof (given in that paper as changes to Thms 6.1/6.2), and
   we did not map the numbering to the J. ACM version.
3. **Prior statements of powers batching for FRI, not read here.**
   - [Hab22] (Haböck, *A summary on the FRI low degree test*, ePrint 2022/1216, rev. 2023-03-31): its revision note
     says it switched its example parameters to "algebraic batching". We could not fetch it (HTTP 403).
   - The ethSTARK documentation [Sta21] uses powers of one challenge in its protocol (this is from memory and was not
     checked).
   - Either may already contain Theorem 2's batching step. If so, it should be cited in place of, or next to, §4.
4. **Theorem 2 is an IOP statement.** These parts are inherited from Track 5 §2 and are not proved here:
   - Merkle binding and the Fiat–Shamir compilation ([BGKTTZ] Cor. 5, digest term 4h);
   - the rule that a g-bit PoW adds g bits to exactly the round it precedes;
   - query-index uniformity (Track 5 §5, condition 4);
   - the challenge rejection when a sample is ≥ p (conditioned on acceptance, the challenge is uniform).
5. **The match between the protocol model (§2) and the code** rests on reading Plonky3 0d80373 for this document (the
   line references in §2) and on Track 8's tests that the scripts match Plonky3 (SOUNDNESS-T8 §2, part B).
   - The as-built t_h are the ones params8.py reads from the committed vectors (asbuilt8-output.txt); we did not
     recount them.
   - Two shape facts carry the argument: a contiguous α′ ladder per height starting at α′^0, and β^a roll-ins. If a
     future Plonky3 left gaps in the ladder, the curve degree would be the largest exponent used, not t_h − 1.
6. **External review: none.** This proof has been checked only by its author. Under the project's rules the Track 5/8
   figures stay labelled as resting on an internal argument until someone outside the project reads §3–§5.

## 8. References

- **[BCIKS20]** Ben-Sasson, Carmon, Ishai, Kopparty, Saraf. *Proximity Gaps for Reed–Solomon Codes.* ECCC TR20-083,
  revision 3 (2021-07-03); FOCS 2020; J. ACM 70(5), 2023. Used: Thm 7.2, Thm 7.4, §8.2 (Lemma 8.2, Thm 8.3,
  Claim 8.5, proof §8.2.1), Thm 6.1.
- **[BCHKS25]** Ben-Sasson, Carmon, Haböck, Kopparty, Saraf. *On Proximity Gaps for Reed–Solomon Codes.* ECCC TR25-169
  (2025-11-07) = ePrint 2025/2055. Used for sensitivity only: Thm 1.5, Thm 4.2, Cor. 4.4, and the remark in §4.1.
- **[ADK]** Atapoor, Delpech de Saint Guilhem, Kindi. *STARK-Based Signatures from the RPO Permutation.* IACR CiC 3(2),
  DOI 10.62056/absgbn-3y (ePrint 2024/1553). Used: Protocol 1 and Protocol 2, Thm 2 and its proof (App. B.1), Thm 3
  (App. B.2), Thm 1.
- **[BGKTTZ]** Block, Garreta, Katz, Thaler, Tiwari, Zając. *Fiat–Shamir Security of FRI and Related SNARKs.*
  ASIACRYPT 2023 (ePrint 2023/1071). Cor. 5, via Track 5. Not re-read here.
- **[Sta21]** StarkWare. *ethSTARK Documentation* (ePrint 2021/582). Cited by [ADK]; not read here.
- **[Hab22]** Haböck. *A summary on the FRI low degree test* (ePrint 2022/1216). Not read here.
- **Plonky3** 0d80373: `fri/src/verifier.rs` (`open_input` ladder, roll-in, final checks), `fri/src/two_adic_pcs.rs`
  (`fold_row`), `fri/src/hiding_pcs.rs` (random columns).
- **Project:** Track 5 SOUNDNESS §2/§2.1 (zk-verifier-bench 6302a2c); SOUNDNESS-T8 §3–§6 and §13 (groth16_cashscript
  31f06b2); params5.py, params8.py, asbuilt8-output.txt (zk-verifier-bench `main` 0a83c22).

## 9. Reproduce

```
cd research/pq-stark/design-t8 && python3 batching8.py     # standard library; imports ../soundness/params5.py; < 1 s
```

It asserts that its A0/B1 equal params5.py's, and it writes `batching8-output.json`. The Track 8 figures it reproduces
(136.33, 135.15, 142.87, 141.87, 128.06, 128.87, 128.70) are the ones in asbuilt8-output.txt.
