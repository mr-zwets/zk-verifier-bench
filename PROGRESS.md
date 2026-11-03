# wip/t10-gates: PROGRESS (wip branch only, not for main)

## G0: security recomputation (done, light compute)

Code: `research/pq-stark/design-t10/params10.py`. Outputs: `params10-output.{txt,json}`.

To regenerate:

```
python3 params10.py --zisk-all <soundcalc>/soundcalc/zkvms/zisk/zisk.toml \
  --toml <soundcalc>/soundcalc/zkvms/zisk/zisk.toml <soundcalc>/soundcalc/zkvms/risc0/risc0.toml
```

- The soundcalc pin is github.com/ethereum/soundcalc @ b325e30dc5dda80b21c7c0465728aca54f29087b (2026-10-30). That was upstream HEAD on 2026-11-03.
- The TOML files are read as data with tomllib. soundcalc's code was **not executed**. Its formulas were re-implemented and checked against its committed reports.

### Gate G0: **PARTIAL**

Every ZisK circuit reaches 128 bits JBR under soundcalc's BCHKS25-based model. Under Track 8's own BCIKS20 accounting none of them does. Details follow.

- **soundcalc model, re-implemented ("SC").** The minimum over all 60 ZisK v1.4.0-alpha circuits is **128.03**, at Final, bound by the query round.
  - Margins are hairline: Final 128.03, Final_Compressed 128.05, Main 128.07, Recursive2 128.47.
  - For Final, Recursive2 and Final_Compressed, every floored cell equals soundcalc's report, in both UDR and JBR.
  - If we choose the multiplicity m ourselves instead of using ZisK's pinned gap, Final moves only to 128.04.
- **Track 8's own accounting ("T8").** This is ADK Thm 2 with BCIKS20 Thm 7.2/7.4, whose error is quadratic in |D| with (m+½)^7.
  - Final 118.26, Recursive2 118.06; the minimum over the 59 FRI circuits is 113.52 (Keccakf).
  - No m in 3..400 reaches 128. At m large enough for the query round, the batching round sits at about 96.6 and fold1 at about 110.8. ZisK has no batching or commit grinding.
- **UDR, the fully published bounds.** Final 73.5, Recursive2 95.9, Final_Compressed 45.0.

So "at least 128 bits provable (JBR)" holds only when we accept two things:
1. BCHKS25 Thm 4.2 (ePrint 2025/2055, Nov 2025). We could not read its text: the ePrint PDF returned 403. The formula is taken from soundcalc's code and math companion, including the factor-2 fix in m that soundcalc says the authors confirmed.
2. The powers step (B−1) × line bound, composed into a round-by-round analysis. It is unpublished, in the same class as Track 8's adaptation (see below).

The gap between the two accountings is entirely in the proximity-gap theorem. For ZisK Final's batching round at m = 38:

| bound | line error |
|---|---|
| BCIKS20 A0 + B1 | 2^-106.72 |
| BCHKS25 Thm 4.2 | 2^-138.25 |
| difference | 31.5 bits (one factor of \|D\| = 22 bits, plus about 9.5 bits from m^7 versus m^5) |

The HYB variant keeps T8's accounting and swaps in BCHKS25. It gives Final 128.04 and Recursive2 128.73, essentially the same as SC. The other accounting differences (L² for DEEP, ADK's list size) are not binding.

### Track 8 reproduction (acceptance)

- params10 equals params8 exactly (0.00 bit difference per round) on M1/Z128, M1/Z128-s, M2/Z128-g cpow 3 and M1 batch PoW 12.
- **M1 Z128 λ_IOP = 128.06: PASS.**
- Under HYB (BCHKS25), M1 Z128 would be 131.29, bound by the query round.
- Field sweep, with the M1 Z128 shape and PoW unchanged:

| field | λ_IOP |
|---|---|
| Gl³ | 128.06 |
| BabyBear⁴ | 64.25 |
| KoalaBear⁴ | 64.58 |
| BabyBear⁵ | 95.16 |
| KoalaBear⁵ | 95.57 |

- DESIGN-T10 Stage 0 checks:
  - BabyBear⁴ bridge shape: 71.12 (< 100) PASS.
  - BabyBear⁵ lb 6, Q 28: 101.77 (≥ 100) PASS.

### RISC Zero

- **soundcalc's rv32im segment config:** SC JBR **48.22** and UDR **33.90**, both bound by the query round, matching the report's 48 / 33. T8 JB gives 45.63.
- **Succinct (recursion) circuit.** soundcalc does not model it, and its shape here is [UNV] (2^18 rows, 167 batched columns, from Design A). It uses the same QUERIES = 50, INV_RATE 4 and BabyBear⁴. Results: SC JBR 48.22, UDR 33.90, T8 JB 47.47. The binding query term does not depend on the shape.
- **The soundcalc risc0 report is stale.** Its batching and commit cells differ from the current formulas by a constant: JBR 63/71 against our 68.29/76.52; UDR 92/100 against our 93.90/102.14.
  - Explained exactly: recomputing with the old m = ⌈√ρ/η⌉ (no factor 2) and the BCIKS20 ε_U = n/|F| matches every report cell.
  - Also, risc0.toml @ b325e30 has no `num_constraints`, which zkvm.py requires, so that TOML would not load at this commit [inferred from code, not run].
  - Correction to the T10 security panel: under current formulas RISC Zero's JBR batching round is about 68, not 63. The 48-bit total does not change.

### Powers batching: soundcalc versus Track 8's adaptation, statement by statement

| Track 8 statement (Track 5 SOUNDNESS.md §2.1) | soundcalc @ b325e30 | Covered by a published result? |
|---|---|---|
| S1. Only the batching round's bad event (BCIKS Lemma 8.2, E^(0)) depends on how the coefficients are drawn. Folds and query see only f0. | Same structure, implicitly: batching is one round, and folds and query do not depend on the batching type (pcs.py, fri.py). | No. It is a modelling convention in both. |
| S2. Powers form a curve of degree t−1, and correlated agreement holds with the error × (t−1). Cites BCIKS20 **Thm 7.2**, a published curve theorem (JB, explicit m), giving (t−1)(A0 + B1). | ε = (B−1) · ε_line, where ε_line is BCHKS25 **Thm 4.2**, cited for the *line* error only. proxgaps_regime.py points to BCIKS20 for the curve case. | Track 8's S2 cites a published curve theorem. soundcalc's S2 applies the curve factor to a BCHKS25 line bound; a BCHKS25 curve statement is **[UNV]** (paper unread, and soundcalc cites none). |
| S3. Substitute S2 into the ADK Thm 2 round-by-round proof; the other rounds are unchanged. | No composition proof. The README states IOP round-by-round soundness, with the minimum "roughly" equal to the BCS security (cites ePrint 2025/1993). | No. Unpublished in both. |
| S4. ALI with powers of α: L·#constraints/q (Schwartz–Zippel per list element). | The same form, L·C/\|F\| (Ha22 Thm 8). deep_ali.py has a TODO on linear versus powers ALI. | Elementary; the same in both. |
| Folds: a curve of degree a−1 per round (Track 8 also charges a for roll-in rounds). | get_error_powers(k_i) per fold round; no roll-in, since every table has one height. | The same convention. |
| UDR powers | Code uses (B−1)·ε_lin. The math companion (prelim.tex) says ·B. | Documentation and code disagree inside soundcalc; the difference is at most log2(B/(B−1)) bits. |

**Answer: no.** No published result covers Track 8's adaptation as a whole.
- What changed is that EF's soundcalc now uses the **same (t−1)-factor convention** for every powers-batched system it scores, ZisK's 128 included. Track 8 can say its batching rule is "the same convention as EF soundcalc", but it must not call the rule published.
- The ZisK 128 figure carries the same unpublished step as Track 8. It also rests on a curve extension of BCHKS25 that we could not find stated anywhere. On that point Track 8's step S2 is the better anchored of the two, because BCIKS20 Thm 7.2 does state a curve theorem.

### Consequences for T10 (input to G1/G2, not acted on here)

- An end-to-end figure built on ZisK can only be stated as **"128 bits JBR under soundcalc's BCHKS25-based model (unpublished powers step, as in Track 8)"**. It is **about 113–118 bits under Track 8's current BCIKS20 accounting**, and **45–112 bits UDR** (Final_Compressed 45, Final 73.5).
  - The two accountings must not be mixed in one claim.
  - The Track 8 outer layer would be reported at 131.29 under the same BCHKS25 model, or 128.06 under BCIKS20.
- The ZisK Final margin is 0.03 bits (query: 51 × 1.98 + 27). Any small change in the gap convention flips it below 128.
- To read BCHKS25 Thm 4.1/4.2 (and any curve corollary), the maintainer needs to fetch https://eprint.iacr.org/2025/2055.pdf. It is blocked from this session (HTTP 403, and a retry was refused).

## G1: ZisK final-proof extraction (done, light compute)

Note: `research/pq-stark/design-t10/ZISK-FINAL.md`. Scripts and outputs: `research/pq-stark/design-t10/g1/`.

### Gate G1: **PASS (narrow)**

- **Pins.** ZisK v1.4.0-alpha `64a1f16` and pil2-proofman v1.4.0-alpha `27b2fc2`. The crates.io `proofman-verifier` and `proofman-fields` sources are identical to the tag.
- **Real proofs without a GPU.** Six published fixtures (`fib_mod`, three hash families, leaf and compressed) verify on CPU with the stock no_std `zisk-verifier`. Plain rejection checks: 706/706 rejected.
- **Independent check.** A Python replay (our own Poseidon2, transcript and Merkle code) matches the Poseidon2 leaf fixture: all 432 Merkle paths, all 8 roots (the constant root equals the release vk), and the 22-bit grinding.
- **Narrow, part 1.** One program only, and no Poseidon2 proving key is published (HTTP 404). Only BLAKE3 (6.5 GB) and Poseidon1 (4.9 GB) keys exist.
- **Narrow, part 2.** Local CPU proving needs sudo-level setup: system packages and memlock. Its RAM use within 24 GB is unverified.

### Correction for G0 and the T10 panel

- soundcalc's ZisK "Final" is the **BLAKE3** setup (51 queries / 27-bit grinding / 1,122 evals / 2^18).
- The **Poseidon2** Final is 2^16 rows, 54 queries, 22-bit grinding, 130 evals, 5 opening points, P2-16 arity-4 trees, 369,368 B.
- Its soundness, from our toml:
  - soundcalc and params10 SC: **128.97 JBR** (compressed 128.63);
  - Track 8 accounting: **122.57** (query-bound);
  - UDR: 71.28 / 57.19.

### Other facts the bridge needs

- The extension is Gl³ with u³ = u + 1, the same as Track 8.
- Poseidon2's round constants match Plonky3's. The internal diagonal and the M4 matrix do **not**, so Track 8's AIR needs pil2's linear layers.
- Final is not ZK: plain LDE, no blinding.
- The only argument in Final is the connection grand product; there is no LogUp.
- The public values are flag + program_vk(4) + 64 u32 outputs. program_vk is a covenant constant. The outputs can carry a SHA-256 that OP_SHA256 rebuilds. The bridge must re-impose the host-side checks: flag = 1, outputs < 2^32.
- Verifying one Final costs 3,876 P2-16 permutations.

## G2: shape twin (done, heavy: prover + BCHN)

Code: groth16_cashscript wip/t10-gates `research/pq-wrap/` (copies of Track 8's prover/verifier/onchain; commits 8014fd2, ffa3b32, daad7db). Results: `research/pq-wrap/onchain/results/g2/`. Here: `research/pq-stark/design-t10/g2/params-g2.py`, `research/node-check/{export-g2.mjs,run-g2.sh,raw/g2n2-*}`.

### Gate G2: **FAIL under today's rules** (b2 meets the numbers only under raised limits that no node implements)

- **Twin.** Two tables: M1's Poseidon2-Gl AIR lengthened to 2^18 rows (17 cols, deg 4) and a dummy Gl^3 mul-add table at 2^16 rows (12 cols, deg 2). Gl^3, SHA-256 trees, ZK on.
- **Parameters.** lb 5, final poly 2^8, Q 43, PoW query 24 / batch 20 / commit 11. params10's T8 accounting gives **128.15** bits (JB, query-bound, m 9); HYB gives 130.22.
  - lb 5 is forced by RAM. lb 6 (Q 36) would be about 39 GB.
  - lb 8 (Q 28, about 172 KB proof) would need roughly 85 to 155 GB.
- **Prover.** Proof 224,142 to 225,262 B at cap 0 (228,846 to 231,534 B at cap 5). Proving time 15.1 to 22.0 s at RAYON_NUM_THREADS=4. **Peak RSS 19.5 GB** (VmHWM 19,521,448 kB, sampled from /proc), which is under 24 GB with about 4.5 GB to spare.
- **a' (today's rules), cap 0.** Cap 5 found no plan: one query per input needs about 10.6 KB of unlocking.
  - Size: **7 tx, 78 inputs, 639,351 / 637,951 B** (91.6 + 5 × 89.8 + 98.5 KB).
  - Op-cost: 3 CODE inputs + DEFINE 53,001 B; max **92.72%** of an input's budget (BCHN-adjusted); total op-cost 339.6 M.
  - libauth: 286/286 accept/reject cases as expected (0 unexpected).
  - Stock BCHN 29.1.0 (run g2n2):
    - block validation 43/43 as expected (14 valid accepted; 27 rejects and 2 b2 txs rejected);
    - testmempoolaccept with POLICY=1: 14/14 allowed;
    - unconfirmed 7-tx chain: all in mempool, mined in one block.
  - Verify time: about 59 ms per tx, **about 414 ms per proof**, 0.264 to 0.278 ns per op-cost unit.
  - → Fails the ≤ 300 KB and ≤ 4 tx limits (2.1× and 1.75× over); passes the ≤ 95% input budget and RAM limits.
- **b2.** QA 19 of 43.
  - Size: **1 tx, 2 inputs, 260,355 / 260,784 B**; unlocking 134,965 + 125,256 B.
  - Op-cost: 47.6% / 51.7% of each input's budget under r150 (spec accounting: 44.3 / 47.9%).
  - libauth r150/r150t (per-input 150,000 B, tx 300,000 B): valid accepted, 172/172 sweep cases as expected.
  - Today: rejected by libauth (unlocking > 10,000 B; tx > 100,000 B) and by stock BCHN (blk-bad-inputs), as expected.
  - → Meets ≤ 300 KB / ≤ 4 tx / ≤ 95% only under raised limits. Not standard today.
- **Floor estimate (modelled, not built).** Even at lb 8, a' needs about 28 × 9.5 KB of QRY inputs plus 4 or 5 tx of HEAD/CODE/FIN overhead (about 37 KB each), roughly 430 to 450 KB. So a' cannot reach 300 KB with this verifier at any blowup.

### Fixes during G2

- test-a2: the cap-5 offsets (ROOTS 578, FROOTS 992) fell outside the cap-0 items, so those flips were no-ops and the cases accepted (test artefact). The offsets are now cap-independent and throw if out of range.
- test-a2: the "tx1 outputs changed" case targets the final tx. A middle tx's plain output is not bound by the covenant, as with Track 8 tx0's extra outputs; this is by design, not a hole, since the statement's CTX is the final tx's.
- test-b2w: the shebang was not on the first line.
- layouta (daad7db): middle txs of T > 2 chains were underfunded (tx0's NFT outputs carried 5,000 sat; the middle txs assumed 200,000). BCHN policy run g2n1 (kept in raw/) rejected tx1 to tx5 with bad-txns-in-belowout. Only values changed; sizes and op-cost are identical. Rerun as g2n2: all allowed.

### Caveats

- The twin matches the target's size and shape (rows, columns, field, hash), not ZisK's verifier logic.
- The bridge needs Poseidon2-16 with pil2's linear layers (G1), 3,876 perms, 130-eval DEEP. Whether 2^18 rows hold that is not checked.
- The 128 bits rests on Track 8's unpublished powers-batching adaptation (G0).
- The RAM figure comes from 0.2 s sampling of VmHWM, which is a high-water mark, so only the last < 0.2 s before exit could be missed.
- g2n2's env.txt records groth16_cashscript ffa3b32 plus the uncommitted layouta funding fix, later committed as daad7db.
