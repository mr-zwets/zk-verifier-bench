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
