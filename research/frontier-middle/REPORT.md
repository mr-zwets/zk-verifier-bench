# Track 2: the empty middle of the Groth16 frontier

Date: 2026-10-28. Status: **registered entries** (updated 2026-10-28). The four designs are now leaderboard entries as five ids (BN T2 is listed in two builds, because they are separate bytes vs op-cost Pareto points): `bch-groth16-sound-si-gls-dproj`, `bch-groth16-bls12381-sound-si-gls-dproj` (both `bch-spec`), `bch-groth16-singleton-rolled-residue`, `bch-groth16-singleton-rolled-residue-mulc` and `bch-groth16-bls12381-singleton-minop-rolled` (`bch-2026`). They have reviewStatus `reviewed` on two internal reviews per curve (soundness and measurement) plus a fix round for the minor findings; none has had an independent external review. Their sources are in groth16_cashscript under `research/frontier-middle/`.

## 1. Question and framing

The bytes-vs-op-cost Pareto frontier of the reviewed Groth16 verifiers had nothing between the singletons (about 6–8 KB, 0.8–1.0 G op-cost) and the SI-GLS / sound-native designs (22–34 KB, 21–26M op-cost).

| curve | entry | bytes | op-cost (libauth) | inputs |
|---|---|--:|--:|--:|
| BN254 | singleton-opcode-optimized | 6,237 | 800.2M | 1 |
| BN254 | singleton | 8,206 | 771.3M | 1 |
| BN254 | singleton-minop | 58,073 | 64.8M | 1 |
| BN254 | sound-si-gls-single (bch-spec) | 21,915 | 23.3M | 1 |
| BN254 | bn254-sound-native | 27,624 | 20.6M | 3 |
| BLS12-381 | singleton-opcode-optimized | 5,999 | 1,003.5M | 1 |
| BLS12-381 | singleton | 7,510 | 994.6M | 1 |
| BLS12-381 | singleton-minop | 58,841 | 145.6M | 1 |
| BLS12-381 | sound-si-gls-single (bch-spec) | 26,484 | 26.1M | 1 |
| BLS12-381 | sound-native | 34,229 | 24.0M | 4 |

**Hypothetical looser budget.** The budget is k times the bch-2026 density, (41 + len)·800·k per input. A design then needs at least

> E_k = max(bytes, op / (800·k) − 41·inputs)

bytes, which we call its *effective size*. Size caps are ignored here: T1 designs and today's SI-GLS single need bch-spec script sizes.

**Policy zone.** Track 1 ([../opcost-timing/REPORT.md](../opcost-timing/REPORT.md)) found that bignum code costs about 1/5–1/10 of the CPU per op-cost unit of the worst signature case. So k = 5–10 is the relevant zone. This is an order-of-magnitude estimate from one machine.

**Design knob.** Hint vs compute, with no new cryptography. Only techniques that are already reviewed are combined:
- looped field code (singletons);
- a final-exponentiation residue witness (minop);
- a fused endpoint G2 check (minop, SI-GLS);
- Miller states checked by one random evaluation (SI-GLS);
- baked vs on-chain fixed-point walks.

## 2. Component profiles (where bytes and op-cost go)

Op-cost was attributed per instruction on unmodified libauth 3.1.0-next.8. Traced totals equal libauth's reported op-cost to the unit. Scripts and outputs are in [profile/](profile/) (BN: `trace.mjs`; BLS: `profiler.mjs`).

### BN254 (committed proof)

| component | singleton (8.2 KB / 771M) | minop (58.1 KB / 64.8M) | SI-GLS single (21.9 KB / 23.3M) |
|---|--:|--:|--:|
| G2 subgroup check | 49.1M | 0.25M (fused endpoint) | in terminal |
| vk_x | 35.5M | 1.2M (GLV, affine slopes) | 1.7M (GT-GLS fold) |
| Fp12 squarings | 223.7M (4 × 65 at 0.86M) | 11.5M (65 at 176k) | folded into ±z steps |
| line evaluation | 195.5M | 36.6M (264 at 139k) | in steps |
| G2 walk arithmetic | 103.8M | 8.2M | 9.3M (B dbl) + 4.2M (B add) |
| δ handling | on-chain (4th loop) | 23.4 KB baked lines | 4.3M + 5.7 KB baked slopes |
| final exponentiation | 151.6M | 0.78M (residue) | 0.71M (residue terminal) |
| random-evaluation machinery | – | – | 2.5M, 10.3 KB hints |

### BLS12-381 (bench vector)

| component | singleton (7.5 KB / 995M) | minop (58.8 KB / 145.6M) | SI-GLS single (26.5 KB / 26.1M) |
|---|--:|--:|--:|
| Fp12 squarings | 351.0M (256 at 1.37M) | 27.1M (64 at 423k) | folded into ±z steps |
| line evaluation | 258.5M (276 at 0.94M) | 92.2M (207 at 445k) | in steps |
| G2 doublings/additions | 122.4M | 19.5M | 15.3M (B) |
| δ handling | on-chain | 45.5 KB baked lines | 5.6M + 6.6 KB baked slopes |
| final exponentiation | 235.2M | 0.37M + 2.5M folds (residue) | 0.17M terminal |
| vk_x | 10.9M (73.9M dense) | 3.6M (29.1M dense) | 1.7M |

### What the profiles say
- **Singletons pay for redundancy, not the method.** Of their op-cost:
  - 4 independent Miller loops: 3/4 of the squarings (BN ~168M, BLS 263M) and the constant e(α,β) loop (BN 133M, BLS 186M) are wasted;
  - full final exponentiation 146–235M, where a residue check costs about 1–3M;
  - G2 subgroup walk 49M (BN), where the fused endpoint costs 0.25M;
  - eager mod reduction: MOD is 45–47% of op-cost.
- **Minop is dominated because of how it was generated.**
  - BN: 23.4 KB of baked lines, 16.8 KB of unrolled stack glue and 3.6 KB of end-of-script NIP/2DROP.
  - BLS: 45.5 KB of baked line calls, 40.6 KB of which are 828 inline coefficients.
  - Baking a line saves only the G2 point arithmetic. The Fp12 sparse product (139k BN / 445k BLS) is still paid.
- **SI-GLS bytes are mostly hints plus the δ pile.**
  - Hints are 10.3 KB (BN) and 13.1 KB (BLS).
  - The baked δ slope pile is 5.7 KB (BN) and 6.6 KB (BLS).
  - Its code is about 5.7 KB.

## 3. The model

[model.py](model.py) is a calibrated component model (outputs: [model-output.md](model-output.md), [model-output.json](model-output.json), notes: [MODEL-NOTES.md](MODEL-NOTES.md)). It reproduces the measured entries within 0.7% of bytes and 0.1% of op-cost, except BLS minop at +0.7% bytes.

It has two architecture families, and components combine only within a family:

| family | lineage | knobs |
|---|---|---|
| F12 | singleton / minop: real Fp12 accumulator | reduced or lazy tower; 4 loops or shared loop; final exp or residue; subgroup walk or fused endpoint; vk_x method; per walk projective, witnessed, slope pile or baked lines; rolled or unrolled; outlining |
| ZEV | SI-GLS: evaluations at ±z, one Schwartz–Zippel check | δ slope pile or projective δ; affine or projective B; chunk length m; single or native multi-input |

Findings:
1. **The middle is not a continuum.** Code is a fixed cost per family (about 5.7 KB ZEV, 8 KB F12). A hybrid of the two families pays for both code bases and loses.
2. **SI-GLS hints are already at their byte optimum** with 2-event chunks. On BN, states plus quotient are 13.8 / 10.0 / 12.5 / 22 KB for m = 1 / 2 / 3 / 4. The real byte lever is the δ pile.
3. **Minop loses to a rolled loop.** Rolling it and computing γ/δ on-chain gives about 8.2 KB at 117M (BN) or 189M (BLS).
4. **Residue plus fused endpoint is the main saving for singletons.** It gives about 5 KB / 323–412M, which only wins at k ≥ 50.

Targets chosen per curve:
- **T1:** SI-GLS with an on-chain projective δ walk instead of the slope pile.
- **T2:** a rolled, residue-terminal singleton with γ/δ computed on-chain.

## 4. What was built

All work is in worktrees under `work/frontier-middle/`. Sources are in groth16_cashscript; measurement glue and vectors are in this repo under [bn254/](bn254/) and [bls12381/](bls12381/). Every number below comes from the harness's own `benchmark()` on the loosened VM, with the designs not registered.

| curve | design | what it is | source branch / head |
|---|---|---|---|
| BN254 | **T1** sigls-dproj | reviewed SI-GLS; the 88-slope δ pile is replaced by a projective on-chain δ walk through shared doubling/addition kernels | [wip/frontier-middle-build-bn254](https://github.com/mr-zwets/groth16_cashscript/tree/wip/frontier-middle-build-bn254) @ [ed13eb4](https://github.com/mr-zwets/groth16_cashscript/commit/ed13eb4) (`research/frontier-middle/bn254/sigls-dproj`) |
| BN254 | T1 inline | same, with the δ doubling inlined (`DPROJ_SHARED=0`) | same |
| BN254 | **T2** rolled-residue | rolled exact-identity singleton in the SI-GLS assembler: Fp12 accumulator in the SI-GLS polynomial basis, 3 projective walks, residue root folded at the 21 additions, exact class check (no FS/SZ, no Miller hints), Jacobian Straus vk_x with witnessed zInv | same (`.../bn254/rolled-residue`) |
| BN254 | T2 mulc | squaring through the shared multiplier (byte-lean) | same |
| BLS12-381 | **T1** sigls-dproj | reviewed BLS SI-GLS, projective δ walk, E_A = 0 (no affine B slopes) | [wip/frontier-middle-build-bls12381](https://github.com/mr-zwets/groth16_cashscript/tree/wip/frontier-middle-build-bls12381) @ [4704d69](https://github.com/mr-zwets/groth16_cashscript/commit/4704d69) (`research/frontier-middle/bls12381/sigls-dproj`) |
| BLS12-381 | **T2** minop-rolled | reviewed BLS minop with one rolled NAF loop and on-chain γ/δ walks instead of 828 baked coefficients | same (`.../bls12381/minop-rolled`) |

Bench measurement commits: BN `4284482`, `58993fb`, `b010d20` (wip/frontier-middle-build-bn254); BLS `5bdebe9` (wip/frontier-middle-build-bls12381); model `4601c4a` (wip/frontier-middle-model). They are collected on main in `bdcb1e8`.

### Measured vs predicted

Op-cost is libauth consensus on the committed proof. "BCHN-adj." adds the executed OP_DEFINE body bytes. "Worst" is the bench worst-case proof vector.

| curve | design | bytes | op-cost | BCHN-adj. | worst (BCHN-adj.) | model | Δ bytes / op | k_min (bch-2026 base) |
|---|---|--:|--:|--:|--:|--:|--:|--:|
| BN254 | T1 | 16,571 | 33,317,244 | 33,318,543 | 33,334,850 | 16,453 / 31.9M | +0.7% / +4.4% | 2.56 (2.73 sweep) |
| BN254 | T1 inline | 17,203 | 32,021,353 | 32,022,832 | 32,039,485 | – | – | 2.36 |
| BN254 | T2 | 9,776 | 130,300,611 | 130,303,393 | 139,083,823 | 8,235 / 117.5M | +18.7% / +10.9% | 17.9 |
| BN254 | T2 mulc | 9,116 | 147,416,156 | 147,419,350 | 156,206,071 | – | – | 21.6 |
| BLS12-381 | T1 | 18,892 | 36,894,701 | 36,897,147 | 37,866,341 | 18,661 / 37.3M | +1.2% / −1.1% | 2.49 (2.50 sweep) |
| BLS12-381 | T2 | 8,712 (bare 8,674) | 192,759,049 | 192,761,316 | 218,291,714 | 8,189 / 189.3M | +5.9% bare / +1.8% | 27.9 (31.2 worst) |

All four main targets met their accept bars, and none hit a kill bar.
- **BN T2** was built differently from the model's design (SI-GLS assembler, non-GLV vk_x). vk_x alone costs 13.0M, where the model assumed 1.9M for GLV. Measured per-call units: squaring 231k, line multiplication 202k, doubling 136k, addition 176k.
- **BLS T2** bytes exceed the model because of the CashScript loop body.

Gates for every design:
- all valid proofs accepted (BN 4/4; BLS T1 6/6, BLS T2 5/5);
- all existing invalid vectors rejected (BN T1 15/15, BN T2 6/6, BLS T1 15/15 plus redteam 81/81, BLS T2 10/10);
- public-input gate: 0 of 9 forged inputs accepted;
- sweeps: BN T1 59/59, BN T2 18/18, BLS T1 87/87 at k = 2.

### Effective size per k (KB, BCHN-adjusted committed op)

"Today" is the best reviewed entry at that k. "Predicted" is the model's best design at that k, including designs that were not built. Worst-case-proof values are in parentheses where they differ.

**BN254**

| k | today | today design | predicted | measured best | measured design | vs today |
|--:|--:|---|--:|--:|---|--:|
| 1 | 27.6 | sound-native | 27.6 | 40.0 | T1 inline | none (+45%) |
| 2 | 21.9 | si-gls-single | 19.9 | 20.0 | T1 inline | −9% |
| 5 | 21.9 | si-gls-single | 16.5 | 16.6 | T1 | **−24%** |
| 10 | 21.9 | si-gls-single | 13.2–14.6 | 16.2 (16.6) | T2 (T1 on worst proof) | **−26% (−24%)** |
| 25 | 21.9 | si-gls-single | 7.1–8.2 | 9.1 | T2 mulc | −58% |
| 50 | 19.2 | singleton | 6.5 | 9.1 | T2 mulc | −53% |
| 100 | 9.6 | singleton | 4.5 | 9.1 | T2 mulc | −5% |

**BLS12-381**

| k | today | today design | predicted | measured best | measured design | vs today |
|--:|--:|---|--:|--:|---|--:|
| 1 | 32.6 | si-gls-single | 32.5 | 46.1 | T1 | none (+42%) |
| 2 | 26.5 | si-gls-single | 22.4 | 23.0 (23.6) | T1 | −13% |
| 5 | 26.5 | si-gls-single | 18.7 | 18.9 | T1 | **−29%** |
| 10 | 26.5 | si-gls-single | 18.7 | 18.9 | T1 | **−29%** |
| 25 | 26.5 | si-gls-single | 9.4 | 9.6 (10.9) | T2 | −64% (−59%) |
| 50 | 24.8 | singleton | 6.2 | 8.7 | T2 | −65% |
| 100 | 12.4 | singleton | 5.3 | 8.7 | T2 | −30% |

At k = 50 and 100 the model's best designs (a lazy or reduced residue singleton with outlining, about 4.5–6.5 KB) were not built, so the measured column lags the prediction there. [ek_table.py](ek_table.py) recomputes the measured and today columns.

**Headline:** in the k = 5–10 zone, hint-vs-compute recombination cuts the effective size by about a quarter on BN254 (21.9 → 16.6 KB) and by 29% on BLS12-381 (26.5 → 18.9 KB). In both cases T1 does it, by moving the baked δ pile on-chain for +8.6–10.8M op-cost. From k ≈ 20–25 upward, a rolled residue singleton of about 9 KB that fits the bch-2026 per-input size caps takes over (−58% to −64% at k = 25).

## 5. Review outcomes

Each curve had one soundness review and one measurement-reproduction review. All four verdicts were **pass**, and there were no blockers or majors. The minor findings below were taken up in a fix round before registration (groth16_cashscript 5f2a55a, f903eed, 37e43ae); none affects soundness.

| curve | review | verdict | minor items (fix round) |
|---|---|---|---|
| BN254 | soundness | pass | T2 per-kernel random-point differential test (tested against a noble mirror, no limb-bound proof; affects liveness only); assert FE(MAB) = e(α,β); one README sentence on T1 script/model δ-line equivalence; note that WQ changes in T1; T2 guard-coverage negative vectors |
| BN254 | measurement | pass | all numbers reproduced exactly. T1 sweep needs `VERIFIER_DIR`; k_min over the sweep is 2.73 / 1.63 (not 2.56 / 1.57); worst-witness T1 bytes 17.1 KB (−22% instead of −24%); T1 needs bch-spec caps; standard-mode op is +0.1%; mixed result-key schema |
| BLS12-381 | soundness | pass | value-level trace test of the on-chain δ kernels against DPROJ; keep the order-13 vector as a projective-degeneracy rejection; state the E_A = 0 exactness lemma; T2 lazy-tower bound envelope not re-established for the rolled dataflow (liveness only) |
| BLS12-381 | measurement | pass | all numbers reproduced exactly. T1 k_min over the sweep is about 1.65 / 2.50; T1 needs bch-spec caps; measure.mjs uses a 63 B overhead (stale 8,650 score in a side file) |

Both reviews also flagged a stale root `PROGRESS.md` on groth16_cashscript main (6204686). It was removed (a594976), and the sources were brought over without the build branches' work notes.

## 6. Limits and caveats
- **Registered entries (2026-10-28).** All five ids are in REGISTRY, results.json and score-history.json with reviewStatus `reviewed`, on the two internal reviews above plus a fix round that closed the minor items in §5. They have had no independent external review. Every one is over the op budget of its target VM, so none is deployable on a current or proposed ruleset.
- **libauth vs BCHN op-cost.** libauth charges 100 per OP_DEFINE; BCHN and bchd also charge the body bytes. The BCHN-adjusted figures add 1.3–3.2k per design, which is negligible here. Standard (relay) mode is about 0.1% above consensus.
- **Proof dependence.** T2 vk_x is input-dependent: +8.8M (BN) and +25.5M (BLS) on dense inputs. T1 is nearly flat, but its unlocking grows with n_q (BN max-degree witness 17.1 KB).
- **Size caps.** E_k ignores caps. T1, like today's SI-GLS single, needs bch-spec sizes (unlockings of 16.5–18.8 KB). T2 fits bch-2026 caps (BN redeem 9,128 / unlocking 9,678; BLS 7,840 / 8,590).
- **One machine.** Track 1's CPU-per-op-cost ratio (which sets k ≈ 5–10) comes from one machine and stock BCHN, so it is an order-of-magnitude estimate. The op-cost numbers in this report are deterministic.
- **Not built.** These were not built:
  - the BLS native multi-input port of T1 (bch-2026 sizes, model 21.2 KB / 40.2M);
  - GLV vk_x for BN T2 (about −10M);
  - outlined T2 variants;
  - the model's k ≥ 50 designs.
- **Constructive only.** No exploit hunting was done. Rejection was checked with the existing invalid classes and the redteam suites that already exist.

## Files

| path | what |
|---|---|
| `REPORT.md` | this report |
| `ek_table.py` | E_k tables from the measured numbers |
| `model.py`, `model-output.{md,json}`, `MODEL-NOTES.md` | the hint-vs-compute model |
| `profile/bn254/` | BN254 call-stack op-cost tracer and section, byte and opcode-class scripts with their small outputs (the minop artifact and trace outputs over 200 KB stay in `work/frontier-middle/profile-bn254`) |
| `profile/bls12381/` | BLS12-381 profiler and segmentation scripts, entries.json and the small outputs |
| `bn254/`, `bls12381/` | measurement glue (`measure.ts`, `run.ts`), vectors and harness results for the built designs |
