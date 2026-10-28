# Track 2: hint-vs-compute cost model (frontier middle)

Status: prediction only. Nothing here is a leaderboard entry. Run `python3 model.py --json model-output.json --md model-output.md`.
Inputs: the profiles in work/frontier-middle/profile-bn254 and profile-bls12381 (libauth 3.1.0-next.8, committed proof).

## How the model works
The model has two architecture families. Their components only combine within a family.

- **F12** (singleton/minop lineage). The Fp12 accumulator is computed on-chain. The knobs are:
  - tower: reduced or lazy;
  - accumulator: 4 separate loops, or 1 shared loop with e(α,β) baked;
  - terminal: final exponentiation or residue witness;
  - G2 subgroup check: walk or fused endpoint;
  - vk_x: Jacobian D&A, GLV with affine witnessed slopes, or GLV-Jacobian with a zInv witness;
  - each G2 walk (B, γ, δ): projective on-chain, witnessed affine slopes, baked slope pile, or baked lines;
  - layout: rolled or unrolled;
  - outlining pass: on or off.
- **ZEV** (SI-GLS lineage). The loop runs on evaluations at ±z, and committed monic states are checked by one Schwartz-Zippel identity. The knobs are:
  - δ walk: slope pile or projective on-chain;
  - B walk: keep the affine witnessed segment, or make it all projective;
  - chunk length m (events per state);
  - host: single input (bch-spec) or native multi-input.
- **Calibration.** The model reproduces the measured entries:
  - BN plain singleton 8,206 B / 771.1M (measured 771.3M);
  - BN opcode-optimized 6,236 / 799.6 (measured 6,237 / 800.2);
  - BN minop 58,285 / 64.8 (measured 58,073 / 64.8);
  - BLS plain and opcode-optimized exact;
  - BLS minop 59,241 / 145.3 (measured 58,841 / 145.6).
- **Bands.** Unmeasured unit costs carry lo/hi bands. The two least certain are the BN lazy projective G2 step (180k/200k, ±25%) and the BN lazy general 034 line (175k, −15%/+25%). BLS lazy units are all measured in the BLS minop.

## Findings
1. **Code bytes are a fixed cost and hints are the variable cost**, so the two families do not interpolate.
   - A mixed design pays for both code bases: about 5.7 KB of SI-GLS code plus about 8 KB of F12 code.
   - So there is no continuum between SI-GLS and the singletons. There are two new points instead.
2. **SI-GLS hints are already at their byte optimum** (m = 2). Sparser checkpoints raise the quotient degree as about 2^m, which costs more than the states they save.
   - BN, states + quotient: m=1 13.8 KB, m=2 10.0 KB, m=3 12.5 KB, m=4 22 KB.
   - The cheap byte lever in SI-GLS is the baked δ slope pile: 5.7 KB on BN, 6.6 KB on BLS.
   - Recomputing the δ walk projectively with the B kernels costs about +8.6M (BN) and +9.8M (BLS).
3. **Minop is dominated because of how it was generated, not because of the method.**
   - Rolling the loop removes 16.8 KB of glue and 3.6 KB of cleanup.
   - Computing the γ/δ lines on-chain removes the baked lines (23.4 KB on BN, 40.6 KB on BLS) for about 33M (BN) / 39M (BLS).
   - The lazy tower, residue terminal and fused endpoint stay. The result is about 8.2 KB at 117M (BN) or 189M (BLS).
4. **A reduced tower with a residue terminal** (the plain singleton minus the FE, the subgroup walk and the 3 extra loops) predicts 5.0 KB / 323M (BN) and 5.3 KB / 412M (BLS). It only wins at k ≥ 50, so it is not a build target.

## Targets
| curve | target | bytes | op-cost | wins from k |
|---|---|--:|--:|--:|
| BN | T1: SI-GLS with the δ walk on-chain | 16.5 KB | 31.9M | 1.8 |
| BN | T2: rolled lazy residue | 8.2 KB | 117.5M | 6.7 |
| BLS | T1: SI-GLS with the δ walk on-chain, all-projective B | 18.7 KB | 37.3M | 1.75 |
| BLS | T2: rolled minop with γ/δ lines on-chain | 8.2 KB | 189M | 8.9 |

The bch-2026-sized multi-input variants of T1 are:
- BLS native with δ and B projective: 21.2 KB / 40.2M over 4 inputs, -20% at k = 5-25. This is a stage-2 option.
- BN native: 19.9 KB / 33.4M, only -9%, so not chosen.
