# Track 6 design: a universal-setup PLONK/KZG verifier for CashVM (gnark, BN254, SHA-256 transcript)

Date: 2026-10-29. Status: **design only**. Research, **not a leaderboard entry**. Nothing is in REGISTRY,
results.json or score-history.json, and the website is unchanged.

Every figure below is an **estimate** from a cost model ([model.mjs](model.mjs), output in [model-output.txt](model-output.txt)
and [model-result.json](model-result.json)). The model's unit costs are VM-measured kernels ([kernels.mjs](kernels.mjs) →
[kernels.json](kernels.json)) plus in-situ figures from the reviewed Groth16 sources (cited inline). The gnark reading of
the protocol is checked by a Go reference verifier ([gnark-ref/](gnark-ref/)). It recomputes gnark's transcript byte for
byte, applies the two substitutions this design makes (§3.3), and accepts gnark's own proof. Both it and gnark reject
six tampered proofs.

## 1. Question

Groth16 needs a trusted setup for every circuit. PLONK with KZG uses one universal, reusable ceremony, such as Aztec
Ignition or the perpetual powers of tau. With it, a BCH developer can verify proofs from standard tooling for any circuit
without running a ceremony. The questions:

1. Which steps does a CashVM verifier for **gnark v0.16.4** BN254 PLONK proofs need? Which existing kernels cover them,
   and at what cost?
2. **Key observation to evaluate.** Both G2 arguments of the KZG pairing check are fixed SRS points, `[1]_2` and `[x]_2`.
   In Groth16 one of them is the prover-supplied B. What does that save, and what does PLONK add?
3. Which soundness checks are required?
4. Which layouts fit each regime? What do they cost compared with Groth16 sound-native (27.6 KB today, 3 inputs) and
   sound-si-gls (21.9 KB bch-spec)?

**Pinned versions.** `github.com/consensys/gnark v0.16.4` and `github.com/consensys/gnark-crypto
v0.21.1-0.20260913224755-1409fe592052`, the version gnark v0.16.4's go.mod pins. The verifier source read is
`backend/plonk/bn254/verify.go`, `ecc/bn254/kzg/kzg.go` (FoldProof, BatchVerifyMultiPoints) and `fiat-shamir/transcript.go`.
Go is 1.27.1; gnark's go.mod asks for go ≥ 1.26.8.

**Why gnark.** Its default `ChallengeHash` and `KZGFoldingHash` are `sha256.New()` (backend/backend.go), and CashVM hashes
SHA-256 natively. snarkjs PLONK uses Keccak-256 instead (§9).

## 2. Result

The PLONK/KZG verifier comes out at about **2.0-2.5× the size of the Groth16 one** in every regime. The G1
multi-scalar multiplication (MSM) dominates the cost. The fixed-G2 pairing is cheap: it does about half of Groth16's
per-event Miller work.

| design (estimate, standard op-cost) | op | content | bch-spec | 100 KB input | today (inputs) |
|---|--:|--:|--:|--:|--:|
| **recommended: plan B + GT folding of the 9 fixed bases** (§6.4) | 44-52M | 55-64 KB | **55.1 KB** | **60.2 KB** | **66.0 KB (7)** |
| simpler: plan B, all bases in the G1 MSM, SI pairing unchanged | 51-57M | 62-69 KB | 61.9 KB | 67.4 KB | 71.3 KB (8) |
| naive: all-Jacobian MSM, no witness help | 86.5M | 35 KB | 98.3 KB | 108.2 KB, **does not fit one 100 KB tx** | 116.8 KB (12) |
| Groth16 reference (reviewed entries, measured) | 20.6-23.3M | | 21.9 KB (si-gls) | 29.3 KB (si-gls TXv5 padded) | 27.6 KB (sound-native, 3) |
| ratio, recommended / Groth16 | | | 2.5× | 2.05× | 2.4× |

- The recommended row's op and content ranges come from the per-regime optimum: window sizes and the Jacobian/affine mix
  are tuned for each regime.
- "today": standard rules, multi-input chain, 10,000 B unlocking per input, base 41.
- "100 KB input": TXv5-style, one input of up to 100,000 B, base 41, padded to buy op-cost.
- "bch-spec": base 10,000.
- **BCHN-adjusted** op-cost adds the OP_DEFINE body bytes. For a code blob of about 6 KB that is about +6k op per input:
  +0.01% for one input, +42k (+0.08%) for the 7-input chain. No regime changes.
- **Uncertainty is about ±10%.** The unbuilt parts are the code-blob size (6.0 ± 1.5 KB), the MSM loop overhead per
  addition, and the per-input setup in the multi-input layout.

Where the cost goes in the recommended design (100 KB-input tuning, 48.1M op, 59.6 KB content):

| part | op | bytes | note |
|---|--:|--:|---|
| G1 MSM over the 9 proof points (+ witnessed Λ), one 128-bit GLV chain | 20.0M | 12.5 KB | about 496 additions and 128 doublings; 60% affine with witnessed slopes |
| variable-base tables (150 affine additions) and GLV splits | 3.3M | 5.1 KB | |
| P_right = W_ζ + u·W_ζω, one 64-bit chain | 2.5M | 1.8 KB | u is 128-bit entropy as u1 + λ·u2 |
| two fixed-G2 Miller chains (88 events) | 9.4M | 11.3 KB | baked slopes of `[1]_2` and `[x]_2` |
| GT-GLS fold of the 9 fixed VK/SRS bases | 7.7M | 4.0 KB | the SI-GLS vk_x technique, 9 bases instead of 2 |
| SI states (65), quotient (132 words), setup, terminal | 4.6M | 17.2 KB | residue root replaces the final exponentiation |
| statement, transcript, Fr work | 0.55M | 0.9 KB | proof 768 B, 2 public inputs, 1 witnessed inverse, Λ 64 B |
| code + VK | – | 6.7 KB | code estimated |

## 3. gnark's verifier, step by step (as read from verify.go)

Notation: `[P]` is a G1 point. The 64-byte raw encoding is `RawBytes()`: x‖y big-endian, no flag bits for an affine
point, and all-zero for infinity. `Fr` elements are 32-byte big-endian canonical (`Marshal()`). With
`nbCommitments = 0` (no BSB22 commitments; see §9 for the extension) a proof is

- 9 G1 points: `L, R, O, Z, H0, H1, H2`, `W_ζ = BatchedProof.H`, `W_ζω = ZShiftedOpening.H`;
- 7 Fr values: `ClaimedValues[0..5] = lin, l, r, o, s1, s2`, and `zu = z(ωζ)`.

That is 800 B, or 808 B in `WriteRawTo`. `lin` is fully determined, so the CashVM verifier recomputes it and the proof
pushes 768 B.

### 3.1 Transcript (bytes, confirmed by the Go reference)

`ComputeChallenge(id)` = SHA256(id ‖ previous challenge's raw 32-byte digest (absent for the first) ‖ bindings). The
challenge is `BE(digest) mod r`, via `fr.Element.SetBytes`.

| challenge | preimage | bytes (2 PIs) | SHA-256 blocks |
|---|---|--:|--:|
| γ | `"gamma"` ‖ S1‖S2‖S3‖Ql‖Qr‖Qm‖Qo‖Qk (raw, 8×64) ‖ PI_i (32 BE each) ‖ L‖R‖O | 773 | 13 |
| β | `"beta"` ‖ γ_raw | 36 | 1 |
| α | `"alpha"` ‖ β_raw ‖ Z | 101 | 2 |
| ζ | `"zeta"` ‖ α_raw ‖ H0‖H1‖H2 | 228 | 4 |
| v (kzg.FoldProof's "gamma") | `"gamma"` ‖ ζ (32 BE) ‖ Λ‖L‖R‖O‖S1‖S2 (raw) ‖ lin, l, r, o, s1, s2 ‖ zu | 645 | 11 |
| u, t (**ours**, §3.3) | `"u"` ‖ v_raw ‖ W_ζ ‖ W_ζω | 161 | 3 |

The whole PLONK transcript is 34 blocks, about 21k op. That is negligible. The VK points enter γ as raw bytes, so the
VK constants are stored big-endian raw (they serve as hash input) and turned into numbers with OP_REVERSEBYTES.

### 3.2 Scalar work (Fr)

1. `ζ^n` by log2(n) squarings, and `zh = ζ^n − 1`.
2. One batch inverse of `Π_{i<nPI}(ζ − ω^i)`, also covering L1's `ζ − 1`. Then `L1(ζ)` and
   `PI(ζ) = Σ w_i·ω^i/n·zh/(ζ − ω^i)`.
3. `constLin = −[PI − α²L1 + α(l+βs1+γ)(r+βs2+γ)(o+γ)zu]`, which **is** `lin`.
4. `_s1`, `_s2`, `coeffZ = α²L1 + _s2`, `l·r`, and `−ζ^{n+2}zh`, `−ζ^{2(n+2)}zh`, `−zh`.
5. The folding powers `v..v^5`, the folded evaluation `e = lin + v l + v² r + v³ o + v⁴ s1 + v⁵ s2`, and the u terms.

This is about 74 Fr multiply-mods for n = 2^16 and 2 public inputs, about 0.37M op.

### 3.3 Commitments and the pairing (gnark), and the two substitutions

- `Λ = l·Ql + r·Qr + lr·Qm + o·Qo + Qk + _s1·S3 + coeffZ·Z + (−zh)·H0 + (−ζ^{n+2}zh)·H1 + (−ζ^{2(n+2)}zh)·H2`
  (the linearised-polynomial digest).
- `D = Λ + v·L + v²·R + v³·O + v⁴·S1 + v⁵·S2`.
- `P_left = D + u·Z − (e + u·zu)·[1]_1 + ζ·W_ζ + u·ζω·W_ζω`.
- `P_right = −(W_ζ + u·W_ζω)`.
- **Accept iff `e(P_left, [1]_2) · e(P_right, [x]_2) = 1`.** gnark calls `PairingCheckFixedQ` with precomputed lines:
  gnark itself treats both G2 arguments as fixed.

Two substitutions; both are verifier-side only, so gnark proofs are unchanged.

1. **u.** gnark draws u at random in the verifier (`randomNumbers[1].SetRandom()`). On-chain it must come from the
   transcript.
   - We take `u = u1 + λ·u2`, where u1 and u2 are the first two 64-bit words of SHA256("u" ‖ v_raw ‖ W_ζ ‖ W_ζω) and λ is
     the G1 GLV eigenvalue.
   - The map (u1, u2) ↦ u is injective: the GLV lattice has no vector shorter than about 2^127. So u carries 128 bits of
     entropy, and `u·W_ζω` costs only 64 doublings.
   - gnark's Solidity verifier also derives u by hashing (`batch_verify_multi_points`). Ours binds the same unbound
     values, W_ζ and W_ζω.
2. **Plan B: witnessed Λ.** The prover hashes Λ into v, so the verifier needs Λ's exact affine coordinates before v.
   - Plan B takes Λ' as a 64-byte witness and checks it on the curve. Then
     `P_left* = rest + t·MSM_lin + (1 − t)·Λ'`, with `t = t1 + λ·t2` from words 3-4 of the same hash.
   - If Λ' ≠ Λ, then `P_left* = P_left + (1 − t)(Λ' − Λ)`, so the pairing equation holds for at most one t. That is a
     2^-128 error per hash query (§7).
   - Plan B removes Λ's separate doubling chain, and it lets the fixed bases inside Λ move into GT (§6.4).
   - Plan A instead computes Λ in its own chain and converts it to affine with one witnessed inverse.

The Go reference ([gnark-ref/main.go](gnark-ref/main.go)) implements exactly this.

- On gnark's proof for a toy 2-public-input circuit (unsafekzg test SRS, n = 8), it accepts both with the MSM value of
  Λ and with Λ witnessed.
- It rejects a wrong witnessed Λ.
- It rejects, as gnark also does, these tampered proofs:
  - public input +1;
  - l(ζ) + 1;
  - z(ωζ) + 1;
  - W_ζ doubled;
  - H1 + G;
  - L and R swapped.

## 4. Step → kernel map

Unit costs are standard op. "VM" means measured here with random full-size operands, in the libauth BCH_2026 VM
([kernels.json](kernels.json)). "SI" means the SI-GLS in-situ profile (`chunked/bn254/sound-si-gls`, `profile.mjs`).

| # | step | existing kernel / source | unit cost | count | op | bytes |
|---|---|---|---|---|--:|--:|
| 1 | pin layout; decode and range-check 18 coordinates (< p), 6 claimed values and PIs (< r) | SI-GLS `RD` (BIN2NUM(w‖00) < p), plus OP_REVERSEBYTES | ~0.9k/word | 26 | 0.02M | 768 + 32·nPI |
| 2 | on-curve check of 9 proof points (+Λ'). Cofactor 1, so this is the subgroup check; (0,0) fails it | new, 3 mul-mods | ~13.6k | 10 | 0.14M | |
| 3 | transcript γ, β, α, ζ, v (gnark bytes); u, t (ours) | OP_SHA256 (SI-GLS transcript code) | 192/block + CATs | 34 blocks | 0.02M | |
| 4 | ζ^n, batch inverse (witnessed, one mul check), L1, PI(ζ), constLin = lin, _s1, _s2, coeffZ, ζ^{n+2} terms, v powers, folded e | Fr mul-mod (VM 3.7k; ~5k in situ) | 5k | ~74 | 0.37M | 32 |
| 5 | GLV split of each MSM scalar: witnessed k1, k2 (≤ 2^128, signed), check k1 + λk2 ≡ s (mod r) | densless-msm GLV check, `pairfold5-msm/vkx-msm-asm.mjs` | ~14k | 9 (17 without folding) | 0.13M | 34 each |
| 6 | variable-base tables (2^(w−1) multiples per proof point; φ half by β·x at lookup) | G1 affine add, witnessed slope (VM **17.4k** + 32 B) | 18k + 32 B | 150 | 2.7M | 4.8 KB |
| 7 | Straus MSM for P_left, one 128-bit chain, signed windows w = 5 | Jacobian dbl (VM **34.2k**) / madd (VM **48.6k**), or affine dbl / add with witnessed slope (VM **16.9k** / **17.4k** + 32 B); loop and lookup ~3.75k + Horner digit 0.9k per addition | – | 128 dbl + ~496 add | 16.5-23.4M | 8.5-16.5 KB |
| 8 | P_right = −(W_ζ + u1·W_ζω + u2·φ(W_ζω)), one 64-bit chain | same | – | 64 dbl + 28 add | 2.1-2.9M | 1.2-2.4 KB |
| 9 | Miller loop event: two baked chains + `F± ← F±²·La·Lb` (doubling) or `F±·La·Lb·c±` (addition) | **SI δ step `kDStep`** (VM 46.7k alone) composed: VM **101.4k / 101.7k** per event, × 1.05 in situ | 106.5k | 88 | 9.38M | 2 × 88 × 64 = 11,264 |
| 10 | GT-GLS fold of the fixed bases (TP/TM tables, acc_k, exact mod-r binding) | **SI-GLS GT-GLS** (`kTable`, `kEval`; profile 1.32M for 2 bases) | 0.66M/base loop + 0.18M/base tables | 9 | 7.73M | 449/base |
| 11 | chunk boundaries `R ← Rρ + F+·S'(−z) − F−·S'(z)` | SI-GLS (1.54M / 33) | 46.7k | 65 (33 without folding) | 3.0M | 192/state |
| 12 | residue root `s^c`, `S_c(±z)`, `S_c(±ηz)`, z powers, `c_j = Φ(γ1^j)(z)` | SI-GLS setup | – | 1 | 0.30M | 192 |
| 13 | terminal: `Fr1 = Frob(S_c)`, `W(±z)`, the two Frobenius steps of each chain (in #9), final identity `R ≡ z·q(z²)·M(z)` | SI-GLS terminal and quotient (6.47k/word) | – | NQ = 132 (60) | 1.2M | 32·NQ |
| 14 | SI transcript `h0, ρ, z` over u_raw, the residue root, states, nibbles and WQ | SI-GLS | | | 0.07M | |

The final exponentiation has no row: the SI residue root replaces it (§5.3).

## 5. Key observation: both G2 arguments are fixed

### 5.1 What it saves (vs the Groth16 SI pairings)

- **No G2 walk.** Groth16's SI pairings walk the prover's B on-chain. In SI-GLS this is a projective doubling at 143k
  per event in situ and a mixed addition at 185k, 13.57M for 65 + 23 steps. sound-native (SI-MX3) uses an affine walk
  with inverse-norm witnesses instead: about 8.7M plus 2.8 KB.
- **Both chains baked.** With `[1]_2` and `[x]_2` fixed, both chains are SI "δ steps" with baked slopes. The δ step was
  already the cheap part of Groth16. One shared event, both lines plus the F update, measures **101.4k**; Groth16's
  SI-GLS event costs about 192k (B doubling + δ) or 234k (B addition + δ).
  - Over 88 events that is 9.4M against 17.9M: **−8.5M op**, worth about 10.6 KB at 800 op/B.
  - The cost is a second 5.6 KB slope pile, so the net saving is about 5 KB-equivalent.
- **No G2 validity work.** The twist check, the ψ-endpoint subgroup argument, B's decoding and its transcript bytes all
  disappear. `[1]_2` and `[x]_2` and all 88 steps of each trajectory (Z ≠ 0, nonzero leading line coefficient, the
  endpoint (6x+2)Q + ψ(Q) − ψ²(Q) = −ψ³(Q)) are asserted against noble at build time, as `math.mjs` does for δ.
- **Lower degree.** Without GT folding an event carries two lines (18), or 42 with an addition, against Groth16's 90
  with GT-GLS. So 2-event chunks give NQ_MAX = 60 instead of 132 (−2.3 KB, −0.47M).
- **Universal constants.** The `[1]_2` slope pile is the same for every SRS. The `[x]_2` pile is fixed per ceremony,
  e.g. Aztec Ignition, and shared by every circuit proved against it.

### 5.2 How to supply the line coefficients

Three ways were weighed for each fixed chain:

1. **Slopes baked (64 B per step), x and c recursion on-chain: chosen.** This is the SI δ step, 46.7k standalone and
   49k in situ.
2. Fully baked `(λ_j, c_j)` (128 B per step). It saves about 18k op per step for 64 more bytes (51k op-equivalent).
   That trade is worse in every regime.
3. No baking: an on-chain projective walk of the fixed point, as T1 sigls-dproj does. Frontier-middle measured +10M for
   −5.6 KB, i.e. 1,775 op/B. That is worse whenever bytes buy op at 800/B.

In the multi-input layout the piles sit in other inputs' unlocking bytes, authenticated by digest (the SI-MX3 `DS_i`
pattern). Committing them as a table costs no extra bytes.

### 5.3 Shared final exponentiation and the residue trick

The residue / witnessed final-exponentiation trick **applies unchanged, and it is already what makes the pairing
cheap**. SI replaces the final exponentiation with one residue root c (6 words): `[f′] = [c]^λ` in `G = Fp12*/Fp6*`
implies `FE(f′) = 1`.

- For the KZG product, `f′ = Miller(P_left, [1]_2) · Miller(P_right, [x]_2) · Π GT-GLS factors`. One accumulator `F±`,
  one set of states and one root serve both pairings.
- So the "shared final exponentiation" is free. The second pairing costs only its own chain recursion and line
  evaluation, about 54.7k per event (101.4k for both chains vs 46.7k for one), 4.8M over 88 events. It needs no second
  accumulator, no second set of states and no second root.
- A direct Fp12 final exponentiation, or the classic `f = c^λ·w` residue check (rolled-residue style), would cost far
  more op. T2 measured about 130M for a whole Groth16.
- 3 ∤ p^6+1 and gcd(λ, (p^6+1)/r) = 1 are SI-GLS's asserted facts, so no 27th-root witness is needed.

**Jacobian P.** P_left and P_right come out of the MSM in Jacobian form. A line at `P = (X:Y:Z)` scaled by `Z³` is
`Y + XZ·X·Φ(ℓ1) + Z³·X³·Φ(ℓ3)`, an Fp multiple of the affine line, so its class in G is unchanged.

- Setup folds Z³ and XZ into the env constants. The per-step cost is the same and no inversion is needed.
- `Z ≠ 0` is required, i.e. P ≠ O. Honestly this fails only with negligible probability. It keeps `ℓ0 = Y ≠ 0`, the
  "nonzero line polynomial" fact of the SI degree argument.

### 5.4 What PLONK adds

- **A G1 MSM with 17 full-size scalars** (Groth16 has only vk_x).
  - Without folding: 8 fixed bases (Ql, Qr, Qm, Qo, S1, S2, S3, [1]_1), Qk with scalar t, and 9 proof points (Z, H0,
    H1, H2, L, R, O, W_ζ, W_ζω).
  - Plus Λ' with a 128-bit scalar, and the separate 64-bit P_right chain.
  - Naively that is about 1,150 additions, 74M op (§6).
  - **This, not the pairing, decides the size.**
- **Fr work.** About 74 multiply-mods and one witnessed inverse for the Lagrange denominators: 0.37M + 32 B. Small.
- **Transcript.** 34 SHA-256 blocks, about 21k op. Negligible, and native thanks to gnark's SHA-256.
- **GT-GLS for the fixed bases** (§6.4). It trades G1 additions for GT factors at higher degree: 65 states and
  NQ = 132 instead of 33 states and 60.

## 6. The MSM (the crux)

Bytes buy op at 800 per byte in every regime, so the objective is `max(bytes, op/800 − base)`. Every knob trades along
that line.

### 6.1 GLV and windows

- Each full Fr scalar is split as `k1 + λ·k2` (witnessed, ≤ 2^128, checked mod r). With φ(x, y) = (βx, y) this gives
  one shared chain of **128 doublings**.
- Signed windows: w = 5 is optimal, at 26 additions per 128-bit half.
- Fixed-base tables are baked (2^(w−1) affine multiples). Variable-base tables are built on-chain, 15 additions each at
  w = 5.
- The φ half reuses the table, with β·x at lookup.
- The accumulator starts at a fixed offset point and the constant correction is added at the end (densless-msm pattern),
  so there are no infinity branches.

### 6.2 Jacobian vs affine with witnessed slopes

| per operation | Jacobian (VM) | affine, witnessed slope (VM) | op-equivalent at 800 op/B |
|---|--:|--:|---|
| doubling | 34.2k | 16.9k + 32 B | 34.2k vs 42.5k |
| addition | 48.6k (madd) | 17.4k + 32 B | 48.6k vs 43.0k |

- **Affine with witnessed slopes.** A slope is fixed by the exact equation `λ(x2 − x1) ≡ y2 − y1` with
  `x2 − x1 ≢ 0` (addition), or `2yλ ≡ 3x²` (doubling; y ≠ 0 on G1). The slope is unique, so it needs no transcript
  binding. This is the inverse-norm idea of SI-MX3, in Fp.
- **Per regime.** Additions are cheaper affine at any byte price. Doublings are cheaper Jacobian once bytes are the
  binding constraint.
- **Mixed.** The model mixes the two along the chain (fraction fA of the positions run affine; one witnessed inverse at
  the switch). The optimum is fA = 0.4-0.8, depending on the regime.

### 6.3 Plan A vs plan B

| | Plan A (Λ computed) | Plan B (Λ witnessed, t-folded check) |
|---|---|---|
| chains | Λ (128) + rest (128) + P_right (64) | P_left (128) + P_right (64) |
| extra terms | Λ to affine (1 inverse); Λ plain add | Λ' (two 64-bit halves); Qk gets scalar t |
| fixed bases movable to GT | 3 (S1, S2, [1]_1); Λ's must stay in G1 | all 9 |
| new soundness surface | none | the t-fold (§7) |
| best today / spec / 100 KB, no GT folding | 72.1 / 64.2 / 69.5 KB | 71.3 / 61.9 / 67.4 KB |

### 6.4 GT folding of the fixed bases (recommended)

Every fixed base B_i (Ql, Qr, Qm, Qo, Qk, S1, S2, S3, [1]_1) is paired with the fixed `[1]_2`, so `e(B_i, [1]_2)` is a VK
constant. Its scalar can then be applied in GT exactly as SI-GLS applies `e(vk_x, γ) = Π e(IC_k, γ)^{n_k}`:

- s_i is split as `Σ_j u_{i,j}·p^j (mod r)` with 64-bit `u_{i,j}`. The nibbles are committed before ρ.
- At each event, F± is multiplied by the table entry `TP_i/TM_i[N_i[e]]`.
- The exact binding check is `(acc_i − 2^64Σπ − s_i) mod r == 0`.

Cost per base: about 0.66M in the loop and 0.18M for the tables, plus 384 B of R constants and 65 B of nibbles. That
replaces 52 G1 additions (about 2.5M op-equivalent).

- **The catch is degree.** Up to 4 R factors of degree 6 per base per event: 9 bases add up to 216 to the event degree.
  That forces 1-event chunks (65 states) and NQ_MAX = 132 (exactly SI-GLS's 270 / 275 degree bound).
- **Net.** Folding saves about 6 KB in every regime (55.1 vs 61.9 bch-spec; 60.2 vs 67.4 at 100 KB; 66.0 vs 71.3 today).
- **Today, it costs more per input.** Each input that runs pairing events must rebuild the GT-GLS tables
  (9 × 0.18M), which is charged in the model.

## 7. Soundness: required checks

Every accept-relevant value needs an owner, as in the SI-GLS / SI-MX3 policy.

| value | owner / check |
|---|---|
| proof points L, R, O, Z, H0-H2, W_ζ, W_ζω and Λ' | canonical `< p` for each coordinate; **on curve** `y² = x³ + 3`. BN254 G1 has cofactor 1, so this is subgroup membership. The all-zero encoding of infinity fails the curve equation, so it is rejected (gnark accepts infinity; honestly it occurs only with negligible probability) |
| l, r, o, s1, s2, zu, public inputs | **canonical `< r`**, so the bytes hashed equal gnark's `Marshal()` and every encoding is unique |
| lin = ClaimedValues[0] | recomputed on-chain as −constLin and serialised into v's preimage (gnark compares it with the proof value) |
| VK (S1-S3, Ql-Qk, n, ω, coset shift k1, n⁻¹, nPI) and SRS (`[1]_2`, `[x]_2`, `[1]_1`) | VK constants, committed by the locking (P2SH32 → redeem → code digest → constants digest). **gnark's γ binds the VK points and the public inputs**, but not n, ω, k1 or the SRS. Those are bound by the locking commitment instead. A VK-as-data variant must commit to a hash of the *whole* VK, not just the points |
| γ, β, α, ζ, v | recomputed from the exact gnark preimages (§3.1); reduced as `BE(digest) mod r` |
| u, t | ours, from SHA256("u" ‖ v_raw ‖ W_ζ ‖ W_ζω), after every prover value they weigh. 128-bit entropy each: the GLV injectivity of u1 + λu2 |
| batch inverse | witnessed, `< r`, **checked by `Π(ζ − ω^i)·inv ≡ 1 (mod r)`**, which also rejects `ζ = ω^i` (probability nPI/r). The per-index inverses come from back-substitution |
| GLV splits `k1 + λk2 ≡ s`, window digits, slope witnesses | fixed by exact equations: the mod-r reconstruction, Horner of the digits, `λ(x2 − x1) ≡ y2 − y1` with `x2 ≠ x1` (or `2yλ ≡ 3x²`). They are not hashed (harmless if they are) |
| exceptional G1 cases | affine: `x2 ≠ x1` checked; Jacobian: H ≠ 0 per madd, or Z = 0 absorbing plus a final Z ≠ 0. Exceptional cases cause rejection only. Honestly they are negligible because the scalars are pseudo-random and the start is an offset point |
| P_left, P_right ≠ O | Jacobian Z ≠ 0, for the SI nonzero-line argument |
| GT-GLS nibbles | committed in SI's h0 before ρ; exact mod-r binding to the on-chain scalar s_i (SI-GLS) |
| SI states, residue root, WQ | as SI-GLS: monic states `< p`, h0 → ρ → z ordering, NQ cap (60 without folding / 132 with), leading word ≠ 0 |

**Soundness error.**
- PLONK (gnark, random-oracle model): the usual `O(n/r)` per query.
- Plus the u-batching (2^-128) and, in plan B, the t-fold (2^-128) per hash query.
- Plus SI's `1.134·(states + deg)/p`, about 2^-245.
- Plus the SHA-256 collision term.

These are additive. BN254's own security, about 100-110 bits, is the binding term. **The plan-B t-fold and the folding
of on-chain scalars into GT-GLS are new compositions** of reviewed parts. They need a written argument and an independent
review before any claim.

## 8. Layouts and estimates per regime

All rows are the recommended design (plan B, GT folding, signed windows, mixed Jacobian/affine MSM). Byte figures follow
the bench convention: unlocking + locking + tx overhead.

### 8.1 bch-spec (one input, base 10,000): **≈ 55.1 KB**

`<WQ> <WSI (states, residue root, nibbles)> <MSM witness stream> <proof ‖ PIs ‖ Λ' ‖ inverse ‖ GLV splits> <redeem>`

- The redeem holds the code (about 6 KB), the VK and R constants (4.7 KB) and the two slope piles (11.3 KB).
- 51.9M op, 55.0 KB content, balanced (no pad).
- MSM tuning: wf = 4, wv = 5, fA = 0.4.

### 8.2 100 KB input (TXv5 rules, base 41): **≈ 60.2 KB**, one input, one tx

- Same layout plus a pad slot (the `chunked/txv5-pad` pattern: `DEPTH <n+1> NUMEQUALVERIFY DROP`).
- 48.1M op, 59.6 KB content, about 0.5 KB pad.
- MSM tuning: fA = 0.6.
- It fits comfortably under the 100,000-byte tx limit. **The naive all-Jacobian build does not fit** (108 KB): the
  witness-assisted MSM is required, not an optimisation.

### 8.3 Today's standard rules: **≈ 66.0 KB over 7 inputs** (one tx, ~66 KB < 100 KB)

This is the SI-MX3 pattern from `chunked/bn254/bn-native-sound`:

- one 57-65 B redeem shared by all inputs;
- the code blob loaded by OP_INPUTBYTECODE and checked by SHA256;
- the graph pinned (input count, same locking);
- per-input digests `d_i`, and `h0 = SHA256(TAG ‖ d0..d6)`;
- canonical handovers checked byte-exactly.

| input | role | main content | op (est.) |
|---|---|---|--:|
| 0 | statement, gnark transcript (γ..v, u, t), Fr scalars, GLV splits; publishes the **scalar blob** (checked byte-exact against its own computation; others read it); MSM positions 127..~100 | code blob 6 KB, proof 768 B, PIs, Λ', inverse, start of the slope stream | ~7.3M |
| 1-2 | MSM positions (Straus, mixed mode), variable-base tables (built once, verified, read by the others) | MSM slope witnesses, digits | ~7.5M each |
| 3 | MSM tail; P_left, P_right out (affine plus Jacobian check); start of the Miller events | MSM witness, the `[1]_2` slope pile | ~7.4M |
| 4-6 | Miller events with GT-GLS factors, boundaries, terminal, quotient | the `[x]_2` pile, states, R constants, nibbles, WQ | ~6.5-7.4M each |

- 44.2M op + 7 × 0.5M setup + 2 × (0.3M z setup + 1.6M GT-GLS tables) = 51.7M, against a budget of 7 × ~7.95M.
- Content 64.1 KB plus redeem and handovers, for 65.4 KB of unlocking.
- Score ≈ 65.4 KB + 22 + 7 × 78 ≈ **66.0 KB**.
- Without GT folding: 71.3 KB over 8 inputs. Folding helps less here because every pairing input rebuilds its tables.

### 8.4 Comparison with Groth16

| | Groth16 sound-native (today) | Groth16 sound-si-gls (bch-spec) | PLONK/KZG (this design) |
|---|---|---|---|
| bytes | 27,624 (3 inputs) | 21,915 | 66.0 KB today (7 inputs) / 55.1 KB bch-spec / 60.2 KB at 100 KB (Groth16 si-gls there: 29.3 KB) |
| op | 20.6M (+ setups) | 23.3M | 44-52M |
| trusted setup | per circuit | per circuit | **one universal ceremony** |
| pairing part | 2 runtime-G2-free pairs + B walk (≈ 18M) | same | two fixed chains (9.4M) |
| G1 MSM | none (vk_x by GT-GLS, 2 PIs) | none | 9 proof points + 9 fixed (GT-folded): about 24-30M + 15-24 KB |

**Bottom line.** A universal setup costs about **2.0-2.5×** the bytes of our best Groth16 verifiers. The fixed-G2
pairing is genuinely cheaper than Groth16's: about 9.4M against 17.9M for the Miller events. But PLONK's MSM over 9 proof
points with full-size scalars dominates. That is not a negative result for feasibility: everything fits today's
standard rules in one transaction. It is a negative result for "PLONK is as cheap as Groth16 on CashVM".

## 9. Alternatives weighed and negative results

- **snarkjs PLONK (Keccak transcript).** CashVM has no Keccak. Emulating Keccak-f[1600] with 64-bit lanes needs about
  24 rounds × ~600 VM operations of ~110 op, i.e. **about 1.6M op per permutation (unmeasured, rough)**.
  - A snarkjs PLONK transcript (VK, public inputs, about 15 permutations at a 136-byte rate) would add about 24M op,
    roughly 30 KB at 800 op/B. Its MSM is similar to gnark's.
  - gnark's SHA-256 transcript costs 21k op: about 1,000 times less. **gnark is the right prover.**
- **fflonk / shplonk-style verifiers** need only about 3-4 MSM terms and would cut the dominant cost. gnark does not
  implement them (gnark v0.16.4 has PLONK only). Not pursued: it would need a non-standard prover, against the "standard
  tooling" goal.
- **Fully baked line coefficients** or an **on-chain fixed-G2 walk**: worse (§5.2).
- **3-event chunks** without folding: 22 states but NQ 144 (8.8 KB vs 8.3 KB). Same op. Not better.
- **Folding only some fixed bases.** Partial folding helps only if the degree stays at NQ 60 (≤ 3 bases with 1-event
  chunks). The 65-state cost then outweighs it (A-gtfold rows of the model table).
- **Fixed-base comb tables** (precomputed multiples per window position): about 100 op/B, far below the useful rate.
  Signed w = 4-5 tables are the optimum.
- **Moving variable-base scalars into GT** (`e(sW, [1]_2) = e(W, [1]_2)^s` with GT-GLS). This would need a witnessed
  representative of `Miller(W, [1]_2)` per proof point. Proving that representative costs a separate 33-65-state chain
  per point. Rejected.
- **BSB22 commitments** (`api.Commit`, used by gnark's range-check and lookup gadgets). Not in v1. Each commitment adds:
  - a proof point (variable full scalar, ~2.7M op-equivalent);
  - a VK point (fixed, folded, ~1.2M);
  - a claimed value;
  - a Lagrange term (into the same batch inverse);
  - gnark's hash-to-field: RFC 9380 expand_message_xmd over SHA-256, 3-4 native SHA-256 calls.
  So roughly +4-5 KB per commitment.
- **nPI and n.** Each public input adds 32 B and about 20k op. The circuit size enters only through log2(n) squarings, so
  the verifier is effectively independent of circuit size: one code blob for every circuit, with per-circuit VK
  constants of 672 B, plus 3.5 KB of GT-GLS R constants when folding.

## 10. Open risks and what the build must verify

- **The MSM loop is the least-calibrated part.** The kernels are VM-measured. The loop, lookup and digit-handling
  overhead (3.75k + 0.9k per addition) is an estimate. A 10% error moves the totals by about 2-3 KB.
- **Code size.** Estimated at 6.0 KB (±1.5 KB). SI-GLS code is 4.06 KB; this adds the MSM, the Fr formulas and the
  transcript.
- **Λ witness (plan B) and GT-GLS on computed scalars** are new compositions. They need written arguments and an
  independent soundness review. Plan A with the 3-base fold is the fallback without the t-fold.
- **Completeness edge cases.** These cause rejection only, all with negligible honest probability:
  - infinity points;
  - `ζ = ω^i`;
  - `P_left` or `P_right = O`;
  - exceptional MSM additions.
  The sweep must include many proofs and circuits.
- **Liveness.** n_q varies up to the cap and witness-stream lengths vary. Sizes vary per proof by up to 2-3 KB.
  Multi-input layouts need prover-sized filler, as SI-MX3 does.
- **The SRS.** The probe uses gnark's `test/unsafekzg` (toxic waste known). A deployment must use a ceremony SRS whose
  `[x]_2` is baked into the second slope pile. Example: Aztec Ignition via consensys/gnark-ignition, or a perpetual
  powers of tau import.

## 11. Reproduce

```sh
# kernels (VM): needs this checkout's node_modules (pnpm install --offline) and the groth16_cashscript modules
# sound-si-gls/{asm,math,protocol,script}.mjs, densless-recovered/public-fixtures.json and
# sound-bn254-native/prototypes/vm26.mjs, reachable at $G16 with a node_modules that resolves @noble/curves 2.2.0 and
# @bitauth/libauth 3.1.0-next.8 (here: a copy of those files plus a node_modules symlink, run without --preserve-symlinks)
G16=<that dir> nice node research/plonk-kzg/kernels.mjs > research/plonk-kzg/kernels.json
node research/plonk-kzg/model.mjs [nPI=2] [log2n=16] > research/plonk-kzg/model-output.txt   # also writes model-result.json
cd research/plonk-kzg/gnark-ref && GOMAXPROCS=4 nice go run . > fixture.json                  # gnark v0.16.4 reference verifier
```
