# BN254 Groth16 PAIRING milestone — checker, vectors, and Fp12-basis finding

This documents the oracle/checker for the **pairing** milestone (Miller-loop →
final-exponentiation), so a future in-script BN254 pairing can be graded
bit-for-bit, exactly as `vkx_ref.py` / `vkx_vectors.json` grade vk_x.

It does NOT implement the in-script Miller loop / Fp12 tower — only the checker,
the deterministic vector generator, the cross-validation, and the basis analysis
the in-script implementation will need.

## Files

| file | role |
|------|------|
| `src/checkpoints/bn254.ts` | the existing noble grading functions (computeVkX, millerBoundary, verify, checkpointsFor) — unchanged |
| `src/checkpoints/gen-pairing-vectors.ts` | deterministic generator of a **non-degenerate** valid Groth16-form instance + golden values → `pairing-vectors.json` |
| `src/checkpoints/gen-pairing-vectors.py` | **independent** py_ecc.bn128 cross-validation of the SAME instance |
| `src/checkpoints/pairing-vectors.json` | the instance (vk/proof/inputs as affine coords) + golden values |
| `src/checkpoints/pairing-check.ts` | the CHECKER/runner — grades a candidate's (vk_x, miller bytes, verdict) against golden; self-tests against the noble reference |
| `src/checkpoints/probe-fp12-basis.ts` | empirical probe confirming noble's tower constants + byte layout |

Run:

```
npx tsx src/checkpoints/gen-pairing-vectors.ts     # (re)generate vectors (deterministic)
python src/checkpoints/gen-pairing-vectors.py      # cross-validate in py_ecc
npx tsx src/checkpoints/pairing-check.ts           # the checker self-test
npx tsx src/checkpoints/probe-fp12-basis.ts        # basis probe
```

## The instance (no trusted setup needed)

Every point is a **known multiple** of its generator, so the verification
equation is solved in the exponent over the scalar field `Fr` (order `r`):

```
vk.alpha = [alpha_s]·G1                         vk.IC[i] = [ic_s[i]]·G1   (IC[0..2] => 2 public inputs)
vk.beta  = [beta_s]·G2, gamma=[gamma_s]·G2, delta=[delta_s]·G2   (all DISTINCT, delta invertible)
proof.A  = [a_s]·G1,  proof.B = [b_s]·G2,  proof.C = [c_s]·G1
vk_x     = IC[0] + Σ inputs[i]·IC[i+1]   =>   vkx_s = ic_s[0] + Σ inputs[i]·ic_s[i+1]  (mod r)
```

The Groth16 pre-final-exp product is
`e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta) = e(G1,G2)^E` with
`E = −a_s·b_s + alpha_s·beta_s + vkx_s·gamma_s + c_s·delta_s`. `finalExp → 1` iff
`E ≡ 0 (mod r)`, so we solve

```
c_s = (a_s·b_s − alpha_s·beta_s − vkx_s·gamma_s) · delta_s⁻¹   (mod r).
```

Scalars come from a fixed SplitMix64 seed → the output is byte-for-byte
reproducible. The instance is genuinely **non-degenerate** (unlike the old
`demo.ts`, where beta=gamma=delta=Q and the sum collapsed to O): beta/gamma/delta
are distinct G2 points, vk_x actually depends on the public inputs, and the
pre-final-exp Fp12 product is **not** the identity — it is a real Miller boundary.

The **invalid** instance reuses the same vk/proof but increments public input[1]
by 1 (mod r), which changes vk_x and makes `E ≢ 0`, so `verify == false`.

### Cross-validation (both oracles agree)

| invariant | noble | py_ecc.bn128 |
|-----------|:-----:|:------------:|
| p, r | ✓ | ✓ (identical) |
| vk_x affine (x,y) | golden | **matches noble exactly** |
| valid: product == 1 / finalExp == 1 | ✓ | ✓ |
| invalid (tampered input) rejected | ✓ | ✓ |

py_ecc reconstructs the instance from the **scalars** (not noble's serialized
points), so the agreement guards against a noble-specific bug. There was **no
noble-vs-py_ecc disagreement**.

## THE Fp12-basis finding (the key output)

### noble's bn254 Fp12 tower (confirmed by source + `probe-fp12-basis.ts`)

A **2-over-3-over-2** tower:

| level | relation | constant |
|-------|----------|----------|
| Fp2 = Fp[u]/(u²−β) | **u² = −1** (β = −1) | confirmed: u² = (p−1, 0) |
| Fp6 = Fp2[v]/(v³−ξ) | **v³ = ξ = 9 + u** | confirmed: `Fp2.NONRESIDUE = (9, 1)`, v³ = (9,1) |
| Fp12 = Fp6[w]/(w²−γ) | **w² = γ = v** | confirmed: w² == v |

- Fp2 Frobenius coefficient (`u^p = −u`): `FROBENIUS_COEFFICIENTS = [1, p−1]`.
- Curve: G1 `y² = x³+3`; G2 D-type **divisive** twist `y² = x³ + 3/(9+u)`,
  `b2 = (19485874751759354771024239261021720505790618469301721065564631296452457478373,
  266929791119991161246907387137283842545076965332900288569378510910307636690)`.
- Ate loop size `6x+2` with seed `x = 4965661367192848881` (positive).

### noble's `Fp12.toBytes` serialization (confirmed empirically)

384 bytes = **12 × 32-byte big-endian** Fp limbs, in nested tower order
`c0,c1` (Fp12) → `c0,c1,c2` (Fp6) → `c0,c1` (Fp2):

```
[ c0.c0.c0, c0.c0.c1,  c0.c1.c0, c0.c1.c1,  c0.c2.c0, c0.c2.c1,
  c1.c0.c0, c1.c0.c1,  c1.c1.c0, c1.c1.c1,  c1.c2.c0, c1.c2.c1 ]
```

Each limb is `Fp.toBytes` = 32-byte **big-endian** (`Fp.isLE === false`). `Fp12.ONE`
→ first limb `1`, rest `0`. The G1 affine for checkpoint #1 is `Fp.toBytes`
(32B BE) for x and y.

### Standard arkworks / py_ecc convention

- The **tower shape** noble uses (Fp2 = Fp[u]/(u²+1), ξ = 9+u, w² = v) is the
  **same** standard BN254 tower as arkworks and as py_ecc's *documented* tower.
- **BUT py_ecc represents Fp12 as a FLAT degree-12 power-basis extension**, not as
  a 2-over-3-over-2 tower of objects. Its modulus polynomial is
  `Fp[w]/(w¹² − 18·w⁶ + 82)` (`fq12_modulus_coeffs = (82,0,0,0,0,0,−18,0,0,0,0,0)`),
  and an `FQ12` is a 12-vector of coefficients in the power basis `{1, w, …, w¹¹}`.
  This is a **different basis** from noble's nested-tower coordinate vector — the
  two are isomorphic fields but the 12 coordinates do **not** line up, so the
  serialized bytes of the same GT element differ between noble and py_ecc.
  (`probe-fp12-basis.ts` shows noble's layout; `gen-pairing-vectors.py`'s modulus
  inspection shows py_ecc's flat power basis.)

### Conclusion + recommendation

- **vk_x (checkpoint #1) is representation-free** (a G1 affine x,y in Fp) → grade
  it **exactly** in any implementation. Done.
- **Miller boundary (checkpoint #2)** is **basis-dependent**. There are two
  gradable paths:

  **(a) Match noble's exact basis + serialization in-script** — then `millerHex`
  is gradable byte-for-byte. The in-script Fp12 must use: Fp2 `u²=−1`; Fp6
  `v³=9+u`; Fp12 `w²=v`; 12 coords serialized big-endian in the nested
  `c0.c0.c0 … c1.c2.c1` order above. This is achievable (it is the standard
  arkworks tower) but requires the implementation to commit to noble's exact
  coordinate/byte order rather than py_ecc's flat power basis.

  **(b) If matching noble's byte-basis in-script is impractical**, grade
  checkpoint #2 **only via `finalExponentiate == 1`** (basis-independent: the
  pairing verdict does not depend on the intermediate Fp12 representation), plus
  checkpoint #1 (vk_x, representation-free). The product of the four
  final-exponentiated pairings equalling 1 is exactly the verification equation
  and is identical across noble, py_ecc, and any correct in-script tower.

  **Recommendation:** target **(a)** — adopt noble's exact tower + serialization
  so checkpoint #2 grades directly on the carried Fp12 accumulator — but keep
  **(b)** as the guaranteed fallback gate. The checker (`pairing-check.ts`,
  `gradeCandidate(..., sameBasis)`) implements both: `sameBasis=true` grades the
  Miller bytes exactly; `sameBasis=false` falls back to the finalExp verdict.

## Milestone / checkpoint definition for a future multi-tx pairing impl

| # | checkpoint | carried/asserted value | grading |
|---|-----------|------------------------|---------|
| 1 | **vk_x** = IC[0] + Σ inputs·IC | G1 affine (x,y in Fp) | EXACT vs `golden.vkXHex` (representation-free) — **done** |
| 2 | **Miller boundary** = e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) | Fp12 (384B, noble basis) | EXACT vs `golden.millerHex` if same basis, else via #3 |
| 3 | **verify** = finalExponentiate(boundary) == 1 | boolean | EXACT vs `golden.verified` (basis-independent) |

**Per-step structure the in-script pairing will likely need** (mirrors the
existing chunked vk_x design, where state is carried as `hash256(state)` in the
NFT commitment):

- The **Fp12 accumulator is the carried state** — ~12 Fp coordinates (≈384 bytes,
  the `f` in the Miller loop). Each transaction commits `hash256(f ‖ loop-state)`;
  step `i`'s outgoing commitment == step `i+1`'s incoming, exactly like
  `vkx-chunked.ts`.
- The Miller loop is `6x+2 ≈ 65` doublings (each: `f = f² · line(R,R,P)`, `R = 2R`)
  with adds where the NAF/bit is set, over the four pairs batched (or four
  separate accumulators multiplied at the boundary). Plus the two Frobenius
  line steps (`Q1`, `−Q2`) at the end of the ate loop.
- Then **final exponentiation** (`(p¹²−1)/r`, the hard part via the
  Fuentes-Castañeda / noble `_cyclotomicExp` ladder) reduces the boundary Fp12 to
  the GT element; assert `== 1`.
- Likely sub-checkpoints to ramp difficulty: Fp2 mul → Fp6/Fp12 mul → one Miller
  iteration → full Miller (**checkpoint #2**) → final exp → **verify (#3)**.

The carried Fp12 should be serialized in noble's byte order (above) if pursuing
grading path (a), so the committed state hashes match the golden Fp12 bytes
directly.
