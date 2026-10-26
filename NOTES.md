# genpow promotions: review notes (2026-10-27)

This is a report only. Nothing was merged and nothing was posted to GitHub.

Snapshot: bench origin/main `37e35f2`, source origin/main `838431c` (detached worktree at `.src/`, not committed).
Policy: constructive only. I checked owners and domains, and ran ordinary rejection tests. I constructed no forgeries and no accepted variants.

## Recommendation

| id | current | recommend | reason |
|---|---|---|---|
| bch-groth16-singleton-genpow | unreviewed | **reviewed** | Every value has an owner and every domain is checked: canonical coordinates, curve, BN G2 psi test, Fr inputs. MSM and Miller handle neutral points completely. The shipped bytes equal the reviewed bytes. |
| bch-groth16-bls12381-singleton-genpow | unreviewed | **reviewed, with the cofactor-equivalent caveat in the reason** | Soundness rests on an endpoint argument: every pairing operand is projected on-chain into its order-r component. Our reviewed BLS singleton accepts the same kind of argument for A and C. The only extra effect is malleability of B, which is not a soundness gap. |

Both stay native HOLD and BCH-incompatible (op-cost). The new status changes no compatibility claim.

## 1. Bytes and gates

| | BN genpow | BLS genpow |
|---|---|---|
| lockingOK on main (both vector files) | 4,320 B, sha256 `022fea806c85f8008990ae244b80b87353f5aedd5555eb369cef63a28269f483` | 5,675 B, sha256 `6b36b9febaa033b366672c7a6a9d01dd604402d77cf7aced0a001a173292ad3f` |
| rebuilt from source on main | `build.mjs` gives the same hash in both vector files | `cofactorPoints()` from `cofactor-points.mjs` gives the same hash |
| source-file hashes in provenance | match verifier.asm, build.mjs and both fixtures on main | match all 9 .mjs files on main |
| provenance revision | asm and builder hashes (no git rev, by design) | `sourceRevision b7338ea`, an ancestor of main. This fixes WF2 §3 nit 1 (it used to record `sourceBaseRevision 5aa48d8`) |
| `pnpm benchmark genpow` (27.5 min run) | PASS: valid accepted, invalid rejected, 4/4 distinct proofs, 9/9 public-input mutations rejected; 4,528 B, 5,519,652,719 op-cost, `no: op-cost` | PASS: same gates; 5,880 B, 25,609,641,017 op-cost, `no: op-cost` |
| results.json on main | 4,613 (4,528 + 85), op-cost 5,519,652,719, unreviewed | 5,965, unreviewed |

These are the same hashes REVIEW-WF2 §2/§3 reviewed, so the shipped artifact is the reviewed artifact.

## 2. BN254 genpow: constructive re-check of the shipped asm

Owners, all checked by reading `singleton/bn254/genpow-reconstructed/verifier.asm`:
- **Public inputs n0, n1:** the main prefix checks `min >= 0` and `max < P - 6x^2 = r`. The VM enforces minimal number encoding.
- **Coordinates:** `0 <= v < P` on depths 6, 5, 4, 3, 2 and 0 (A.x, the four B limbs, C.x). The parities at depths 7 and 1 are owned by the decoder.
- **A, C (`g1_decompress`):**
  - Parity 2 requires x = 0 and gives (0,0).
  - Otherwise root = rhs^((P+1)/4), with an exact `root^2 == x^3+3` check (NUMEQUALVERIFY).
  - Finally `root % 2 == parity`. This rejects parities outside {0,1} and parity 1 for a zero root.
  - The BN G1 cofactor is 1, so a point on the curve is in G1.
- **B:**
  - If any limb is nonzero, there is an exact twist check (`y^2 == x^3 + b'`) and then [6x^2]B in Jacobian, starting at O. The add has complete O, doubling and negation branches.
  - The end check `X == psi(B).x * Z^2`, `Y == psi(B).y * Z^3` is exact. psi(Q) = [6x^2]Q is the standard BN G2 membership test.
  - Degenerate walks: #E'(Fp2) = r(2p - r) is odd, so there is no 2-torsion. So no Jacobian O reached by these formulas has X = Y = 0: from (0:1:0), doubling keeps Y != 0, and a P + (-P) add gives X3 = r^2 != 0. A walk that collapses to O therefore fails the end check against a finite psi(B). The final comparison never holds vacuously.
  - With four zero limbs, B = O. The finite checks are skipped. (0,0) is not on the twist, so this encoding is unambiguous.
- **vk_x:**
  - Each term is [n_i]IC_i (outline_42, 254-bit loop, scalars < r).
  - outline_32 is complete: it returns P if Q.Z = 0 (the orig5 fix), returns Q if P.Z = 0, doubles when U1 = U2 and S1 = S2, and gives H = 0, so Z = 0, for P + (-P). That makes the sum IC0 + [n0]IC0' + [n1]IC1' exact for every input.
  - The affine step uses Z^(p-2), so Z = 0 gives (0,0), the canonical neutral.
- **Miller (outline_40):** if P = (0,0) or all Q limbs are 0, it returns the Fp12 unit (outline_62). Otherwise it runs the original loop. I checked the stack depths: Px/Py at depths 4/5, then Q at depths 0..3 after one extra item. Every pairing goes through outline_40.
- **Final step:** the exponent (P^12 - 1)/R is derived exactly from BN_X, and the result is compared limb by limb against Fp12 ONE.

So every value the accept decision depends on is a VK constant, computed on-chain, or fixed by an exact equation. Neutral A, B and vk_x take the correct group semantics (e(O, ·) = 1). I found no unowned value.

Rejection runs (`tools/genpow-reject.mts bn [full]`, loosened VM, all rejected):
- Public input + r, and -1. Both parities set to 2, 3 and -1. Each coordinate + p and - p: 22 cases.
- Full runs: honest proof ACCEPT (5,519,652,719, the sanity check). Then A neutral (parity 2, x 0), C neutral, and B = four zero limbs. All three reach the final equation (about 5.3B op-cost) and are rejected there, which exercises the new neutral branches. This addresses WF2 §2 nit 1.

## 3. BLS12-381 genpow: constructive re-check

Owners (`leader-recovered/{cofactor-points,complete-points,point-checks,subgroup,compact}.mjs`):
- **Public inputs:** the `rangeCheck` prefix enforces min >= 0 and max < x^4 - x^2 + 1 = r.
- **decompressG1:** x is in [0,p), the sign is in {0,1}, and there is an exact `root^2 == x^3+4` check.
- **decompressG2 (`completeG2Decoder`):**
  - x0 and x1 are in [0,p), and the sign and norm bits are in {0,1}.
  - The u = 0 chart is complete.
  - It ends in two exact residual checks, `re^2 - im^2 == a` and `2 re im == b`, so y^2 = rhs exactly on the M-twist.
  - The VK G2 constants go through the same decoder with fixed bits.
- **vk_x:** a Shamir double-and-add (255 bits) from (0,1,0) with `g1Add`. g1Add has a Z = 0 branch, a doubling branch for equal points, and a general formula, which gives Z = 0 for P + (-P). Then it adds IC0 and inverts Z, so Z = 0 gives (0,0). The sum is exact for every input.
- **millerLoop wrapper:** both operands are first projected: projectG1 with k1 = h1·(h1^-1 mod r) (381 bits) and projectG2 with k2 = h2·(h2^-1 mod r) (761 bits). I recomputed both:
  - h1 equals the standard G1 cofactor, and h1·r = p + 1 - t.
  - h2 equals the standard G2 cofactor constant `0x5d543a95…7238e5`.
  - k ≡ 1 (mod r) and k ≡ 0 (mod h) for both.
  - Both cofactors are odd, so there is no 2-torsion and no Y = 0 doubling.
- **Projection arithmetic:**
  - Jacobian double-and-add from the leading bit, with complete add (R = O gives Q, equal points double, P + (-P) gives Z = 0).
  - The affine step maps Z = 0 to zeros. projectG1 passes (0,0), the internal vk_x neutral, through unchanged.
- **Neutral test after projection:** I checked the stack depths. Px, Py are tested at depths 4 and 5 (+1). Qx0, Qx1, Qy0, Qy1 at 0 through 3 (+k). If P = O or Q = O, it returns stackSequence51 = Fp12 ONE.
- **Final step:** the exponent (p^12 - 1)/r is derived on-chain from the seed, and the 12-limb comparison against ONE is exact.

Endpoint argument (soundness): with the decoders exact, each input point P lies in E(Fp) or E'(Fp2) = G_r ⊕ T_h, with gcd(h, r) = 1. [k]P is exactly its G_r component. The accept decision therefore equals the Groth16 equation evaluated on (π(A), π(B), π(C)), with VK points fixed by projection and vk_x in G1. Any accepted (A, B, C) yields a standard valid proof (π(A), π(B), π(C)) for the same public inputs, and the reduction computes it efficiently from public data. So knowledge soundness transfers, and every value has an owner. The policy's "G2 subgroup (or an endpoint argument) for B" is met by the endpoint argument.

What it does not give:
- Proof uniqueness: B + T2 for T2 in the G2 cofactor torsion, and A + T1, C + T1, give the same projected proof.
- Rejection of non-subgroup B.
- The `proofDomain` provenance field and the README already say so.

Comparison with our reviewed `bch-groth16-bls12381-singleton` (groth16.cash):
- That entry checks psi(B) == [x]B strictly, fused with a Z != 0 guard. B is unique.
- It does not check A or C for G1 membership and relies on the same cofactor argument: B is in G2 and gamma/delta are fixed, so a G1 torsion component pairs to 1. Its README documents A/C malleability as "malleability only".
- So the already-accepted standard for "reviewed" includes cofactor-equivalence on G1. genpow extends that to G2, and projects explicitly rather than relying on pairing annihilation.
- The difference is malleability, not soundness. Applications should not use proof bytes as identifiers anyway, since Groth16 is re-randomizable.
- I therefore think "reviewed" is appropriate, provided the reason text states the cofactor-equivalent G1/G2 domain plainly, as below.
- If the maintainer wants "reviewed" for BLS to mean strict G2, keep this entry unreviewed and say why. That is a policy choice, not a finding.

Rejection runs (`tools/genpow-reject.mts bls`, 24 cases, all rejected at the decoders or the range guard):
- Public input + r, and -1.
- Every sign or norm bit set to 2, 3 and -1.
- Every coordinate + p and - p.

These exercise the decoders only. I did not construct any accepted non-subgroup variant (policy).

## 4. Proposed REVIEW_STATUS text (not applied)

```ts
  // genpow singletons: corrected successors (source #30/#31, bench #47/#48) reviewed in
  // REVIEW-WF2 §2/§3; shipped bytes re-confirmed 2026-10-27 (notes: verifier.cash work/genpow-promotions/NOTES.md).
  'bch-groth16-singleton-genpow': {
    status: 'reviewed',
    reason: 'independent review 2026-10-26/27 of the corrected 4,320 B program (sha 022fea80…): canonical coordinate and Fr guards, exact curve and psi G2 checks, complete MSM identity addition and neutral Miller units verified; no soundness gap. Native resource HOLD (op-cost).',
    refs: [...FINDINGS, `${SRC}/pull/30`, `${BENCH}/pull/47`, `${SRC}/blob/main/singleton/bn254/genpow-reconstructed/README.md`],
  },
  'bch-groth16-bls12381-singleton-genpow': {
    status: 'reviewed',
    reason: 'independent review 2026-10-26/27 of the corrected 5,675 B program (sha 6b36b9fe…): canonical decoders with exact curve residuals, complete group operations, and on-chain r-component projection of every G1/G2 pairing operand (cofactor-equivalent domain: soundness holds, but A, B and C are malleable by cofactor torsion and non-subgroup B is not rejected). Native resource HOLD (op-cost).',
    refs: [...FINDINGS, `${SRC}/pull/31`, `${BENCH}/pull/48`, `${SRC}/blob/main/singleton/bls12-381/leader-recovered/README.md`],
  },
```
Move both entries out of the "withdrawn" comment block in review-status.ts.

## 5. Consequences and leftover nits (non-blocking)

- **Frontier:**
  - BN genpow 4,613 becomes the smallest reviewed full BN verifier.
  - BLS genpow 5,965 becomes the smallest reviewed BLS singleton, ahead of opcode-optimized at 5,999.
  - Both are not BCH-compatible. Check that the leaderboard shows the HOLD and the BLS "cofactor-equivalent G2" note (WF2 §3 issue 2).
  - Regenerate results.json after the status change (full `SKIP_IMPLS='' pnpm benchmark:json`).
- **Missing vectors:** neither entry ships vectors for the neutral branches or the decoder rejections. The bench shows "input validation NOT DEMONSTRATED" for BLS. The cases in `tools/genpow-reject.mts` could become `invalidInputs` runs.
- **Dead code:** `subgroupDeclarations` is gone, but `membership()` in `subgroup.mjs` is still unused.
- **Cost (WF2 §3 issue 4):** projecting the fixed VK G2 points is wasted work. A psi check on B would be cheaper and stricter. This is an author choice and not a status blocker.

The bench gates pass for both. Their 'input validation NOT DEMONSTRATED' line is a single-tx harness limitation: it ships no invalidInputs. The decoder checks are covered by the rejection runs above.
