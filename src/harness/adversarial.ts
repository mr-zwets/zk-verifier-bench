// Synthesis primitives for adversarial Groth16 curve points (off-curve G1/G2, on-curve
// off-subgroup G2) plus the decl-order witness codec.
//
// IMPORTANT — this is NOT yet wired into input-validation grading, and naive use does NOT
// work as a single-tx test. Swapping a proof point for a bad value in a FULL (single-tx)
// verifier makes the verification equation e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) ≠ 1, so the
// verifier rejects it REGARDLESS of whether it performs on-curve / subgroup checks —
// rejection therefore does not discriminate a validating verifier from a non-validating one
// (e.g. singleton/bls12-381/groth16.cash has no checks at all yet would still reject these).
// Input validation can only be DEMONSTRATED by rejecting a bad point at an ISOLATED check
// (a chunked g2check stage), which is what Scenario.invalidInputs supplies.
//
// FUTURE (the meaningful single-tx test): construct an off-subgroup B′ that STILL satisfies
// the verification equation (a subgroup-malleability point B′ = B + S with e(-A,S) = 1), so
// that a verifier accepts it iff it omits the subgroup check. That construction is
// proof-dependent and not implemented here; these primitives (off-subgroup search + witness
// codec) are the building blocks for it.
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bigIntToVmNumber, vmNumberToBigInt } from '@bitauth/libauth';

// ---- decl-order witness codec ----
// Witnesses push their args reversed (last decl arg pushed first), each a minimal
// VM-number data push; parse reverses back to decl order. Matches the singleton
// builders' encoding so a re-encoded witness is byte-identical to a hand-built one.
const pushInt = (n: bigint): number[] => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return [0x00];
  if (d.length === 1 && d[0]! >= 1 && d[0]! <= 16) return [0x50 + d[0]!];
  if (d.length === 1 && d[0]! === 0x81) return [0x4f];
  if (d.length <= 75) return [d.length, ...d];
  if (d.length <= 255) return [0x4c, d.length, ...d];
  return [0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d];
};
export const parseWitness = (b: Uint8Array): bigint[] => {
  const vals: bigint[] = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i++]!;
    if (op === 0x00) vals.push(0n);
    else if (op === 0x4f) vals.push(-1n);
    else if (op >= 0x51 && op <= 0x60) vals.push(BigInt(op - 0x50));
    else {
      let len: number;
      if (op <= 75) len = op;
      else if (op === 0x4c) len = b[i++]!;
      else { len = b[i]! | (b[i + 1]! << 8); i += 2; }
      vals.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false }) as bigint);
      i += len;
    }
  }
  return vals.reverse(); // -> decl order
};
export const encodeWitness = (args: bigint[]): Uint8Array =>
  Uint8Array.from([...args].reverse().flatMap((a) => pushInt(a)));

// ---- curve registry (the G2 twist `b` for the off-subgroup search) ----
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const curveOf = (field: string): { Fp2: any; G2: any; b2: any } | null => {
  if (field === 'BN254') {
    const Fp2 = bn254.fields.Fp2;
    return { Fp2, G2: bn254.G2, b2: Fp2.div(Fp2.fromBigTuple([3n, 0n]), Fp2.fromBigTuple([9n, 1n])) }; // D-twist b = 3/(9+u)
  }
  if (field === 'BLS12-381') {
    const Fp2 = bls12_381.fields.Fp2;
    return { Fp2, G2: bls12_381.G2, b2: Fp2.fromBigTuple([4n, 4n]) }; // M-twist b = 4(1+u)
  }
  return null;
};

/** An on-curve but OFF-SUBGROUP G2 point [xc0,xc1,yc0,yc1] for `field` — the point a
 * naive verifier accepts but a subgroup check rejects. Searches small x until the twist
 * equation has a root whose point is on-curve yet not torsion-free (assertValidity, which
 * enforces the prime-order subgroup, throws). null if the curve is unknown / none found. */
export const offSubgroupG2 = (field: string): [bigint, bigint, bigint, bigint] | null => {
  const c = curveOf(field);
  if (!c) return null;
  const { Fp2, G2, b2 } = c;
  for (let i = 1n; i < 2000n; i++) {
    const x = Fp2.fromBigTuple([i, 0n]);
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2); // x^3 + b
    let y;
    try { y = Fp2.sqrt(rhs); } catch { continue; }
    if (!Fp2.eql(Fp2.sqr(y), rhs)) continue; // sqrt exists -> on the twist curve
    try { G2.Point.fromAffine({ x, y }).assertValidity(); continue; } catch { /* on-curve, NOT torsion-free */ }
    return [x.c0, x.c1, y.c0, y.c1];
  }
  return null;
};

/** Decl-order limb indices of the G1 (2 limbs: x,y) and G2 (4 limbs: x.c0,x.c1,y.c0,y.c1)
 * proof points in a single-tx verifier's unlocking witness. */
export interface WitnessLayout {
  g1: number[][];
  g2: number[][];
}
export interface AdversarialRun {
  label: string;
  args: bigint[];
}

/** Mint adversarial witnesses from a VALID decl-order arg vector: an off-curve G1 (perturb
 * a G1 y so y^2 != x^3+b), an off-curve G2 (perturb a G2 limb), and an on-curve OFF-SUBGROUP
 * G2 point. Uses the FIRST declared G1/G2 slot. The off-subgroup run is omitted when the
 * curve is unknown (so an exotic curve still gets the two on-curve checks). */
export const synthAdversarial = (field: string, valid: bigint[], layout: WitnessLayout): AdversarialRun[] => {
  const runs: AdversarialRun[] = [];
  const g1 = layout.g1[0];
  const g2 = layout.g2[0];
  if (g1) {
    const a = valid.slice();
    a[g1[1]!] = a[g1[1]!]! + 1n; // bump A.y off the curve
    runs.push({ label: 'off-curve A (G1)', args: a });
  }
  if (g2) {
    const a = valid.slice();
    a[g2[2]!] = a[g2[2]!]! + 1n; // bump B.y off the curve
    runs.push({ label: 'off-curve B (G2)', args: a });
  }
  const sub = offSubgroupG2(field);
  if (g2 && sub) {
    const a = valid.slice();
    a[g2[0]!] = sub[0];
    a[g2[1]!] = sub[1];
    a[g2[2]!] = sub[2];
    a[g2[3]!] = sub[3];
    runs.push({ label: 'off-subgroup B (G2)', args: a });
  }
  return runs;
};

/** Build adversarial single-step runs for a single-tx verifier: parse the valid witness,
 * synthesize bad-point variants, and splice each back into a copy of the valid step. */
export const synthInputRuns = (
  field: string,
  validStep: { lockingBytecode: Uint8Array; unlockingBytecode: Uint8Array; label: string },
  layout: WitnessLayout,
): { label: string; lockingBytecode: Uint8Array; unlockingBytecode: Uint8Array }[] =>
  synthAdversarial(field, parseWitness(validStep.unlockingBytecode), layout).map((r) => ({
    ...validStep,
    label: `${validStep.label} [adversarial: ${r.label}]`,
    unlockingBytecode: encodeWitness(r.args),
  }));
