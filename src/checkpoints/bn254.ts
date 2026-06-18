// Off-chain BN254 Groth16 reference for the verifier checkpoints — the "golden"
// intermediate values our BCH verifier will be graded against — via @noble/curves.
//
//   checkpoint #1  vk_x = IC[0] + Σ publicInputs[i]·IC[i+1]            (a G1 point)
//   checkpoint #2  the Miller-loop -> final-exponentiation boundary:
//                  the pre-final-exp product
//                    e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta)    (an Fp12),
//                  where finalExponentiate(it) == 1 iff the proof verifies.
//
// Note: the checkpoint #1 value is a G1 affine (x,y) in Fp — representation-free,
// so it can be asserted exactly across implementations. The checkpoint #2 Fp12 is
// in noble's tower basis; to grade another implementation against it, that
// implementation must use the same Fp12 basis (or compare via finalExponentiate).
import { bn254 } from '@noble/curves/bn254.js';

const { G1, G2, pairingBatch } = bn254;
const Fp12 = bn254.fields.Fp12;

export type G1Pt = typeof G1.Point.BASE;
export type G2Pt = typeof G2.Point.BASE;

export interface VerifyingKey {
  alpha: G1Pt;
  beta: G2Pt;
  gamma: G2Pt;
  delta: G2Pt;
  /** IC[0..n], length = number of public inputs + 1 */
  ic: G1Pt[];
}
export interface Proof {
  a: G1Pt;
  b: G2Pt;
  c: G1Pt;
}

/** checkpoint #1: public-input commitment point on G1. */
export const computeVkX = (ic: G1Pt[], publicInputs: bigint[]): G1Pt => {
  if (ic.length !== publicInputs.length + 1) {
    throw new Error(`IC length ${ic.length} must equal publicInputs.length ${publicInputs.length} + 1`);
  }
  let acc = ic[0]!;
  for (let i = 0; i < publicInputs.length; i++) {
    acc = acc.add(ic[i + 1]!.multiply(publicInputs[i]!));
  }
  return acc;
};

/** canonical "x,y" hex of a G1 point (affine) — representation-free identity. */
export const g1Hex = (p: G1Pt): string => {
  const a = p.toAffine();
  return `${a.x.toString(16)},${a.y.toString(16)}`;
};

const groth16Pairs = (vk: VerifyingKey, proof: Proof, vkX: G1Pt) => [
  { g1: proof.a.negate(), g2: proof.b },
  { g1: vk.alpha, g2: vk.beta },
  { g1: vkX, g2: vk.gamma },
  { g1: proof.c, g2: vk.delta },
];

/** checkpoint #2: the pre-final-exponentiation Fp12 product (Miller boundary). */
export const millerBoundary = (vk: VerifyingKey, proof: Proof, vkX: G1Pt) =>
  pairingBatch(groth16Pairs(vk, proof, vkX), false);

export const fp12Hex = (f: ReturnType<typeof millerBoundary>): string =>
  Buffer.from(Fp12.toBytes(f)).toString('hex');

/** full Groth16 check: the pairing product, after final exponentiation, equals 1. */
export const verify = (vk: VerifyingKey, proof: Proof, publicInputs: bigint[]): boolean => {
  const vkX = computeVkX(vk.ic, publicInputs);
  return Fp12.eql(pairingBatch(groth16Pairs(vk, proof, vkX), true), Fp12.ONE);
};

/** Both checkpoint golden values plus the end-to-end verdict, for one instance. */
export const checkpointsFor = (vk: VerifyingKey, proof: Proof, publicInputs: bigint[]) => {
  const vkX = computeVkX(vk.ic, publicInputs);
  const miller = millerBoundary(vk, proof, vkX);
  return {
    vkX,
    vkXHex: g1Hex(vkX), // checkpoint #1 golden
    miller,
    millerHex: fp12Hex(miller), // checkpoint #2 golden
    verified: Fp12.eql(Fp12.finalExponentiate(miller), Fp12.ONE),
  };
};
