// Groth16 PAIRING-milestone CHECKER / oracle. Loads pairing-vectors.json (the
// golden values produced by gen-pairing-vectors.ts and cross-validated by
// gen-pairing-vectors.py) and grades a candidate pairing implementation's three
// checkpoints, bit-for-bit, mirroring how src/bch/vkx-chunked.ts grades vk_x.
//
//   checkpoint #1  vk_x  = IC[0] + Σ inputs[i]·IC[i+1]   (G1 affine; representation-free)
//   checkpoint #2  miller= e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta)  (pre-final-exp Fp12)
//   checkpoint #3  verify= finalExponentiate(miller) == 1                  (boolean verdict)
//
// GRADING RULES (see docs/pairing-checker.md):
//   #1 graded EXACTLY (G1 affine x,y hex — basis/representation-free).
//   #2 graded EXACTLY against millerHex IF the candidate uses noble's Fp12 tower
//      basis + byte serialization (2-over-3-over-2, w^2=v, v^3=9+u, u^2=-1, each
//      coord 32B big-endian, 12 coords in c0.c0.c0..c1.c2.c1 order). If matching
//      that byte-basis in-script is impractical, grade #2 ONLY via #3
//      (finalExp==1), which is basis-INDEPENDENT.
//   #3 graded as the boolean verdict.
//
// Since no in-script pairing impl exists yet, this self-tests against the NOBLE
// reference recomputed from the vectors, proving the checker + golden values are
// internally consistent and that a tampered candidate is rejected at each gate.
// Run: npx tsx src/checkpoints/pairing-check.ts
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { bn254 } from '@noble/curves/bn254.js';

import { checkpointsFor, type Proof, type VerifyingKey } from './bn254.js';

const here = dirname(fileURLToPath(import.meta.url));
const Fp2 = bn254.fields.Fp2;

interface G1J { x: string; y: string }
interface G2J { x: { c0: string; c1: string }; y: { c0: string; c1: string } }
interface Vectors {
  p: string;
  r: string;
  scalars: Record<string, string | string[]>;
  publicInputs: string[];
  vk: { alpha: G1J; beta: G2J; gamma: G2J; delta: G2J; ic: G1J[] };
  proof: { a: G1J; b: G2J; c: G1J };
  invalid: { note: string; publicInputs: string[] };
  golden: {
    vkXHex: string;
    vkXAffine: G1J;
    millerHex: string;
    millerBytes: number;
    verified: boolean;
    invalidVkXHex: string;
    invalidMillerHex: string;
    invalidVerified: boolean;
  };
}

const vec = JSON.parse(readFileSync(join(here, 'pairing-vectors.json'), 'utf8')) as Vectors;

// --- deserialize the instance back into noble points ---
const g1 = (o: G1J) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o: G2J) =>
  bn254.G2.Point.fromAffine({
    x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]),
    y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]),
  });

const vk: VerifyingKey = {
  alpha: g1(vec.vk.alpha),
  beta: g2(vec.vk.beta),
  gamma: g2(vec.vk.gamma),
  delta: g2(vec.vk.delta),
  ic: vec.vk.ic.map(g1),
};
const proof: Proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
const inputs = vec.publicInputs.map(BigInt);

// ---------------------------------------------------------------------------
// The CHECKER: grade a candidate's (vk_x, miller bytes, verdict) against golden.
// `sameBasis` selects whether checkpoint #2 is graded by exact bytes (true) or
// only via the basis-independent finalExp verdict (false).
// ---------------------------------------------------------------------------
export interface Candidate {
  vkXHex: string; // "x,y" affine hex
  millerHex: string; // 384B Fp12 (noble tower basis) hex, or '' if not provided
  verdict: boolean; // finalExp(miller) == 1
}
export interface Grade {
  cp1_vkX: boolean;
  cp2_miller: 'exact' | 'finalExp-only' | 'FAIL';
  cp3_verdict: boolean;
  pass: boolean;
}

export const gradeCandidate = (
  cand: Candidate,
  golden: { vkXHex: string; millerHex: string; verified: boolean },
  sameBasis: boolean,
): Grade => {
  const cp1 = cand.vkXHex === golden.vkXHex;
  let cp2: Grade['cp2_miller'];
  if (sameBasis) {
    cp2 = cand.millerHex === golden.millerHex ? 'exact' : 'FAIL';
  } else {
    // basis-independent: trust only the final verdict for the Miller boundary.
    cp2 = cand.verdict === golden.verified ? 'finalExp-only' : 'FAIL';
  }
  const cp3 = cand.verdict === golden.verified;
  return {
    cp1_vkX: cp1,
    cp2_miller: cp2,
    cp3_verdict: cp3,
    pass: cp1 && cp2 !== 'FAIL' && cp3,
  };
};

// ---------------------------------------------------------------------------
// Self-test: recompute the reference from the deserialized instance and grade.
// ---------------------------------------------------------------------------
const ref = checkpointsFor(vk, proof, inputs);

console.log('=== Groth16 PAIRING milestone checker (BN254) ===');
console.log('vectors: src/checkpoints/pairing-vectors.json');
console.log('oracle : @noble/curves bn254  (cross-validated by gen-pairing-vectors.py / py_ecc.bn128)');
console.log();
console.log('--- milestone checkpoints ---');
console.log('  #1 vk_x   = IC[0] + Σ inputs[i]·IC[i+1]            (G1 affine; graded EXACT, representation-free)');
console.log('  #2 miller = e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta)  (pre-final-exp Fp12, 384B)');
console.log('  #3 verify = finalExponentiate(miller) == 1         (boolean verdict)');
console.log();

// 1) the deserialized instance reproduces the golden values
console.log('--- golden values ---');
console.log('  #1 vk_x (x,y):', vec.golden.vkXHex);
console.log('     recomputed :', ref.vkXHex, ref.vkXHex === vec.golden.vkXHex ? 'OK' : 'MISMATCH');
console.log('  #2 miller Fp12 (' + vec.golden.millerBytes + 'B):', vec.golden.millerHex.slice(0, 48) + '...');
console.log('     recomputed :', ref.millerHex.slice(0, 48) + '...', ref.millerHex === vec.golden.millerHex ? 'OK' : 'MISMATCH');
console.log('  #3 verified   :', vec.golden.verified, '(recomputed', ref.verified, ref.verified === vec.golden.verified ? 'OK)' : 'MISMATCH)');
console.log();

// 2) grade a GOOD candidate (= the noble reference) under BOTH basis modes
const goodCand: Candidate = { vkXHex: ref.vkXHex, millerHex: ref.millerHex, verdict: ref.verified };
const golden = { vkXHex: vec.golden.vkXHex, millerHex: vec.golden.millerHex, verified: vec.golden.verified };

const gExact = gradeCandidate(goodCand, golden, true);
const gIndep = gradeCandidate(goodCand, golden, false);
console.log('--- grading a CORRECT candidate (noble reference) ---');
console.log('  same-basis mode  :', JSON.stringify(gExact));
console.log('  finalExp-only mode:', JSON.stringify(gIndep));
console.log();

// 3) grade TAMPERED candidates — each gate must catch its corruption
console.log('--- grading TAMPERED candidates (each gate must reject) ---');
// (a) wrong vk_x
const tVkX: Candidate = { ...goodCand, vkXHex: '00,00' };
const rVkX = gradeCandidate(tVkX, golden, true);
console.log('  tampered vk_x        : cp1 rejects =', !rVkX.cp1_vkX, ' overall pass =', rVkX.pass);
// (b) wrong miller bytes (same-basis mode)
const tMiller: Candidate = { ...goodCand, millerHex: 'ff' + goodCand.millerHex.slice(2) };
const rMiller = gradeCandidate(tMiller, golden, true);
console.log('  tampered miller bytes: cp2 rejects =', rMiller.cp2_miller === 'FAIL', ' overall pass =', rMiller.pass);
// (c) wrong verdict
const tVerdict: Candidate = { ...goodCand, verdict: !goodCand.verdict };
const rVerdict = gradeCandidate(tVerdict, golden, false);
console.log('  tampered verdict     : cp3 rejects =', !rVerdict.cp3_verdict, ' overall pass =', rVerdict.pass);
console.log();

// 4) confirm the INVALID instance's golden verdict is false, and a candidate
//    claiming the invalid instance verifies is rejected.
const invInputs = vec.invalid.publicInputs.map(BigInt);
const invRef = checkpointsFor(vk, proof, invInputs);
console.log('--- invalid instance (tampered public input) ---');
console.log('  ' + vec.invalid.note);
console.log('  golden invalidVerified :', vec.golden.invalidVerified, '(recomputed', invRef.verified + ')');
console.log('  invalid vk_x matches golden:', invRef.vkXHex === vec.golden.invalidVkXHex);

// --- summary / assertions ---
const allOK =
  ref.vkXHex === vec.golden.vkXHex &&
  ref.millerHex === vec.golden.millerHex &&
  ref.verified === vec.golden.verified &&
  gExact.pass && gIndep.pass &&
  !rVkX.pass && !rMiller.pass && !rVerdict.pass &&
  vec.golden.verified === true &&
  vec.golden.invalidVerified === false &&
  invRef.verified === false &&
  invRef.vkXHex === vec.golden.invalidVkXHex;

console.log();
console.log('--- summary ---');
console.log('  vectors reproduce golden (all 3 checkpoints) :', ref.vkXHex === vec.golden.vkXHex && ref.millerHex === vec.golden.millerHex && ref.verified === vec.golden.verified);
console.log('  correct candidate passes (both modes)        :', gExact.pass && gIndep.pass);
console.log('  every tampered candidate rejected            :', !rVkX.pass && !rMiller.pass && !rVerdict.pass);
console.log('  valid instance verified == true              :', vec.golden.verified === true);
console.log('  invalid instance verified == false           :', vec.golden.invalidVerified === false);
console.log();
console.log(allOK ? 'CHECKER SELF-TEST: PASS' : 'CHECKER SELF-TEST: FAIL');
if (!allOK) process.exit(1);
