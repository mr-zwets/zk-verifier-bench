// SI-GLS for BLS12-381 with an on-chain projective delta walk (Track 2 "frontier middle" design T1): the reviewed
// bch-groth16-bls12381-sound-si-gls-single with two changes. (1) The baked delta slope pile is replaced by an on-chain
// projective walk of the fixed VK point delta through the same doubling / mixed-addition kernels as B (role D); the
// projective lines are Fp2* multiples of the reviewed affine lines, so the classes are unchanged. (2) E_A = 0: the
// whole B walk is projective from (x : y : 1), so there are no witnessed affine slopes; Z = 0 is absorbing and the
// endpoint checks Z_T != 0, which makes every step exact (README, E_A = 0 exactness lemma). New transcript tag
// SIGLS-BLS/P. ONE P2SH32 input graded on the PROPOSED bch-spec VM (100,000-byte scripts); it needs about 1.65x the
// bch-spec op-cost budget, so it is NOT bch-compatible as shipped. Statement: full Groth16 under the fixed VK of the
// locking (the bench BLS12-381 fixture VK), public inputs n0, n1 packed in push 1 (WS) at bytes 384 and 416,
// 32-byte little-endian (canonical: 0 <= n < r enforced on-chain). A and C are curve-checked (cofactor malleability
// only); B in G2 by the exact endpoint [|x|]B = -psi(B).
// Owning source: research/frontier-middle/bls12381/sigls-dproj in groth16_cashscript. Vectors: sigls-dproj/export.mjs
// (the reviewed entry's 15 invalid classes).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bls12381SiGlsDprojProofInputs } from './groth16-proof-inputs.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
  checkpoint?: string;
}

interface Vectors {
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  worstCaseProof?: RawStep[];
  invalid?: RawStep[][];
}

const vectors = JSON.parse(readFileSync('src/bch/groth16-bls12381-sound-si-gls-dproj-vectors.json', 'utf8')) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((step) => ({
    lockingBytecode: hexToBin(step.locking),
    unlockingBytecode: hexToBin(step.unlocking),
    valueSatoshis: 1000n,
    sequenceNumber: 0,
  }));
  return raw.map((step, index) => ({
    label: step.label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: step.checkpoint,
    valueSatoshis: 1000n,
    sequenceNumber: 0,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16Bls12381SoundSiGlsDproj: Implementation = {
  id: 'bch-groth16-bls12381-sound-si-gls-dproj',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [
    { input: 0, push: 1, name: 'n0', offset: 384, encoding: 'le32' },
    { input: 0, push: 1, name: 'n1', offset: 416, encoding: 'le32' },
  ],
  name: 'BCH Groth16 BLS12-381 SI-GLS single torus identity with an on-chain projective delta walk, single input (bch-spec)',
  vm: 'bch-spec',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381SiGlsDprojProofInputs,
  source:
    'Single-identity BLS12-381 Groth16 verifier: the reviewed SI-GLS design (one batched odd torus identity at +-z ' +
    'over 32 committed monic states, base-|x| GT-GLS folding of e(vk_x, gamma), exact psi endpoint G2 check) with ' +
    'the baked delta slope pile replaced by an on-chain projective walk of the fixed delta through the B kernels, ' +
    'and an all-projective B walk (E_A = 0, no witnessed slopes) (research/frontier-middle/bls12381/sigls-dproj); ' +
    'graded on the proposed bch-spec VM; needs about 1.65x its op-cost budget.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
