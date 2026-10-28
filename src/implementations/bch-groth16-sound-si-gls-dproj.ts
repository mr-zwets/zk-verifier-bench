// SI-GLS with an on-chain projective delta walk (Track 2 "frontier middle" design T1, BN254): the reviewed
// bch-groth16-sound-si-gls-single with one change. The 88-slope baked delta pile and its DSTEP function are replaced
// by an on-chain projective walk of the fixed VK point delta, through the same doubling / mixed-addition kernels as the
// projective B walk (one shared local kernel each). The projective delta lines are Fp2* multiples of the reviewed
// affine lines, so the line classes in Fp12*/Fp6* and the honest monic states are unchanged (WS is byte-identical to
// the reviewed entry's for the same proof; WQ changes). ONE P2SH32 input graded on the PROPOSED bch-spec VM
// (100,000-byte scripts); it needs about 1.6x the bch-spec op-cost budget, so it is NOT bch-compatible as shipped.
// Statement: full Groth16 under the fixed VK of the locking (the SI-GLS fixture VK), public inputs n0, n1 packed in
// push 1 (WS) at bytes 256 and 288, 32-byte little-endian (canonical: 0 <= n < r enforced on-chain).
// Owning source: research/frontier-middle/bn254/sigls-dproj in groth16_cashscript (README there and in
// research/frontier-middle/bn254/README.md). Vectors: sigls-dproj/export.mjs (the reviewed entry's 15 invalid classes).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bn254SiGlsDprojProofInputs } from './groth16-proof-inputs.js';

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

const vectors = JSON.parse(readFileSync('src/bch/groth16-sound-si-gls-dproj-vectors.json', 'utf8')) as Vectors;

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

export const bchGroth16SoundSiGlsDproj: Implementation = {
  id: 'bch-groth16-sound-si-gls-dproj',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [
    { input: 0, push: 1, name: 'n0', offset: 256, encoding: 'le32' },
    { input: 0, push: 1, name: 'n1', offset: 288, encoding: 'le32' },
  ],
  name: 'BCH Groth16 SI-GLS single torus identity with an on-chain projective delta walk, single input (bch-spec)',
  vm: 'bch-spec',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bn254SiGlsDprojProofInputs,
  source:
    'Single-identity BN254 Groth16 verifier: the reviewed SI-GLS design (one batched odd torus identity at +-z over ' +
    '33 committed monic states, GT-GLS folding of e(vk_x, gamma), projective B with exact G2 endpoint check) with the ' +
    'baked delta slope pile replaced by an on-chain projective walk of the fixed delta through the shared B kernels ' +
    '(research/frontier-middle/bn254/sigls-dproj); trades about 5.3 KB of baked data for about +10M op-cost. Graded ' +
    'on the proposed bch-spec VM; needs about 1.6x its op-cost budget.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
