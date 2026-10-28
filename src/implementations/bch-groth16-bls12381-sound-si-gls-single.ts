// SI-GLS for BLS12-381: a sound-by-construction Groth16 verifier in ONE P2SH32 input, graded on the PROPOSED
// bch-spec VM (100,000-byte scripts, op-cost budget (10,000 + unlocking) * 800 per input).
// One batched torus identity at +-z over 32 committed monic states: the Miller loops of (-A, B) (the first
// E_A = 10 B events affine with witnessed slopes, each fixed by an exact equation, then homogeneous projective)
// and (C, delta) (baked slopes, on-chain x/c recursion), base-|x| GT-GLS folding of e(vk_x, gamma) (public
// inputs bound through hashed nibbles and an exact integer equality), and a torus residue root (lambda = p + |x|),
// checked by Schwartz-Zippel with every evaluation computed on-chain. G2 membership of B by the exact endpoint
// [|x|]B = -psi(B); A and C are curve-checked (cofactor malleability only). Statement: full Groth16 under the fixed
// VK of the locking (the bench BLS12-381 fixture VK), public inputs n0, n1 packed in push 1 (WS) at bytes 384 and
// 416, 32-byte little-endian (canonical: 0 <= n < r enforced on-chain).
// Owning source: chunked/bls12-381/sound-si-gls in groth16_cashscript.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bls12381SiGlsProofInputs } from './groth16-proof-inputs.js';

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

const vectors = JSON.parse(
  readFileSync('src/bch/groth16-bls12381-sound-si-gls-single-vectors.json', 'utf8'),
) as Vectors;
// TXv5-grading variant (used only for the txv5 field; Scenario.txv5Variant): the reviewed redeem with its
// entry check DEPTH <2> NUMEQUALVERIFY replaced by DEPTH <3> NUMEQUALVERIFY DROP, so the unlocking takes a pad
// <WQ> <WS> <pad> <redeem> that is dropped unread before any other instruction. Same WQ / WS witnesses as above.
// Derived and checked by chunked/txv5-pad/derive.mjs in groth16_cashscript (bls12-381.json).
const txv5Vectors = JSON.parse(
  readFileSync('src/bch/groth16-bls12381-sound-si-gls-single-txv5pad-vectors.json', 'utf8'),
) as Vectors;
const TXV5_VARIANT =
  'pad slot: entry check DEPTH <2> NUMEQUALVERIFY -> DEPTH <3> NUMEQUALVERIFY DROP (one instruction-level edit of the ' +
  'reviewed redeem, +1 B; unlocking <WQ> <WS> <pad> <redeem>, the pad dropped unread before any other instruction; ' +
  'groth16_cashscript chunked/txv5-pad)';

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

export const bchGroth16Bls12381SoundSiGlsSingle: Implementation = {
  id: 'bch-groth16-bls12381-sound-si-gls-single',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [
    { input: 0, push: 1, name: 'n0', offset: 384, encoding: 'le32' },
    { input: 0, push: 1, name: 'n1', offset: 416, encoding: 'le32' },
  ],
  name: 'BCH Groth16 BLS12-381 SI-GLS single torus identity (sound by construction), single input (bch-spec)',
  vm: 'bch-spec',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381SiGlsProofInputs,
  source:
    'Single-identity BLS12-381 Groth16 verifier: one batched odd torus identity at +-z over 32 committed monic ' +
    'states, base-|x| GT-GLS folding of e(vk_x, gamma) with an exact integer binding, affine-then-projective B walk ' +
    '(witnessed affine slopes fixed by exact equations) with an exact psi endpoint G2 check, every accept-relevant ' +
    'value computed on-chain, baked, hash-committed before its challenge, or exactly checked ' +
    '(chunked/bls12-381/sound-si-gls); graded on the proposed bch-spec VM.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    txv5Variant: {
      description: TXV5_VARIANT,
      valid: toRun(txv5Vectors.steps),
      extraValidProofs: (txv5Vectors.extraValidProofs ?? []).map(toRun),
      worstCaseProof: txv5Vectors.worstCaseProof ? toRun(txv5Vectors.worstCaseProof) : undefined,
      invalid: (txv5Vectors.invalid ?? []).map(toRun),
    },
  }),
};
