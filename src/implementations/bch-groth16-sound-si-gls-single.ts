// SI-GLS: a sound-by-construction BN254 Groth16 verifier in ONE P2SH32 input, graded on the PROPOSED
// bch-spec VM (100,000-byte scripts, op-cost budget (10,000 + unlocking) * 800 per input).
// One batched torus identity at +-z: the Miller loops of (-A, B) and (C, delta), the GT-GLS fold of
// e(vk_x, gamma) (public inputs bound through hashed, range-checked sub-scalars and an exact mod-r check),
// and a torus residue root, checked by Schwartz-Zippel with every evaluation computed on-chain. Statement:
// full Groth16 under the fixed VK of the locking, public inputs n0, n1 packed in push 1 (WS) at bytes
// 256 and 288, 32-byte little-endian (canonical: 0 <= n < r enforced on-chain).
// Owning source: chunked/bn254/sound-si-gls in groth16_cashscript.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bn254SiGlsProofInputs } from './groth16-proof-inputs.js';

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
  readFileSync('src/bch/groth16-sound-si-gls-single-vectors.json', 'utf8'),
) as Vectors;
// TXv5-grading variant (used only for the txv5 field; Scenario.txv5Variant): the reviewed redeem with its
// entry check DEPTH <2> NUMEQUALVERIFY replaced by DEPTH <3> NUMEQUALVERIFY DROP, so the unlocking takes a pad
// <WQ> <WS> <pad> <redeem> that is dropped unread before any other instruction. Same WQ / WS witnesses as above.
// Derived and checked by chunked/txv5-pad/derive.mjs in groth16_cashscript (bn254.json).
const txv5Vectors = JSON.parse(
  readFileSync('src/bch/groth16-sound-si-gls-single-txv5pad-vectors.json', 'utf8'),
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

export const bchGroth16SoundSiGlsSingle: Implementation = {
  id: 'bch-groth16-sound-si-gls-single',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [
    { input: 0, push: 1, name: 'n0', offset: 256, encoding: 'le32' },
    { input: 0, push: 1, name: 'n1', offset: 288, encoding: 'le32' },
  ],
  name: 'BCH Groth16 SI-GLS single torus identity (sound by construction), single input (bch-spec)',
  vm: 'bch-spec',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bn254SiGlsProofInputs,
  source:
    'Single-identity BN254 Groth16 verifier: one batched odd torus identity at +-z over 33 committed monic ' +
    'states, GT-GLS folding of e(vk_x, gamma), projective B with exact G2 endpoint check, every accept-relevant ' +
    'value computed on-chain, baked, hash-committed before its challenge, or exactly checked ' +
    '(chunked/bn254/sound-si-gls); graded on the proposed bch-spec VM.',
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
