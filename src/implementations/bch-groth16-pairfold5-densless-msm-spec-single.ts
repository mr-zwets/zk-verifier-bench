// Single-input variant of bch-groth16-intratx-pairfold5-densless-msm-spec, graded on the PROPOSED
// bch-spec VM (100,000-byte scripts, op-cost budget (10,000 + unlocking) * 800 per input). The five
// programs (genesis, three executors, terminal) run in sequence in ONE P2SH32 redeem on one stack:
// headers are handed over instead of pushed and re-checked, the executors' shared program is
// defined once, the vk_x MSM returns vk_x (spliced into the genesis block) and builds its Straus
// tables on-chain. Same statement: full Groth16 with vk_x recomputed from the claimed public
// inputs, the last two pushes before the redeem: 55 (n0), 54 (n1).
// Owning source: chunked/bn254/densless-msm-spec-single in groth16_cashscript.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

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
  readFileSync('src/bch/groth16-pairfold5-densless-msm-spec-single-vectors.json', 'utf8'),
) as Vectors;

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

export const bchGroth16Pairfold5DenslessMsmSpecSingle: Implementation = {
  id: 'bch-groth16-pairfold5-densless-msm-spec-single',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 0, push: 55, name: 'n0' }, { input: 0, push: 54, name: 'n1' }],
  name: 'BCH Groth16 PairFold-5 densless with on-chain vk_x MSM, single input (bch-spec)',
  vm: 'bch-spec',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'The densless-msm-spec verifier (chunked/bn254/densless-msm-spec) merged into one P2SH32 input: genesis, ' +
    'the three executors and the terminal run in sequence on one stack, with a GLV Straus MSM recomputing vk_x ' +
    'from the claimed public inputs (chunked/bn254/densless-msm-spec-single); graded on the proposed bch-spec VM.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
