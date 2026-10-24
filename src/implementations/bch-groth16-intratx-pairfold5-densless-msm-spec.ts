// WITHDRAWN full-verifier qualification; retained as a historical measurement artifact.
// The vk_x MSM description is component-level and does not establish pairing soundness.
// See https://github.com/mr-zwets/zk-verifier-bench/issues/49.
// bch-spec variant of bch-groth16-intratx-pairfold5-densless-msm, graded on the PROPOSED bch-spec VM
// (100,000-byte scripts, op-cost budget (10,000 + unlocking) * 800 per input). With that base budget
// the genesis input carries the whole vk_x MSM, checked against its own push 0, so the verifier is
// kallisti's reconstructed densless (5 inputs, unmodified executors and terminal) with the dead vk_x
// predicate sliced out of genesis and no padding anywhere. Public inputs: genesis pushes 23 (n0), 22 (n1).
// Owning source: chunked/bn254/densless-msm-spec in groth16_cashscript.
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
  invalidInputs?: RawStep[][];
}

const vectors = JSON.parse(
  readFileSync('src/bch/groth16-intratx-pairfold5-densless-msm-spec-vectors.json', 'utf8'),
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

export const bchGroth16IntratxPairfold5DenslessMsmSpec: Implementation = {
  id: 'bch-groth16-intratx-pairfold5-densless-msm-spec',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 3, push: 23, name: 'n0' }, { input: 3, push: 22, name: 'n1' }],
  name: 'BCH Groth16 intra-tx PairFold-5 densless with sound vk_x MSM (bch-spec)',
  vm: 'bch-spec',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'WITHDRAWN full-verifier claim: the retained pairing/terminal construction has a confirmed correctness gap. ' +
    'Historical program and measurement bytes are preserved; the vk_x MSM description is component-level. ' +
    'PairFold-5 densless (public-only reconstruction, chunked/bn254/densless-recovered) whose genesis carries ' +
    'a GLV Straus MSM recomputing vk_x from the claimed public inputs (chunked/bn254/densless-msm-spec); ' +
    'five P2SH32 inputs, one transaction, graded on the proposed bch-spec VM.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
