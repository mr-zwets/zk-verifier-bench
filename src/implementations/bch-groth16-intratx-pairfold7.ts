// BCH-native BN254 Groth16 PairFold-7 verifier (7 linked inputs, one tx).
// Stock public-bench envelope: value=1000, sequence=0.
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
  readFileSync('src/bch/groth16-intratx-pairfold7-vectors.json', 'utf8'),
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

export const bchGroth16IntratxPairfold7: Implementation = {
  id: 'bch-groth16-intratx-pairfold7',
  name: 'BCH Groth16 intra-tx PairFold-7 (scalar endpoints)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: seven P2SH32 inputs in one intra-transaction-linked BN254 ' +
    'Groth16 verifier (PairFold-7). Mixed singleton/pair Miller windows, fixed-G2 tables, ' +
    'scalar (bind‖fn) endpoints, pure-BQ dens pads (sibling-auth) + residual BQ dens on terminal, ' +
    'stock public-bench value=1000 / sequence=0 envelope. All lockings P2SH32 (≤201 B); research score ~57.9 kB, ' +
    'fitsBchStandardness=true; not a promotion-certified crown.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(toRun),
  }),
};
