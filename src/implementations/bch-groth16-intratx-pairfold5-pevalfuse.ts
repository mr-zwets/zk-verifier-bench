// WITHDRAWN from the default registry: original equation ownership is unresolved.
// The standalone deterministic successor also remains native resource HOLD.
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
  readFileSync('src/bch/groth16-intratx-pairfold5-pevalfuse-vectors.json', 'utf8'),
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

export const bchGroth16IntratxPairfold5Pevalfuse: Implementation = {
  id: 'bch-groth16-intratx-pairfold5-pevalfuse',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 3, push: 37, name: 'n0' }, { input: 3, push: 36, name: 'n1' }],
  name: 'WITHDRAWN BCH Groth16 intra-tx PairFold-5 peval-fuse (archived original)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'WITHDRAWN from the default registry. These are the archived original native5 scripts; ' +
    'their complete-equation soundness is not established. ' +
    'The separate bch-groth16-intratx-pairfold5-pevalfuse-deterministic descriptor has a mandatory ' +
    'complete-equation guard but remains standalone with native resource admission HOLD. ' +
    'Original fixtures are retained unchanged for provenance; corrected-code observations do not apply to these scripts.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(toRun),
  }),
};
