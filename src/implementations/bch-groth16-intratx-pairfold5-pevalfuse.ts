// Source-reconstructed PairFold-5 peval-fuse: 36,836 score bytes, five inputs.
// Owning source: chunked/bn254/leader-recovered in groth16_cashscript.
// Public-only witness production; fixed deployed VK/tag and declared semantics retained.
// Official corpus and bounded independent review pass; no universal resource claim.
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
  name: 'BCH Groth16 intra-tx PairFold-5 peval-fuse source-reconstructed (score 36836)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Public-only source reconstruction in chunked/bn254/leader-recovered. ' +
    'Five P2SH32 inputs, one standard transaction, 36,836 score bytes. ' +
    'Preserves the deployed VK/tag, transcript, coefficient ordering and worker authentication. ' +
    'Fixed deployment and finite-point/nonzero-denominator requirements remain; ' +
    'historical compiler lineage and universal resource/soundness proof are not claimed.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(toRun),
  }),
};
