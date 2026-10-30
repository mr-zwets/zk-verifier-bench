// Standalone checked positive artifact for the BLS12-381 intra-tx residue-large
// frame correction. This descriptor is intentionally not registered in the
// default implementation index until the maintainer accepts the correction.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
  checkpoint?: string;
}

interface Vectors {
  description?: string;
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  worstCaseProof?: RawStep[];
}

const vectorBytes = readFileSync('src/bch/groth16-bls12381-intratx-residue-large-checked-vectors.json');
assert.equal(createHash('sha256').update(vectorBytes).digest('hex'), 'e5d352105aee57abdeac865c1125c2b66085f0112ccfeace275e13dc024dc90d');
const vectors = JSON.parse(vectorBytes.toString('utf8')) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((step) => ({
    lockingBytecode: hexToBin(step.locking),
    unlockingBytecode: hexToBin(step.unlocking),
  }));
  return raw.map((step, index) => ({
    label: step.label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: step.checkpoint,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16Bls12381IntratxResidueLargeCorrected: Implementation = {
  id: 'bch-groth16-bls12381-intratx-residue-large-corrected',
  name: 'BCH BLS12-381 Groth16 intra-tx residue-large exact-frame correction (checked positive artifact)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  publicInputs: [
    {input: 0, push: 0, offset: 0, encoding: 'le32', name: 'n0'},
    {input: 0, push: 0, offset: 48, encoding: 'le32', name: 'n1'},
  ],
  vm: 'bch-spec',
  source:
    'Frozen positive-only BLS12-381 residue-large artifact with exact 288-byte GLV carrier, 768-byte input-validation carrier, and 1632-byte quotient-terminal frame guards. ' +
    'The arithmetic program suffix and all proof/public/witness/state/table/padding bytes are preserved; only executable code and its coherent P2SH32 locking are corrected. ' +
    'The fixed-key arithmetic and complete ordered graph remain premises of the conditional equation claim. This is a proposed-spec profile; current-BCH, whole-transaction and relay admission remain HOLD.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: [], invalidInputs: [],
  }),
};
