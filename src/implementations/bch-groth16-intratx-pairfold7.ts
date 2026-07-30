// BCH-native BN254 Groth16 PairFold-7 verifier (7 linked inputs, one tx).
// Dens-rich tip score 54483. Stock public-bench envelope: value=1000, sequence=0.
//
// Construction (summary):
// - PairFold-7 mixed w=2 composed P2SH executors (5) + genesis + self-carried terminal
// - Fixed VK / fixed deployment; dens-rich densFuel=0 path; runtime proof binding
// - All lockings P2SH32 (35 B); standard-relayable one-tx under 55 kB score
//
// Provenance: verifier.cash lane bn254-onetx tip, promotion-green pack
// artifacts/bn254-one-tx-standard/54483 (score 54483).
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
  name: 'BCH Groth16 intra-tx PairFold-7 dens-rich (score 54483)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: seven P2SH32 inputs in one intra-transaction-linked BN254 ' +
    'Groth16 verifier (PairFold-7 dens-rich). Mixed Miller windows, fixed-G2 tables, ' +
    'densFuel=0 pure dens path, stock public-bench value=1000 / sequence=0 envelope. ' +
    'Score 54483 (scriptBytes 54162 + tx overhead 321); fitsBchStandardness=true.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(toRun),
  }),
};
