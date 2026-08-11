// BCH-native BN254 Groth16 PairFold-5 verifier (5 linked inputs, one tx).
// Release-candidate tip score 44968. Stock public-bench envelope: value=1000, sequence=0.
//
// Construction (summary):
// - PairFold-5 mixed composed P2SH executors (3) + genesis + self-carried terminal
// - Fixed VK / fixed deployment; densFuel DROP dens-positive path; peval pin; fixed-G2 x-only
// - dens floors [9600, 9400, 9500]; terminal densDrop 1200
// - All lockings P2SH32 (35 B); standard-relayable one-tx
//
// Provenance: verifier.cash lane bn254-pf5 tip bn254-pf5-pairfold-5-p2shchain-r0,
// frozen RC artifacts/bn254-one-tx-standard/44968 (SHA256SUMS). Dual rebuild A≡B;
// multiproof 0/1/2 + worst; stock + full adversarial redteam PASS; A1 89/0;
// public-bench FULL PASS @ 44968 on this harness.
//
// Artifact pins (sha256 of each locking bytecode):
//   exec0    a0d70073fbb478d4f12e2cbdebfdf605a63a7b81b37f12027fd54295e3fbf1c8  (35 B)
//   exec1    7fb9ebd9f3b3d1d9a9966d64d01b067c6ca83c0c835914791e17746a7fbc837c  (35 B)
//   exec2    7fb9ebd9f3b3d1d9a9966d64d01b067c6ca83c0c835914791e17746a7fbc837c  (35 B)
//   genesis  4251519dd8961c5a4d78a0b48b886b81236d75da25132db69f13f06880f9517a  (35 B)
//   terminal e12889da8295c67323f72010b450c87ca2aff39b0d0157bf15036c5f6274d3b3  (35 B)
// Vectors file sha256: db5101c11e19030bc647a43b5f81d27b2376bc6188595271318f1feca1384491
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
  readFileSync('src/bch/groth16-intratx-pairfold5-vectors.json', 'utf8'),
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

export const bchGroth16IntratxPairfold5: Implementation = {
  id: 'bch-groth16-intratx-pairfold5',
  name: 'BCH Groth16 intra-tx PairFold-5 peval dens-rich (score 44968)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: five P2SH32 inputs in one intra-transaction-linked BN254 ' +
    'Groth16 verifier (PairFold-5 peval dens-rich). Fixed-G2 xonly tables, peval pin, ' +
    'dens floors 9600/9400/9500, densDrop 1200, densFuel DROP dens-positive path, stock ' +
    'public-bench value=1000 / sequence=0 envelope. Score 44968 (scriptBytes 44733 + ' +
    'tx overhead 235); fitsBchStandardness expected true. Smaller than PairFold-7 frontier ' +
    'and the local PairFold-6 peval RC while dropping to five inputs.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(toRun),
  }),
};
