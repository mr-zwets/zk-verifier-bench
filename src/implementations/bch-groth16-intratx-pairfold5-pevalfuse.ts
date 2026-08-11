// BCH-native BN254 Groth16 PairFold-5 peval-fuse tip (5 linked inputs, one tx).
// Score 39691. Stock public-bench envelope: value=1000, sequence=0.
//
// Separate entry from bch-groth16-intratx-pairfold5 (score 44968 RC on this board).
// Same topology (3 shared P2SH executors + genesis + terminal); denser tables via
// peval-fuse (offline (peval_γ · peval_δ) % P = 32 B/event).
//
// Construction (summary):
// - PairFold-5 mixed composed P2SH executors (3) + genesis + self-carried terminal
// - Fixed VK / fixed deployment; densFuel DROP dens-positive path; peval-fuse pin;
//   fixed-G2 x-only tables
// - dens floors [8318, 7248, 7750]; terminal densDrop 850; bqReserve 400
// - All lockings P2SH32 (35 B); standard-relayable one-tx
//
// Provenance: verifier.cash lane bn254-target-40k tip
// bn254-target-40k-pairfold-5-p2shchain-r0 (parent RC 44968). Dual rebuild A≡B;
// multiproof 0/1/2 + worst; stock input-redteam + off-subgroup; qualification green;
// public-bench FULL PASS @ 39691 on this harness (fitsBchStandardness true).
//
// Artifact pins (sha256 of each locking bytecode):
//   exec0    1b3c7b834906f66ad782bf0725470a6ea577ce59ec221f88619b68b897a2b181  (35 B)
//   exec1    1b3c7b834906f66ad782bf0725470a6ea577ce59ec221f88619b68b897a2b181  (35 B)
//   exec2    1b3c7b834906f66ad782bf0725470a6ea577ce59ec221f88619b68b897a2b181  (35 B)
//   genesis  4251519dd8961c5a4d78a0b48b886b81236d75da25132db69f13f06880f9517a  (35 B)
//   terminal 8145972e4c5da3292b29fd92da9f40ab270a50a34e3e09e8c3b0da84e21246d7  (35 B)
// Vectors file sha256: dc10764f1e6bafad2727538ed33d51134e7bc04a349e7ac138415474beaa2747
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
  name: 'BCH Groth16 intra-tx PairFold-5 peval-fuse dens-rich (score 39691)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: five P2SH32 inputs in one intra-transaction-linked BN254 ' +
    'Groth16 verifier (PairFold-5 peval-fuse dens-rich). Fixed-G2 xonly tables, peval-fuse ' +
    '32 B/event, dens floors 8318/7248/7750, densDrop 850, bqReserve 400, densFuel DROP ' +
    'dens-positive path, stock public-bench value=1000 / sequence=0 envelope. Score 39691 ' +
    '(scriptBytes 39456 + tx overhead 235); fitsBchStandardness true. Sibling of ' +
    'bch-groth16-intratx-pairfold5 (44968 RC); same 5-in topology, denser peval tables.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(toRun),
  }),
};
