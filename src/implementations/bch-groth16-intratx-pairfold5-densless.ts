// BCH-native BN254 Groth16 PairFold-5 densless natural0 tip (5 linked inputs, one tx).
// Score 33179. Stock public-bench envelope: value=1000, sequence=0.
//
// Separate entry from bch-groth16-intratx-pairfold5-pevalfuse (score 39691) and
// bch-groth16-intratx-pairfold5 (score 44968 RC). Same 5-in topology
// (3 shared P2SH executors + genesis + terminal) with zero artificial density
// (no dens floors / densFuel / densDrop / densPad).
//
// Construction (summary):
// - PairFold-5 mixed composed P2SH executors (3) + genesis + self-carried terminal
// - Fixed VK / fixed deployment; equal-limb BQ residual 2336; peval-expand; aff-R-only
// - All lockings P2SH32 (35 B); standard-relayable one-tx
// - Soundness: Groth16 pairing check e(A,B)=e(alpha,beta)*e(vk_x,gamma)*e(C,delta)
//   with runtime proof in the unlocking; T5-1 G2-subgroup fold rejects off-subgroup B;
//   genesis on-curve + canonical G2 guards; intra-tx INPUTBYTECODE seams bind one proof
//
// Provenance: verifier.cash lane bn254-densless tip
// bn254-densless-pairfold-5-p2shchain-natural0
// frozen vault artifacts/bn254-one-tx-standard/33179/ @ 4b26f34
// Dual rebuild A≡B; multiproof 0/1/2 + worst; stock input-redteam + full adversarial
// PASS; A1 89/0 global; public-bench FULL PASS @ 33179 on this harness
// (fitsBchStandardness true).
//
// Artifact pins (sha256 of each locking bytecode):
//   exec0    5db764662199ce4ae747198678b41c5072b76f8dac25a46f90b96940e2dabf93  (35 B)
//   exec1    5db764662199ce4ae747198678b41c5072b76f8dac25a46f90b96940e2dabf93  (35 B)
//   exec2    5db764662199ce4ae747198678b41c5072b76f8dac25a46f90b96940e2dabf93  (35 B)
//   genesis  1066a847c903abf4be70b3c2e75f23a02e4cf0f403415579a3c3551efbbfcccf  (35 B)
//   terminal 3a2ee206fa0c056fc94f73b34f9dd66d4f6d5dd75449384a3cd96e714fa9d2d0  (35 B)
// Vectors file sha256: b9d418090d217f0e4eb34cf28fc52b502db80decab73af88b9193c77ce633858
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
  readFileSync('src/bch/groth16-intratx-pairfold5-densless-vectors.json', 'utf8'),
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

export const bchGroth16IntratxPairfold5Densless: Implementation = {
  id: 'bch-groth16-intratx-pairfold5-densless',
  name: 'BCH Groth16 intra-tx PairFold-5 densless natural0 (score 33179)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: five P2SH32 inputs in one intra-transaction-linked BN254 ' +
    'Groth16 verifier (PairFold-5 densless natural0). Zero artificial density; equal-limb BQ ' +
    'residual 2336; peval-expand + aff-R-only; stock public-bench value=1000 / sequence=0. ' +
    'Score 33179 (scriptBytes 32944 + tx overhead 235). Sibling of pevalfuse 39691 / RC 44968.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(toRun),
  }),
};
