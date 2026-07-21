// BCH-native BN254 Groth16 verifier — PairFold-7 composed single-tx research entry.
//
// Seven inputs in one transaction:
//   exec0..exec4  P2SH32 composed fixed-G2 windows (mixed w=2 PairFold)
//   genesis       proof/statement bind + ECIP head
//   terminal      self-carried final BQ + T5-1 subgroup fold + pairing close
//
// Fixed VK and fixed deployment; proofBinding = runtime. Public score 67,844 B
// (script 67,523 + overhead 321) under stock 1000-sat / sequence-0 envelope.
//
// Vectors pin three extra accepted multiproofs + worst-case against the same
// locking graph, seven witness-tamper invalid runs, and four invalidInputs
// (off-curve A/B, non-canonical B, on-curve off-subgroup B) for the harness
// inputValidation channel.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
}

interface Vectors {
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  worstCaseProof?: RawStep[];
  invalid?: RawStep[][];
  invalidInputs?: RawStep[][];
}

const v = JSON.parse(
  readFileSync('src/bch/groth16-intratx-pairfold7-vectors.json', 'utf8'),
) as Vectors;

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

const toRun = (raw: RawStep[]): Step[] => {
  if (raw.length !== 7) throw new Error('pairfold7 vectors must contain exactly seven inputs');
  const inputs = raw.map((s) => ({
    lockingBytecode: hexToBin(s.locking),
    unlockingBytecode: hexToBin(s.unlocking),
  }));
  return raw.map((s, i) => ({
    label: s.label,
    lockingBytecode: inputs[i]!.lockingBytecode,
    unlockingBytecode: inputs[i]!.unlockingBytecode,
    checkpoint:
      i === 0 ? 'exec0'
        : i === 4 ? 'exec4-tail'
          : i === 5 ? 'genesis'
            : i === 6 ? 'terminal'
              : undefined,
    intraTx: { index: i, inputs },
  }));
};

const assertLockInvariant = (): void => {
  const base = v.steps.map((s) => hexToBin(s.locking));
  for (const run of [...(v.extraValidProofs ?? []), ...(v.worstCaseProof ? [v.worstCaseProof] : [])]) {
    const locks = run.map((s) => hexToBin(s.locking));
    if (locks.some((lock, index) => !sameBytes(lock, base[index]!))) {
      throw new Error('runtime proof vector changed a pairfold7 locking bytecode');
    }
  }
};

export const bchGroth16IntratxPairfold7: Implementation = {
  id: 'bch-groth16-intratx-pairfold7',
  name: 'BCH BN254 Groth16 PairFold-7 composed (7-input single-tx)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Seven-input single-tx BN254 Groth16 verifier: five P2SH32 composed PairFold-7 ' +
    'mixed w=2 executors plus genesis and a self-carried terminal. Full CSE on the ' +
    'shared executor redeem with density-funded fixed-G2 table carriage. Fixed VK and ' +
    'deployment; runtime proof binding. Measured score 67844 under stock public-bench ' +
    'envelope. Genesis rejects off-curve/non-canonical B; terminal T5-1 fold rejects ' +
    'on-curve off-subgroup B. Research evidence — not a promotion-certified universal verifier.',
  load: async () => {
    assertLockInvariant();
    return {
      valid: toRun(v.steps),
      extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
      worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
      invalid: (v.invalid ?? []).map(toRun),
      invalidInputs: (v.invalidInputs ?? []).map(toRun),
    };
  },
};
