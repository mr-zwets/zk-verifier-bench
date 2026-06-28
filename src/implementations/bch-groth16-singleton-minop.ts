// OP-OPTIMIZED BCH-native Groth16 verifier singleton.
//
// Same complete verification as bch-groth16-singleton, with every chunked-verifier
// optimization that lowers OP-COST stacked on:
//   - LAZY field tower for the Miller loop (deferred reductions ~31% cheaper op than
//     the reduced tower — the single biggest lever);
//   - witnessed-residue final exponentiation (ePrint 2024/640) — drops the ~250M-op
//     hard-part final-exp for a cheap Frobenius tail (c,cInv,w gated witnesses);
//   - e(alpha,beta) baked as a constant (only 3 runtime single-pair Miller loops);
//   - fast-endo 63-bit G2 subgroup check (ePrint 2022/348) vs the 128-bit walk
//     (witness zinv, gated);
//   - GLV vk_x: 4-scalar ~128-bit Straus over a baked subset-sum table (witness
//     k-decomposition + zInv, gated).
//
// Source: groth16_contract/singleton/bn254/groth16_minop.cash
// Vectors: groth16_contract/singleton/bn254/build_vectors_groth16_minop.mjs ->
//          src/bch/groth16-singleton-minop-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-singleton-minop-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

const mp = JSON.parse(readFileSync('src/bch/groth16-singleton-minop-multiproof-vectors.json', 'utf8')) as {
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16SingletonMinOp: Implementation = {
  id: 'bch-groth16-singleton-minop',
  name: 'BCH Groth16 verifier singleton — op-optimized (lazy tower + residue + fast-G2 + GLV)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in ONE contract, op-optimized. ' +
    'Lazy field tower for the Miller loop (deferred reductions); witnessed-residue final ' +
    'exponentiation (ePrint 2024/640) replacing the hard part; e(alpha,beta) baked (3 runtime ' +
    'Miller loops); fast-endo 63-bit G2 subgroup check (ePrint 2022/348); GLV 4-scalar vk_x. ' +
    'All extra inputs (c,cInv,w; zinv; GLV k-decomposition + zInv) are prover-supplied and gated ' +
    'on-chain. Sound (vk_x recomputed on-chain). Verified vs @noble/curves bn254. Single-tx like ' +
    'bch-groth16-singleton but ~53% less op-cost. Still over the 10,000 B / per-input op limits.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'op-optimized Groth16 verify: lazy Miller + residue + fast-G2 + GLV (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'verify',
      },
    ];
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
    ];
    const extraValidProofs: Step[][] = mp.proofs
      .filter((p) => !p.committed)
      .map((p) => [{ ...valid[0]!, unlockingBytecode: hexToBin(p.unlocking) }]);
    return { valid, invalid, extraValidProofs };
  },
};
