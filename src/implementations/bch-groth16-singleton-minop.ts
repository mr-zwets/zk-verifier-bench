// OP-OPTIMIZED BCH-native Groth16 verifier singleton.
//
// Same complete verification as bch-groth16-singleton, with every torus-era
// optimization that lowers OP-COST stacked on:
//   - LAZY field tower for the Miller loop (deferred reductions);
//   - quotient-torus residue check in Fp12*/Fp6* (six-limb canonical root u,
//     [c]=[1+uW]): the c^-(6x+2) fold rides the Miller loop and the terminal is the
//     cross-multiplied [f*c^(p^2)]=[c^p*c^(p^3)] with explicit [0:0] rejection —
//     no hard-part final-exp, no w27 coset correction;
//   - e(alpha,beta) baked as a torus constant (only the (-A,B) pair runs on-chain
//     G2 arithmetic; vk_x/C unit lines baked);
//   - affine runtime B with prover-witnessed slopes; the exact G2 subgroup check is
//     the Miller-endpoint endomorphism relation (no separate subgroup walk);
//   - GLV vk_x: 4-scalar Straus over a baked table with an affine witnessed-slope
//     accumulator (witnessed top-bit-gated k-decomposition).
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
  worstCaseUnlocking: string;
};

const mp = JSON.parse(readFileSync('src/bch/groth16-singleton-minop-multiproof-vectors.json', 'utf8')) as {
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16SingletonMinOp: Implementation = {
  id: 'bch-groth16-singleton-minop',
  name: 'BCH Groth16 verifier singleton — op-optimized (lazy tower + quotient torus + fused G2 + affine GLV)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in ONE contract, op-optimized. ' +
    'Lazy field tower; quotient-torus residue check in Fp12*/Fp6* (six-limb canonical root, ' +
    'c-fold riding the Miller loop, terminal [f*c^(p^2)]=[c^p*c^(p^3)] with [0:0] rejection); ' +
    'e(alpha,beta) baked so only (-A,B) runs on-chain G2 arithmetic; affine runtime B with ' +
    'witnessed slopes and the exact G2 subgroup check fused into the Miller endpoint; affine ' +
    'witnessed-slope GLV 4-scalar vk_x. All witnesses (u, slopes, inverses, k-decomposition) are ' +
    'prover-supplied and gated on-chain. Sound (vk_x recomputed on-chain). Verified vs ' +
    '@noble/curves bn254. Single-tx like bch-groth16-singleton but ~92% less op-cost — below the ' +
    '13-input chunked torus total. Still over the 10,000 B / per-input op limits.',
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
    // worst-case run: the same dense (near-r) proof the chunked entries measure, through the SAME
    // locking. Makes the op-cost column apples-to-apples (this GLV-based singleton is proof-DEPENDENT).
    const worstCaseProof: Step[] = [{ ...valid[0]!, unlockingBytecode: hexToBin(v.worstCaseUnlocking) }];
    return { valid, invalid, extraValidProofs, worstCaseProof };
  },
};
