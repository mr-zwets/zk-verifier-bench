// BCH-native COMPLETE Groth16 verifier on BLS12-381, single-tx -- the SAME verifier as
// bch-groth16-bls12381-singleton (vk_x computed on-chain, then the full pairing check),
// but with the locking bytecode byte-optimized: the smaller of the golf recompile
// (groth16_contract/singleton/bn254/recompiler/, curve-agnostic) and the rescheduled
// compile, followed by the auto-outlining pass that factors repeated instruction
// sequences into OP_DEFINE bodies. Semantics are identical (same runtime witnesses,
// same verdict). Together with the plain entry this shows the bytesize-vs-opcost
// tradeoff on BLS12-381: outlining trades a few percent op-cost for the byte savings,
// exactly like the BN254 pair (bch-groth16-singleton vs -opcode-optimized).
//
// Every rewritten subroutine is differential-tested against the cashc original on the
// loosened BCH-2026 VM, every outline rewrite batch is verified accept-valid /
// reject-tampered, and the full multiproof battery gates the vectors.
//
// Pipeline + vectors:
//   node groth16_contract/singleton/bls12-381/build_vectors_optimized.mjs
//     -> src/bch/groth16-bls12381-singleton-opcode-optimized-vectors.json
//     -> src/bch/groth16-bls12381-singleton-opcode-optimized-multiproof-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-opcode-optimized-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-opcode-optimized-multiproof-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: { unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16Bls12381SingletonOpcodeOptimized: Implementation = {
  id: 'bch-groth16-bls12381-singleton-opcode-optimized',
  name: 'BCH Groth16 verifier singleton, BLS12-381, opcode-optimized (recompile + outlining)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Same complete BLS12-381 Groth16 verifier as bch-groth16-bls12381-singleton ' +
    '(Groth16Verify, singleton/bls12-381/groth16.cash: vk_x = IC0 + in0*IC1 + in1*IC2 ' +
    'on-chain, then e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) == 1), but the ' +
    'locking bytecode is byte-optimized: the smaller of a custom ' +
    'decompile->reschedule->recompile of the cashc output and the rescheduled compile, ' +
    'then repeated instruction sequences outlined into OP_DEFINE bodies. Identical ' +
    'semantics + runtime witnesses; each subroutine differential-tested and every ' +
    'outline rewrite verified accept/reject. The plain entry keeps the other end of ' +
    'the bytesize-vs-opcost tradeoff. Pipeline: singleton/bls12-381/' +
    'build_vectors_optimized.mjs + singleton/bn254/recompiler/.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full BLS12-381 Groth16 verify (opcode-optimized): vk_x on-chain + e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d)==1 (single tx)',
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
