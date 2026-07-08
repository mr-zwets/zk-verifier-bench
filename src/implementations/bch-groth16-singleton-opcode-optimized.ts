// BCH-native COMPLETE Groth16 verifier, single-tx -- the SAME verifier as
// bch-groth16-singleton (vk_x computed on-chain, then the full BN254 pairing check),
// but with the locking bytecode opcode-optimized: a custom decompile -> reschedule ->
// recompile pass over the cashc output that eliminates cashc's altstack park/restore in
// loops/branches, minimizes ROLL/PICK addressing, and folds adjacent stack ops into
// multi-item ops, followed by an auto-outlining pass that factors repeated instruction
// sequences into OP_DEFINE bodies. Semantics are identical (same runtime witnesses, same
// verdict) -> 14,131 -> 6,314 B (-55%), far under BCH's 10,000-byte standard script-size
// cap. Op-cost grows slightly from the outline call overhead (~750M -> ~796M), so it
// still does not fit one input -- the win is purely byte size.
//
// Every rewritten subroutine is differential-tested against the cashc original on the
// loosened BCH-2026 VM, and the whole contract is verified accept-valid / reject-tampered.
//
// Pipeline + vectors:
//   groth16_contract/singleton/bn254/recompiler/  (decompile.mjs, schedule.mjs, recompiler.mjs)
//   node singleton/bn254/recompiler/build_vectors_optimized.mjs
//     -> src/bch/groth16-singleton-opcode-optimized-vectors.json
//     -> src/bch/groth16-singleton-opcode-optimized-multiproof-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-singleton-opcode-optimized-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

const mp = JSON.parse(readFileSync('src/bch/groth16-singleton-opcode-optimized-multiproof-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16SingletonOpcodeOptimized: Implementation = {
  id: 'bch-groth16-singleton-opcode-optimized',
  name: 'BCH Groth16 verifier singleton, opcode-optimized (stack-scheduling recompile)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Same complete Groth16 verifier as bch-groth16-singleton (Groth16Verify, ' +
    'singleton/bn254/groth16.cash: vk_x = IC0 + in0*IC1 + in1*IC2 on-chain, then ' +
    'e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) == 1), but the locking bytecode is a ' +
    'custom decompile->reschedule->recompile of the cashc output plus an auto-outlining ' +
    'pass. It eliminates cashc\'s altstack park/restore (its emitReplace reassignment ' +
    'routine, ~2,150 alt-ops in the Miller loop alone), minimizes ROLL/PICK depth ' +
    'addressing, folds adjacent stack ops into multi-item ops, and outlines repeated ' +
    'instruction sequences into OP_DEFINE bodies -- 14,131 -> 6,314 B (-55%, far under ' +
    'the 10,000-byte standard cap). Identical semantics + runtime witnesses; each ' +
    'subroutine differential-tested vs the cashc original and every outline rewrite ' +
    'verified accept/reject. Op-cost ~796M, so still not one-input-standard. ' +
    'Pipeline: singleton/bn254/recompiler/.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full Groth16 verify (opcode-optimized): vk_x on-chain + e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d)==1 (single tx)',
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
