// Source-assembled BN254 genpow with shared prime constant: 4,228 locking bytes.
// Exact reconstruction baseline: official 4,292-byte artifact 61c451d0...8494c83.
// Owning source: singleton/bn254/genpow-reconstructed/{verifier.asm,build.mjs}.
// Candidate hash a7686356...57cd0; structural full-graph equivalence preserves
// the original arithmetic, proof/public-input checks and final exponentiation.
// Original CashScript/stackcert pipeline is not recovered by this reconstruction.
// Committed operation cost rises 298,949,517 to 5,505,565,336. This remains a
// relaxed-VM singleton, with no native input-resource or new point-validation claim.
// The original load function and gates below are unchanged, including its labels.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-singleton-genpow-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), to confirm this verifier
// is runtime-general (one program verifies many proofs). committed:true is the primary
// vector already in `v`; the rest are the extra runtime proofs.
const mp = JSON.parse(readFileSync('src/bch/groth16-singleton-genpow-multiproof-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16SingletonGenpow: Implementation = {
  id: 'bch-groth16-singleton-genpow',
  name: 'BCH Groth16 verifier singleton, BN254 genpow (shared P, source-assembled 4,228 B)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Explicit symbolic assembly in singleton/bn254/genpow-reconstructed/verifier.asm. ' +
    'Reproduces the official 4,292-byte genpow leader exactly before a proved P-sharing ' +
    'rewrite to 4,228 bytes (sha256 a7686356eba90eb594d2a05189e645111506e67fc3c52007144081761d357cd0). ' +
    'All original verification predicates and public fixtures are preserved. The missing ' +
    'original CashScript/stackcert lineage is not claimed recovered. Committed relaxed-VM ' +
    'cost 5,505,565,336, +298,949,517; no native BCH resource or stronger input-validation claim.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full BN254 Groth16 verify (genpow, full EIP-197 incl. G2 subgroup): vk_x on-chain + finalExpPow(e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d))==Fp12.ONE (single tx)',
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
