// Source-assembled BN254 genpow with canonical G1 parity witnesses.
// 4,320 locking bytes and a 208-byte witness; historical UE used 4,198/272.
// Owning source: singleton/bn254/genpow-reconstructed/{verifier.asm,build.mjs}.
// Assembly SHA-256: fef9584108c9cfa0c05c8ca2ff99b6de1cdf744d6b65f1e084b8a5eb37dc7c19.
// Corrected locking SHA-256: 022fea806c85f8008990ae244b80b87353f5aedd5555eb369cef63a28269f483.
// Finite parity0/1 witnesses remain byte-identical. Parity2,x0 denotes neutral G1;
// four zero B limbs denote neutral G2. Canonical coordinates and Fr inputs are guarded.
// Complete MSM identity addition and neutral Miller units preserve the fixed-key equation.
// Four unchanged positives passed the arithmetic oracle; all eight default native
// consensus/standard executions rejected at operation-cost density. Native resource HOLD.
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
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 0, push: 1, name: 'n0' }, { input: 0, push: 0, name: 'n1' }],
  name: 'BCH Groth16 verifier singleton, BN254 genpow (shared P, range-checked inputs, source-assembled 4,320 B, G1 parity)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Explicit symbolic assembly in singleton/bn254/genpow-reconstructed/verifier.asm. ' +
    'Original finite A/C parity witnesses and all proof/public bytes remain unchanged. ' +
    'Canonical coordinate/Fr guards, complete MSM identity addition, and neutral G1/G2 Miller branches ' +
    'bind the fixed-key equation, including neutral vk_x. The 72 helper IDs and 2,790-step final exponent ' +
    'schedule are unchanged. Neutral G1 uses parity2,x0; neutral G2 uses four zero limbs. ' +
    'All four unchanged 208-byte original positives passed the pinned arithmetic oracle. ' +
    'All eight default BCH2026 consensus/standard runs rejected at operation-cost density. ' +
    'Native resource HOLD remains; arithmetic-oracle success does not establish native or relay acceptance.',
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
