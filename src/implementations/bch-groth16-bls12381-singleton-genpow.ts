// Checked full-final-exponentiation genpow entry; source API: cofactorPoints().
// Canonical finite compressed points, complete G2 square-root chart, complete
// group operations and r-component-preserving projections for G1 and G2.
// The fixed-VK equation uses cofactor-equivalent G1/G2 inputs. This does not
// enforce strict subgroup membership of the original G2 point.
// Locking: 5675 bytes, SHA256
// 6b36b9febaa033b366672c7a6a9d01dd604402d77cf7aced0a001a173292ad3f.
// All original proof/public/witness fields remain unchanged. Four original
// positives passed the arithmetic oracle with resource ceilings lifted.
// Native-resource status: HOLD. No BCH/relay admission or native score claim.
// Recovered symbolic source; original compiler/search lineage is unavailable.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-genpow-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), to confirm this
// verifier is runtime-general (one program verifies many proofs). committed:true is
// the primary vector already in `v`; the rest are the extra runtime proofs.
const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-genpow-multiproof-vectors.json', 'utf8')) as {
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16Bls12381SingletonGenpow: Implementation = {
  id: 'bch-groth16-bls12381-singleton-genpow',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 0, push: 1, name: 'n0' }, { input: 0, push: 0, name: 'n1' }],
  name: 'BCH Groth16 verifier singleton, BLS12-381 genpow (checked cofactor-equivalent G1/G2, 5,675 B; native-resource HOLD)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'cofactorPoints() in singleton/bls12-381/leader-recovered/cofactor-points.mjs: ' +
    'canonical finite compressed-point and curve checks, complete G2 root chart, ' +
    'complete group arithmetic and r-component-preserving G1/G2 projections. ' +
    'On-chain vk_x and the full final exponent bind the fixed-VK four-pair equation. ' +
    'G1 and G2 have cofactor-equivalent semantics; original G2 subgroup membership ' +
    'is not enforced. All original proof/public/witness bytes are unchanged. ' +
    'Four original positives passed the arithmetic oracle; native-resource HOLD. ' +
    'No BCH/relay admission or native score is claimed. Original compiler/search ' +
    'lineage remains unavailable.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full BLS12-381 Groth16 verify (genpow): vk_x on-chain + finalExpPow(e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d))==Fp12.ONE (single tx)',
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
