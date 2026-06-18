import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation } from '../harness/types.js';

// First BCH-native entry: one scalar multiply (input · IC, 254-bit double-and-add)
// + one Jacobian point add + affine conversion — the sub-step of Groth16
// checkpoint #1 (vk_x needs two of these). Compiled from CashScript via the local
// cashc feat/reusable-functions build; verified against py_ecc / @noble (same
// curve, BN254). It accepts the correct result and rejects a tampered scalar.
//
// It is NOT a full verifier — its own leaderboard track. The full single-tx vk_x
// (src/bch/vkx.ts) is correct but ~10 BCH inputs by op-cost (a multi-input
// checkpoint); this scalarMult sub-step is the per-step chunk unit (see
// src/bch/VKX-CHECKPOINT-NOTE.md).
const v = JSON.parse(readFileSync('src/bch/vkx-scalarmult-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
};

export const bchVkxScalarmult: Implementation = {
  id: 'bch-vkx-scalarmult',
  name: 'BCH vk_x scalarMult (Groth16 checkpoint #1 sub-step)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BN254',
  structure: 'single-tx',
  source: 'BCH-native CashScript (cashc feat/reusable-functions); checkpoint #1 sub-step',
  // Same-milestone, NORMALIZED comparison at scrypt-bn256's scalar (113569).
  // Both loops are fixed-iteration (ours: a 254-step loop; scrypt's: unrolled,
  // since BSV scripts can't loop), so op-cost is ~scalar-VALUE-independent and a
  // same-scalar measurement is a fair per-implementation comparison:
  //   ours @113569      = 38,735,274  (pnpm bch:vkx-scalarmult-sweep)
  //   scrypt-bn256 @113569 = 49,477,018  (pnpm scrypt-bn256:find-vkx)
  milestone: {
    name: 'vk_x (1 scalar-mult + add)',
    thisOpCost: 38_735_274,
    referenceOpCost: 49_477_018,
    referenceSource: 'scrypt-bn256',
    scalar: '113569 (popcount 10)',
    normalized: true,
  },
  load: async () => ({
    valid: [
      {
        label: 'scalarMult + Jacobian add',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
      },
    ],
    tamperable: true,
  }),
};
