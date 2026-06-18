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
