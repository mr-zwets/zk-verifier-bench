// BCH-native BLS12-381 Groth16 checkpoint #1 (vk_x) as the FULL single-tx contract
// -- the monolithic baseline on the same curve as nchain.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BLS12-381, b=4)
//
// The ENTIRE vk_x aggregation in ONE CashScript contract (VkX,
// groth16_contract/singleton/bls12-381/vkx.cash): two 255-iteration double-and-add
// scalar multiplies (input0*IC1, input1*IC2) over Jacobian-projective coordinates
// (b-independent formulas), the folds, and a single final Fermat inverse to affine.
// Public inputs (input0,input1) at RUNTIME; only the expected vk_x affine point is
// baked (constructor args expectedX/expectedY) -- the same honesty model as the
// BN254 entries. Verified against @noble/curves bls12-381.
//
// Accepts the correct inputs and rejects a tampered input or a wrong baked
// expected. At ~101M op-cost it needs ~13 standard BCH inputs' worth of budget, so
// it does NOT fit one input on the real BCH 2026 VM (op-cost density limit).
//
// Vectors: groth16_contract/singleton/bls12-381/build_vectors_vkx.mjs ->
// src/bch/vkx-bls12381-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/vkx-bls12381-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  lockingBAD: string;
  unlocking: string;
  invalidUnlocking: string;
};

export const bchVkxBls12381Singleton: Implementation = {
  id: 'bch-vkx-bls12381-singleton',
  name: 'BCH vk_x singleton, BLS12-381 (Groth16 checkpoint #1, full vk_x in ONE contract, single-tx)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BLS12-381',
  structure: 'single-tx',
  source:
    'BCH-native CashScript: the FULL vk_x = IC0 + input0*IC1 + input1*IC2 in ONE ' +
    'contract on BLS12-381 (VkX/singleton/bls12-381/vkx.cash). Two inlined ' +
    '255-iteration double-and-add scalar mults over Jacobian-projective coords ' +
    '(b-independent) + one final Fermat inverse to affine; RUNTIME public inputs ' +
    '(only expected vk_x baked). ~101M op-cost -> ~13 BCH inputs; does NOT fit one ' +
    'input (real-VM op-cost density limit). Verified vs @noble/curves bls12-381.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full BLS12-381 vk_x = IC0 + input0*IC1 + input1*IC2 (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'vk_x',
      },
    ];
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
      [{ ...valid[0]!, lockingBytecode: hexToBin(v.lockingBAD) }],
    ];
    return { valid, invalid };
  },
};
