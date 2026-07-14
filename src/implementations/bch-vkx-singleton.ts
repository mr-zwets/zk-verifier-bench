// BCH-native Groth16 checkpoint #1 (vk_x) as the FULL single-tx contract --
// the monolithic baseline.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// This is the ENTIRE vk_x aggregation in ONE CashScript contract (VkX,
// groth16_contract/singleton/vkx.cash): one 254-iteration MSB-first
// Shamir/Straus loop over Jacobian-projective coordinates, with a fixed affine
// table for IC1, IC2, and IC1+IC2, then a single final Fermat inverse to affine.
// The public inputs
// (input0,input1) are supplied at RUNTIME as spend() args and bit-tested in
// script; only the expected vk_x affine point is baked (the constructor args
// expectedX/expectedY), as the checkpoint comparison -- the SAME honesty model
// as the chunked entries. Compiled by the local cashc feat/reusable-functions
// build; verified against py_ecc.bn128.
//
// It accepts the correct inputs (reproducing the baked vk_x) and rejects both a
// tampered input and a wrong baked expected. The loop skips leading-zero
// doublings, so op-cost varies with the runtime inputs. The published vector is
// ~11.21M op-cost and needs ~2 standard BCH inputs' worth of budget, so it does
// NOT fit one input: on the real BCH 2026 VM it fails the op-cost density limit
// even with the unlocking zero-padded to the 10,000-byte cap. That is the honest
// result, and the reason
// the chunked (multi-tx) entries exist.
//
// Vectors built/measured by groth16_contract/singleton/build_vectors.mjs ->
// src/bch/vkx-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/vkx-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  lockingBAD: string;
  unlocking: string;
  invalidUnlocking: string;
};

export const bchVkxSingleton: Implementation = {
  id: 'bch-vkx-singleton',
  name: 'BCH vk_x singleton (Groth16 checkpoint #1, full vk_x in ONE contract, single-tx)',
  proofSystem: 'Groth16 vk_x (BCH-native)',
  field: 'BN254',
  structure: 'single-tx',
  source:
    'BCH-native CashScript: the FULL vk_x = IC0 + input0*IC1 + input1*IC2 in ONE ' +
    'contract (monolithic baseline, VkX/singleton/bn254/vkx.cash). One MSB-first ' +
    '254-iteration Shamir/Straus loop with an affine IC1/IC2/IC1+IC2 table + ' +
    'one final Fermat inverse to affine; RUNTIME public inputs (only expected vk_x ' +
    'baked, like the chunked entries). Published vector: ~11.21M op-cost -> ~2 BCH ' +
    'inputs (runtime cost varies with scalar bits); does NOT fit ' +
    'BCH in a single input (real-VM op-cost density limit) -- this is why the ' +
    'chunked multi-tx entries exist.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full vk_x = IC0 + input0*IC1 + input1*IC2 (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'vk_x',
      },
    ];

    // Explicit invalid runs so rejection is actually tested (-> PASS):
    //   (1) tampered RUNTIME input  -> recomputed vk_x != baked expected -> reject
    //   (2) wrong baked expected    -> recomputed vk_x != baked expected -> reject
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
      [{ ...valid[0]!, lockingBytecode: hexToBin(v.lockingBAD) }],
    ];

    return { valid, invalid };
  },
};
