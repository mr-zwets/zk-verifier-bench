// BCH-native BLS12-381 pairing verdict as a single-tx contract: the pairing-only
// milestone (vk_x supplied as the pair-3 G1 input, not recomputed) on the SAME
// curve as nchain. require( e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) == 1 ).
//
// GrothVerify (groth16_contract/singleton/bls12-381/verify.cash): four optimal-ate
// Miller loops (M-twist, |x| NAF, final conjugate), their product, and the BLS
// (Hayashida-Scott) final exponentiation, then require() the result is Fp12 ONE.
// RUNTIME pair inputs. Verified against @noble/curves bls12-381. ~1.38B op-cost
// (~172 BCH inputs); ~19.8 KB does NOT fit one input. The pairing milestone that
// precedes the full bch-groth16-bls12381-singleton (which also computes vk_x).
//
// Vectors: groth16_contract/singleton/bls12-381/build_vectors.mjs ->
// src/bch/pairing-bls12381-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/pairing-bls12381-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

export const bchPairingBls12381Singleton: Implementation = {
  id: 'bch-pairing-bls12381-singleton',
  name: 'BCH Groth16 pairing singleton, BLS12-381 (4 Miller loops + final exp, single-tx)',
  proofSystem: 'Groth16 pairing (BCH-native)',
  field: 'BLS12-381',
  structure: 'single-tx',
  source:
    'BCH-native CashScript: the FULL BLS12-381 pairing ' +
    'e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta)==1 in ONE contract (GrothVerify, ' +
    'singleton/bls12-381/verify.cash). BLS12-381 field tower (Fp2/Fp6/Fp12, xi=1+u), ' +
    'four optimal-ate Miller loops (M-twist, mul014 lines, |x| NAF, final conjugate), ' +
    'product, and the Hayashida-Scott final exponentiation. RUNTIME pair inputs; ' +
    'require()s the product == 1. Verified vs @noble/curves bls12-381. ~1.38B op-cost ' +
    '(~172 BCH inputs); ~19.8 KB does NOT fit one input -- the pairing milestone on ' +
    'the same curve as nchain.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'BLS12-381 pairing verdict: e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d)==1 (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'pairing',
      },
    ];
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
    ];
    return { valid, invalid };
  },
};
