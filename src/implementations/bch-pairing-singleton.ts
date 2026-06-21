// BCH-native Groth16 PAIRING as the FULL single-tx contract -- the monolithic
// baseline for the pairing (the ~95% of a Groth16 verifier that vk_x is not).
//
//   verify: e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1
//
// This is the ENTIRE pairing in ONE CashScript contract (GrothPairing,
// groth16_contract/singleton/pairing/verify.cash): the BN254 field tower
// (Fp2/Fp6/Fp12), four optimal-ate Miller loops (6x+2, divisive twist, mul034
// line functions, psi Q1/Q2 steps), their product, and the final exponentiation
// ((p^12-1)/r via cyclotomic exp). The four (P in G1, Q in G2) pairs are supplied
// at RUNTIME (spend args); the contract require()s the pairing product == Fp12
// ONE, which IS the verification verdict -- nothing is baked. Every field/curve
// op is a reusable function (OP_DEFINE/OP_INVOKE), compiled by the local cashc
// feat/reusable-functions build. Verified against @noble/curves bn254 (the Miller
// boundary matches the golden millerHex byte-for-byte; the verdict matches the
// golden valid/invalid).
//
// It accepts the valid instance and rejects the invalid one (a tampered public
// input changes vk_x so the product != 1). But at ~1.21B op-cost (~151 standard
// BCH inputs) and a ~20 KB contract it does NOT fit one input: on the real BCH
// 2026 VM it fails the 10,000-byte bytecode limit (and the op-cost density limit)
// -- the honest result that motivates the chunked (multi-tx) pairing.
//
// Vectors built/measured by groth16_contract/singleton/pairing/build_vectors.mjs
// -> src/bch/pairing-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/pairing-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

export const bchPairingSingleton: Implementation = {
  id: 'bch-pairing-singleton',
  name: 'BCH Groth16 pairing singleton (Miller loops + final exp, full verdict, single-tx)',
  proofSystem: 'Groth16 pairing (BCH-native)',
  field: 'BN254',
  structure: 'single-tx',
  source:
    'BCH-native CashScript: the FULL pairing e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*' +
    'e(C,delta)==1 in ONE contract (GrothPairing, singleton/bn254/verify.cash). ' +
    'BN254 field tower (Fp2/Fp6/Fp12), four optimal-ate Miller loops (6x+2, divisive ' +
    'twist, mul034 lines, psi Q1/Q2), product, and final exponentiation ' +
    '((p^12-1)/r, cyclotomic exp). RUNTIME pair inputs; the contract require()s the ' +
    'product == Fp12 ONE (the verdict is intrinsic). Verified vs @noble/curves bn254 ' +
    '(Miller boundary == golden millerHex; verdict == golden). ~1.21B op-cost -> ~151 ' +
    'BCH inputs; ~20 KB contract does NOT fit BCH in one input -- this is why the ' +
    'chunked multi-tx pairing exists.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full pairing verdict e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d) == 1 (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'pairing',
      },
    ];
    // invalid run: the tampered-public-input instance (different vk_x) -> product != 1 -> reject
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
    ];
    return { valid, invalid };
  },
};
