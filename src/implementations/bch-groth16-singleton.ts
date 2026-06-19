// BCH-native COMPLETE Groth16 verifier as a single-tx contract -- the full
// verification, not just a piece: vk_x computed on-chain from the public inputs,
// then the pairing check.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                                  (on-chain, G1)
//   require( e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1 )
//
// The ENTIRE verifier in ONE CashScript contract (Groth16Verify,
// groth16_contract/singleton/pairing/groth16.cash): the BN254 field tower
// (Fp2/Fp6/Fp12), the G1 scalar-mult for vk_x (Jacobian double-and-add + a final
// Fermat inverse), four optimal-ate Miller loops, their product, and the final
// exponentiation. The verifying key (alpha,beta,gamma,delta,IC) is hardcoded for
// the committed instance; the proof (A,B,C) and public inputs (in0,in1) are
// supplied at RUNTIME. A is negated in-script. The contract require()s the
// product == Fp12 ONE -- the verification verdict. Sound: vk_x is recomputed
// on-chain, so a forged vk_x cannot satisfy the equation. Every field/curve op is
// a reusable function (OP_DEFINE/OP_INVOKE). Verified against @noble/curves bn254.
//
// Same curve (BN254) as scrypt-bn256, so a direct apples-to-apples size compare:
// this is ~543x smaller bytecode. But at ~1.26B op-cost (~157 standard BCH
// inputs) and a ~21.7 KB contract it does NOT fit one input -- on the real BCH
// 2026 VM it fails the 10,000-byte bytecode limit (and op-cost density). That is
// the honest result that motivates the chunked (multi-tx) verifier.
//
// Vectors: groth16_contract/singleton/pairing/build_vectors_groth16.mjs ->
// src/bch/groth16-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

export const bchGroth16Singleton: Implementation = {
  id: 'bch-groth16-singleton',
  name: 'BCH Groth16 verifier singleton (vk_x on-chain + full pairing, single-tx)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in ONE contract ' +
    '(Groth16Verify, singleton/pairing/groth16.cash). Computes vk_x = IC0 + in0*IC1 ' +
    '+ in1*IC2 on-chain (G1 Jacobian double-and-add + Fermat inverse), then the full ' +
    'BN254 pairing e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) and require()s == 1. ' +
    'VK hardcoded; proof (A,B,C) + public inputs (in0,in1) at RUNTIME; A negated ' +
    'in-script. Sound (vk_x recomputed on-chain). Verified vs @noble/curves bn254. ' +
    'Same curve as scrypt-bn256 -> ~543x smaller bytecode, but ~1.26B op-cost ' +
    '(~157 BCH inputs); ~21.7 KB does NOT fit one input -- motivates the chunked ' +
    'multi-tx verifier.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full Groth16 verify: vk_x on-chain + e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d)==1 (single tx)',
        lockingBytecode: hexToBin(v.lockingOK),
        unlockingBytecode: hexToBin(v.unlocking),
        checkpoint: 'verify',
      },
    ];
    // invalid run: tampered public input -> different vk_x -> product != 1 -> reject
    const invalid: Step[][] = [
      [{ ...valid[0]!, unlockingBytecode: hexToBin(v.invalidUnlocking) }],
    ];
    return { valid, invalid };
  },
};
