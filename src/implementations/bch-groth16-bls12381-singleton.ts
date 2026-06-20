// BCH-native COMPLETE BLS12-381 Groth16 verifier as a single-tx contract -- the
// full verification on the SAME curve as the nChain reference, so a true
// apples-to-apples head-to-head: vk_x computed on-chain, then the pairing check.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                                  (on-chain, G1)
//   require( e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1 )
//
// The ENTIRE verifier in ONE CashScript contract (Groth16Verify,
// groth16_contract/singleton/bls12-381/groth16.cash): the BLS12-381 field tower
// (Fp2/Fp6/Fp12, xi = 1+u), the G1 scalar-mult for vk_x (Jacobian double-and-add +
// a final Fermat inverse), four optimal-ate Miller loops (M-twist, |x| NAF, final
// conjugate), their product, and the BLS (Hayashida-Scott) final exponentiation.
// The verifying key (alpha,beta,gamma,delta,IC) is hardcoded for the committed
// instance; the proof (A,B,C) and public inputs (in0,in1) are supplied at RUNTIME.
// A is negated in-script. require()s the product == Fp12 ONE. Sound: vk_x is
// recomputed on-chain. Verified against @noble/curves bls12-381.
//
// Same curve (BLS12-381) as nchain -> a direct comparison. At ~1.48B op-cost
// (~185 standard BCH inputs) and a ~24 KB contract it does NOT fit one input -- on
// the real BCH 2026 VM it fails the 10,000-byte bytecode limit. The honest
// single-tx baseline that motivates a chunked (multi-tx) BLS verifier.
//
// Vectors: groth16_contract/singleton/bls12-381/build_vectors_groth16.mjs ->
// src/bch/groth16-bls12381-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), to confirm this
// verifier is runtime-general (one program verifies many proofs) on nchain's curve.
// Built by groth16_contract/singleton/bls12-381/gen_multiproof.mjs.
const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-multiproof-vectors.json', 'utf8')) as {
  proofs: { unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16Bls12381Singleton: Implementation = {
  id: 'bch-groth16-bls12381-singleton',
  name: 'BCH Groth16 verifier singleton, BLS12-381 (vk_x on-chain + full pairing, single-tx)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in ONE contract on ' +
    'BLS12-381 -- the SAME curve as nchain (Groth16Verify, ' +
    'singleton/bls12-381/groth16.cash). Computes vk_x = IC0 + in0*IC1 + in1*IC2 ' +
    'on-chain (G1 Jacobian double-and-add + Fermat inverse), then the full ' +
    'BLS12-381 pairing e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) (M-twist ' +
    'Miller, |x| NAF, conjugate, Hayashida-Scott final exp) and require()s == 1. ' +
    'VK hardcoded; proof (A,B,C) + public inputs (in0,in1) at RUNTIME; A negated ' +
    'in-script. Sound (vk_x recomputed on-chain). Verified vs @noble/curves ' +
    'bls12-381. ~1.48B op-cost (~185 BCH inputs); ~24 KB does NOT fit one input ' +
    '-- the honest baseline vs the nchain single-tx reference.',
  load: async () => {
    const valid: Step[] = [
      {
        label: 'full BLS12-381 Groth16 verify: vk_x on-chain + e(-A,B)*e(a,b)*e(vk_x,g)*e(C,d)==1 (single tx)',
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
