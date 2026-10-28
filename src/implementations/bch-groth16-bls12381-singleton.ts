import { affineSingletonProofInputs } from './groth16-proof-inputs.js';
// BCH-native COMPLETE BLS12-381 Groth16 verifier as a single-tx contract -- the
// full verification on the SAME curve as the nChain reference, so a true
// apples-to-apples head-to-head: vk_x computed on-chain, then the pairing check.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                                  (on-chain, G1)
//   require( e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1 )
//
// The ENTIRE verifier in ONE CashScript contract (Groth16Verify,
// groth16_contract/singleton/bls12-381/groth16.cash): the BLS12-381 field tower
// (Fp2/Fp6/Fp12, xi = 1+u), the G1 MSM for vk_x (one MSB-first Shamir/Straus
// pass with shared doublings + a final Fermat inverse), four optimal-ate Miller
// loops (M-twist, |x| NAF, final conjugate), their product, and the BLS
// (Hayashida-Scott) final exponentiation.
// The verifying key (alpha,beta,gamma,delta,IC) is hardcoded for the committed
// instance; the proof (A,B,C) and public inputs (in0,in1) are supplied at RUNTIME.
// A is negated in-script. require()s the product == Fp12 ONE. Sound: vk_x is
// recomputed on-chain. Verified against @noble/curves bls12-381.
//
// The proof points are validated before any pairing work: coordinates in [0, p), A and C
// on y^2 = x^3 + 4, B on the twist y^2 = x^3 + 4(1+u), and B in G2 (psi(B) == [-x]B fused
// into B's Miller walk, with a Z != 0 guard). Points at infinity have no encoding and are
// rejected. The vectors ship 17 out-of-domain proofs as extra invalid runs (including +p on
// every coordinate). A and C are not G1-subgroup checked: cofactor variants also verify,
// which is malleability only (see the source README).
//
// Same curve (BLS12-381) as nchain -> a direct comparison. At ~995M op-cost
// (~124 standard BCH inputs) and a 7,026-byte locking script it does not fit one
// input because of op-cost density. The honest
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
  // out-of-domain proof points (coordinate >= p, off-curve A/C/B, B on the twist but outside
  // G2), from groth16_contract/singleton/bls12-381/domain_cases.mjs; each must be REJECTED
  domainInvalid: { label: string; unlocking: string }[];
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), to confirm this
// verifier is runtime-general (one program verifies many proofs) on nchain's curve.
// Built by groth16_contract/singleton/bls12-381/gen_multiproof.mjs.
const mp = JSON.parse(readFileSync('src/bch/groth16-bls12381-singleton-multiproof-vectors.json', 'utf8')) as {
  proofs: { unlocking: string; invalidUnlocking: string; committed: boolean }[];
};

export const bchGroth16Bls12381Singleton: Implementation = {
  id: 'bch-groth16-bls12381-singleton',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 0, push: 1, name: 'n0' }, { input: 0, push: 0, name: 'n1' }],
  name: 'BCH Groth16 verifier singleton, BLS12-381 (vk_x on-chain + full pairing, single-tx)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: affineSingletonProofInputs,
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in ONE contract on ' +
    'BLS12-381 -- the SAME curve as nchain (Groth16Verify, ' +
    'singleton/bls12-381/groth16.cash). Computes vk_x = IC0 + in0*IC1 + in1*IC2 ' +
    'on-chain (one MSB-first Shamir/Straus pass with shared Jacobian doublings + ' +
    'Fermat inverse), then the full ' +
    'BLS12-381 pairing e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) (M-twist ' +
    'Miller, |x| NAF, conjugate, Hayashida-Scott final exp) and require()s == 1. ' +
    'VK hardcoded; proof (A,B,C) + public inputs (in0,in1) at RUNTIME; A negated ' +
    'in-script; proof points validated (coordinate range, curve equations, G2 subgroup via ' +
    'psi(B) == [-x]B fused into the Miller walk). Verified vs @noble/curves ' +
    'bls12-381. Locking is plain compiler output (size objective + ' +
    'rescheduleStacks, no post-passes; 7,026-byte locking) -- the honest baseline vs the ' +
    'nchain single-tx reference, and the other end of the bytesize-vs-opcost ' +
    'tradeoff from the -opcode-optimized entry. ~995M op-cost (~124 BCH ' +
    'inputs) does NOT fit one input.',
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
      ...v.domainInvalid.map((d) => [{ ...valid[0]!, unlockingBytecode: hexToBin(d.unlocking) }]),
    ];
    const extraValidProofs: Step[][] = mp.proofs
      .filter((p) => !p.committed)
      .map((p) => [{ ...valid[0]!, unlockingBytecode: hexToBin(p.unlocking) }]);
    return { valid, invalid, extraValidProofs };
  },
};
