// BCH-native COMPLETE Groth16 verifier, multi-transaction — the BCH-compatible
// full verifier: vk_x computed on-chain from the public inputs, then the whole
// pairing, split so EVERY step fits one BCH input (op-cost <= 8,032,800, scripts
// <= 10,000 B).
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                                  (chunked, G1)
//   require( e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) == 1 )  (chunked pairing)
//
// The ordered steps are: the vk_x Shamir/Straus chunks (public inputs at RUNTIME,
// asserting vk_x == the point the pairing uses) → 4 single-pair optimal-ate Miller
// chains → combine (boundary = f0*f1*f2*f3) → final exponentiation → a final step
// asserting the product == Fp12 ONE. State is carried between steps as a hash256
// commitment of the live values (the vk_x accumulator, or the Fp12 `f` + running
// G2 point, or the live final-exp temporaries) and re-supplied in the witness,
// verified on entry and exit. Verified against @noble/curves: the boundary matches
// the golden millerHex and the verdict matches the golden valid/invalid.
//
// This is the BCH-compatible counterpart of bch-groth16-singleton (~1.26B op-cost,
// ~157 inputs, single-tx, NOT BCH-compatible): same complete verifier, but here
// every step validates on the real BCH 2026 VM. Same BN254 curve as scrypt-bn256.
//
// Vectors: groth16_contract/chunked/pairing/build_vectors.mjs (run via
// generate.mjs) -> src/bch/groth16-chunked-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-chunked-vectors.json', 'utf8')) as {
  steps: { label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string }[];
};

export const bchGroth16Chunked: Implementation = {
  id: 'bch-groth16-chunked',
  name: 'BCH Groth16 verifier chunked (vk_x on-chain + full pairing, multi-tx, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier split across transactions ' +
    'so EVERY step fits one BCH input. vk_x = IC0+in0*IC1+in1*IC2 computed on-chain ' +
    '(Shamir/Straus, public inputs at RUNTIME) -> 4 single-pair Miller chains -> ' +
    'combine -> final exponentiation -> assert product == Fp12 ONE. State carried as ' +
    'hash256 commitments of the live values, verified on entry/exit each step. ' +
    'Verified vs @noble/curves (boundary == golden millerHex, verdict == golden). ' +
    'BCH-compatible counterpart of bch-groth16-singleton (~1.26B op-cost, ~157 ' +
    'inputs, single-tx, not BCH-compatible). Same BN254 curve as scrypt-bn256.',
  load: async () => {
    const valid: Step[] = v.steps.map((s) => ({
      label: s.label,
      lockingBytecode: hexToBin(s.locking),
      unlockingBytecode: hexToBin(s.unlocking),
      checkpoint: s.checkpoint,
    }));
    // tampered witness (wrong committed state) must be rejected — test at the first
    // vk_x step and at the final verdict step.
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    return { valid, invalid };
  },
};
