// BCH-native FULL BLS12-381 Groth16 verifier, multi-transaction — the complete
// proof check on the same curve as nchain, every step fitting ONE BCH input.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                 (public-input aggregation, G1)
//   then  e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta)  via 4 Miller loops +
//   combine + final exponentiation, asserting the verdict == Fp12 ONE.
//
// The vk_x chunks (bch-vkx-bls12381-chunked-covenant) prepended to the pairing
// (bch-pairing-bls12381-chunked): a single proof-agnostic covenant chain where all
// state + proof-derived points + public inputs ride in the token NFT commitment
// (48-byte limbs), so one fixed set of lockings verifies ANY proof. Every one of the
// ~196 steps validates on the real BCH 2026 VM (op-cost <= 8,032,800, scripts
// <= 10,000 B). Verified against @noble/curves bls12-381 end to end.
//
// The BLS12-381 counterpart of bch-groth16-chunked (BN254); the only BCH-compatible
// full Groth16 verifier on the nchain curve.
//
// Vectors: groth16_contract/chunked/bls12-381/build_vectors_pairing.mjs ->
// src/bch/groth16-bls12381-chunked-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string;
  covenant?: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-chunked-vectors.json', 'utf8')) as {
  steps: RawStep[]; extraValidProofs?: RawStep[][]; invalidInputs?: RawStep[][];
};

const toStep = (s: RawStep): Step => ({
  label: s.label,
  lockingBytecode: hexToBin(s.locking),
  unlockingBytecode: hexToBin(s.unlocking),
  checkpoint: s.checkpoint,
  covenant: s.covenant && {
    category: hexToBin(s.covenant.category),
    capability: s.covenant.capability,
    inCommitment: hexToBin(s.covenant.inCommitment),
    outCommitment: hexToBin(s.covenant.outCommitment),
    outLockingBytecode: hexToBin(s.covenant.outLockingBytecode),
  },
});

export const bchGroth16Bls12381Chunked: Implementation = {
  id: 'bch-groth16-bls12381-chunked',
  name: 'BCH Groth16 full verifier chunked, BLS12-381 (vk_x + pairing + final exp -> verdict, multi-tx, BCH-compatible)',
  // FULL verifier -> the ranked 'Groth16' leaderboard (same as nchain, scrypt-bn256,
  // bch-groth16-singleton/chunked, bch-groth16-bls12381-singleton). nchain is the
  // BLS12-381 reference, so this is its direct BCH-native chunked competitor. (The
  // vk_x / pairing sub-steps use the separate '... (BCH-native)' sub-step groups.)
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the COMPLETE BLS12-381 Groth16 verifier — a G2 input-validation ' +
    'prologue (EIP-197: on-curve A/B/C + the prime-order-subgroup test psi(B)==[-x]B) then ' +
    'vk_x = IC0 + ' +
    'in0*IC1 + in1*IC2 (public-input aggregation) then e(-A,B)*e(alpha,beta)*' +
    'e(vk_x,gamma)*e(C,delta) via 4 Miller loops + combine + final exponentiation, ' +
    'asserting the verdict == Fp12 ONE — split across transactions so EVERY step fits ' +
    'one BCH input. Proof-agnostic covenant: all state + proof-derived points + public ' +
    'inputs ride in the token NFT commitment (48-byte limbs), so one fixed set of ' +
    'lockings verifies any proof (confirmed via extraValidProofs). Verified vs ' +
    '@noble/curves bls12-381. The BLS12-381 counterpart of bch-groth16-chunked; the ' +
    'BCH-compatible full Groth16 verifier on the nchain curve.',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const extraValidProofs: Step[][] = (v.extraValidProofs ?? []).map((run) => run.map(toStep));
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    // adversarial INPUT runs (off-curve A, on-curve off-subgroup B) — the g2check prologue's
    // on-curve + psi(B)==[-x]B subgroup checks must reject them (grades inputValidation).
    const invalidInputs: Step[][] = (v.invalidInputs ?? []).map((run) => run.map(toStep));
    return { valid, extraValidProofs, invalid, invalidInputs };
  },
};
