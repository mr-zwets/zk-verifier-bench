// BCH-native FULL BLS12-381 Groth16 verifier, multi-transaction — the complete
// proof check on the same curve as nchain, every step fitting ONE BCH input.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                 (public-input aggregation, G1)
//   then  e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) via a prepared-VK
//   Miller product + final exponentiation, asserting the verdict == Fp12 ONE.
//
// The vk_x chunks (bch-vkx-bls12381-chunked-covenant) prepended to the pairing
// (bch-pairing-bls12381-chunked): a single proof-agnostic covenant chain where all
// state + proof-derived points + public inputs ride in the token NFT commitment
// (48-byte limbs), so one fixed set of lockings verifies ANY proof. Every step
// validates on the real BCH 2026 VM (op-cost <= 8,032,800, scripts
// <= 10,000 B). Layout: 5 GLV vk_x + 29 input-validated Miller + 22 final-exp inputs =
// 56 inputs, 484,865 bytes, 377,821,912 op-cost. Verified against @noble/curves.
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
  steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalidInputs?: RawStep[][];
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
  name: 'BCH Groth16 full verifier chunked, BLS12-381 (GLV + prepared Miller, 56 inputs)',
  // FULL verifier -> the ranked 'Groth16' leaderboard (same as nchain, scrypt-bn256,
  // bch-groth16-singleton/chunked, bch-groth16-bls12381-singleton). nchain is the
  // BLS12-381 reference, so this is its direct BCH-native chunked competitor. (The
  // vk_x / pairing sub-steps use the separate '... (BCH-native)' sub-step groups.)
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  // Every nonterminal covenant step pins the token category, requires mutable capability,
  // preserves the single NFT thread, and pins the successor locking. The vector generator
  // rejects a wrong category or stripped capability for every such step.
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the COMPLETE BLS12-381 Groth16 verifier — canonical-range-checked ' +
    'five-chunk GLV vk_x = IC0 + ' +
    'in0*IC1 + in1*IC2 (public-input aggregation, with the fixed VK table embedded in each locking), then e(-A,B)*e(alpha,beta)*' +
    'e(vk_x,gamma)*e(C,delta) via an input-validated prepared-VK Miller product: only B walks G2 ' +
    'on-chain, gamma/delta line coefficients are baked, and fixed e(alpha,beta) is ' +
    'folded once as its pre-conjugate Miller value. The first Miller input checks A/C and B ' +
    'on-curve; the last reuses R_B=[|x|]B for the guarded psi(B)==[-x]B subgroup check. ' +
    'Final exponentiation asserts Fp12 ONE. The 5 GLV vk_x + 29 Miller + 22 final-exp inputs ' +
    'total 56 inputs, 484,865 bytes, and 377,821,912 op-cost; EVERY step fits ' +
    'one BCH input. Proof-agnostic covenant: all state + proof-derived points + public ' +
    'inputs ride in the token NFT commitment (48-byte limbs). vk_x emits the exact ' +
    '(-A,B,C,vk_x) stage, Miller derives f=1 and R_B=B, and every ' +
    'nonterminal step pins the actual successor locking, so one fixed set of ' +
    'lockings verifies any proof (confirmed via extraValidProofs). Verified vs ' +
    '@noble/curves bls12-381. The BLS12-381 counterpart of bch-groth16-chunked; the ' +
    'BCH-compatible full Groth16 verifier on the nchain curve.',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const extraValidProofs: Step[][] = (v.extraValidProofs ?? []).map((run) => run.map(toStep));
    const worstCaseProof = v.worstCaseProof?.map(toStep);
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    // Invalid input runs cover the fused point/subgroup checks plus GLV range,
    // decomposition, shared-table, and seam checks.
    const invalidInputs: Step[][] = (v.invalidInputs ?? []).map((run) => run.map(toStep));
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
