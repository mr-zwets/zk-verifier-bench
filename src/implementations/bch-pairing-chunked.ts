// BCH-native Groth16 PAIRING, multi-transaction — the BCH-compatible pairing:
// every step fits ONE BCH input (op-cost <= 8,032,800, scripts <= 10,000 B).
//
// The pre-final-exponentiation Miller boundary
//   e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta)            (an Fp12)
// computed in 20 transactions by one prepared batched loop. The three
// runtime-dependent pairs share each fp12Sqr; fixed e(alpha,beta) is omitted from
// the loop and its precomputed raw Miller value is multiplied into f once at the
// end. Fixed-G2 line coefficients are baked, so only e(-A,B)'s R0 is carried and
// updated on-chain. State is hash256-committed and re-supplied in the witness.
//
// This is the multi-tx counterpart of bch-pairing-singleton (~1.21B op-cost,
// ~151 inputs, BCH-INcompatible): here every one of the 20 steps validates on
// the real BCH 2026 VM. Reaches checkpoint "miller-boundary"; the final
// exponentiation (verdict) is added on top of this boundary.
//
// Vectors: groth16_contract/chunked/pairing/build_vectors.mjs ->
// src/bch/pairing-chunked-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string;
  covenant?: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/pairing-chunked-vectors.json', 'utf8')) as {
  steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[];
};

// map a raw (hex) step -> Step, carrying the token-covenant context so the harness
// drives it through a synthetic token tx (state in the NFT commitment, not baked).
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

export const bchPairingChunked: Implementation = {
  id: 'bch-pairing-chunked',
  name: 'BCH Groth16 pairing chunked (Miller boundary, multi-tx, BCH-compatible)',
  proofSystem: 'Groth16 pairing (BCH-native)',
  field: 'BN254',
  structure: 'multi-tx',
  // GENERIC covenant chunks: the running state lives in the token NFT commitment,
  // NOT baked into the program. One fixed set of lockings verifies any proof; the
  // benchmark confirms it empirically via extraValidProofs (a distinct proof, same
  // lockings). (Token-safety pinning of category/capability/single-token-flow is a
  // separate hardening step; tokenSafetyEnforced is left at its default.)
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the BN254 Groth16 Miller boundary e(-A,B)*e(alpha,beta)*' +
    'e(vk_x,gamma)*e(C,delta) split across transactions so EVERY step fits one ' +
    'BCH input (op-cost <=8,032,800, scripts <=10,000 B). One prepared batched ' +
    'optimal-ate loop shares each fp12Sqr across the three runtime-dependent pairs; ' +
    'fixed e(alpha,beta) is omitted and its precomputed raw Miller value is multiplied ' +
    'once at the end. Fixed-G2 line coefficients are baked, so only e(-A,B) updates ' +
    'a G2 accumulator on-chain. The exact four-pair boundary is verified against the ' +
    '@noble/curves oracle. Reaches the miller-boundary ' +
    'checkpoint (the full verdict is bch-groth16-chunked).',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    // additional DISTINCT proofs (same lockings, different state/commitments) -> the
    // harness confirms runtime-generality (one program, many proofs).
    const extraValidProofs: Step[][] = (v.extraValidProofs ?? []).map((run) => run.map(toStep));
    // worst-case run: dense public inputs through the same lockings. No vk_x stage here,
    // so op-cost is ~unchanged (proof-size-independent) — recorded for the side-by-side.
    const worstCaseProof: Step[] | undefined = v.worstCaseProof?.map(toStep);
    // invalid runs: a tampered state limb (NFT-commitment mismatch) must be rejected
    // -- test it at the first Miller step and at the combine.
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
