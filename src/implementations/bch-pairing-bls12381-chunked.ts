// BCH-native BLS12-381 Groth16 PAIRING, multi-transaction — Miller loops + final
// exponentiation, every step fits ONE BCH input (op-cost <= 8,032,800, scripts
// <= 10,000 B). Same curve as nchain.
//
// The 4-pair optimal-ate pairing
//   e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta)
// computed as 4 single-pair Miller chains + a combine step (-> the Miller boundary),
// then the BLS/Hayashida-Scott final exponentiation -> the verdict (== Fp12 ONE iff
// the proof verifies), split across transactions. Each step carries its state (Miller
// f in Fp12 + the running G2 point R, or the live final-exp Fp12 values) committed as
// hash256(48-byte LE limbs) in the token NFT commitment and re-supplied in the
// witness, verified on entry/exit — the proof-agnostic covenant pattern. Proof-derived
// points ride in the committed state; VK points stay baked. The easy-part 381-iter
// Fermat inverse is supplied as an unlocking witness and verified by
// fp12Mul(f, f^-1)==ONE (computing it on-chain would alone exceed one input's budget).
// Verified against @noble/curves bls12-381: combine boundary == pairingBatch(.,false)
// and finalExp(boundary)==ONE.
//
// Multi-tx counterpart of bch-pairing-bls12381-singleton (BCH-INcompatible: one
// monolithic tx needing many inputs' worth of op-cost); here every step is
// BCH-compatible. Reaches the "verify" checkpoint (the full verdict).
//
// Vectors: groth16_contract/chunked/bls12-381/build_vectors_pairing.mjs ->
// src/bch/pairing-bls12381-chunked-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string;
  covenant?: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/pairing-bls12381-chunked-vectors.json', 'utf8')) as {
  steps: RawStep[]; extraValidProofs?: RawStep[][];
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

export const bchPairingBls12381Chunked: Implementation = {
  id: 'bch-pairing-bls12381-chunked',
  name: 'BCH Groth16 pairing chunked, BLS12-381 (Miller loops + final exponentiation -> verdict, multi-tx, BCH-compatible)',
  proofSystem: 'Groth16 pairing (BCH-native)',
  field: 'BLS12-381',
  structure: 'multi-tx',
  // GENERIC covenant chunks: running state + proof-derived points in the token NFT
  // commitment, NOT baked. One fixed set of lockings verifies any proof; confirmed
  // empirically via extraValidProofs (a distinct instance, same lockings). (Token-
  // safety pinning is a separate hardening step; tokenSafetyEnforced left at default.)
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the BLS12-381 Groth16 pairing e(-A,B)*e(alpha,beta)*' +
    'e(vk_x,gamma)*e(C,delta) — 4 single-pair optimal-ate Miller loops + a combine ' +
    '(boundary = f0*f1*f2*f3) + the BLS/Hayashida-Scott final exponentiation -> verdict ' +
    '== Fp12 ONE — split across transactions so EVERY step fits one BCH input. ' +
    'Proof-agnostic covenant: Miller f+R / live final-exp values + proof-derived points ' +
    'ride in the token NFT commitment (48-byte limbs); the easy-part Fermat inverse is a ' +
    'verified unlocking witness. Verified vs @noble/curves bls12-381. Multi-tx ' +
    'counterpart of bch-pairing-bls12381-singleton; same curve as nchain.',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const extraValidProofs: Step[][] = (v.extraValidProofs ?? []).map((run) => run.map(toStep));
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    return { valid, extraValidProofs, invalid };
  },
};
