// BCH-native Groth16 PAIRING, multi-transaction — the BCH-compatible pairing:
// every step fits ONE BCH input (op-cost <= 8,032,800, scripts <= 10,000 B).
//
// The pre-final-exponentiation Miller boundary
//   e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta)            (an Fp12)
// computed as 4 single-pair optimal-ate Miller chains + a combine step, split
// across 133 transactions. Each step carries its state (f in Fp12 + the running
// G2 point R, or the 4 f_i for the combine) committed as hash256(40-byte LE
// limbs) and re-supplied in the witness, verified on entry and exit — the same
// stateful-covenant pattern as the chunked vk_x. Per chunk the Miller steps are
// UNROLLED with the NAF digit baked, so the body compiles once and op-cost binds
// (not size): chunks are ~4.7 KB, <=6.2M op-cost. Verified against the singleton
// oracle / @noble/curves: the combine's boundary == the golden millerHex.
//
// This is the multi-tx counterpart of bch-pairing-singleton (~1.21B op-cost,
// ~151 inputs, BCH-INcompatible): here every one of the 133 steps validates on
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
    'BCH input (op-cost <=8,032,800, scripts <=10,000 B). 4 single-pair optimal-ate ' +
    'Miller chains (f in Fp12 + running G2 point R, hash256-committed, ~5 KB/chunk, ' +
    'NAF steps unrolled with the digit baked so op-cost binds not size) + a combine ' +
    'step (boundary = f0*f1*f2*f3). Verified vs @noble/curves: combine boundary == ' +
    'golden millerHex. Multi-tx counterpart of bch-pairing-singleton (which needs ' +
    '~151 inputs); here every step is BCH-compatible. Reaches the miller-boundary ' +
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
