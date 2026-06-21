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

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking: string; checkpoint?: string;
  covenant?: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-chunked-vectors.json', 'utf8')) as {
  steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[];
};

// map a raw (hex) step -> Step, carrying the token-covenant context (state lives in
// the NFT commitment, not baked) so the harness drives it through a token tx.
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

export const bchGroth16Chunked: Implementation = {
  id: 'bch-groth16-chunked',
  name: 'BCH Groth16 verifier chunked (vk_x on-chain + full pairing, multi-tx, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  // GENERIC covenant chunks: each step's running state lives in the token NFT
  // commitment, NOT baked into the program. One fixed set of lockings verifies any
  // proof; the benchmark confirms it empirically via extraValidProofs (a distinct
  // proof, same lockings). (Token-safety pinning of category/capability/single-token
  // is a separate hardening step; tokenSafetyEnforced is left at its default.)
  proofBinding: 'runtime',
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
    const valid: Step[] = v.steps.map(toStep);
    // additional DISTINCT proofs (same lockings, different state/commitments) -> the
    // harness confirms runtime-generality (one program graph, many proofs).
    const extraValidProofs: Step[][] = (v.extraValidProofs ?? []).map((run) => run.map(toStep));
    // worst-case run: dense public inputs (2^253-1) through the same lockings. The vk_x
    // prefix pays for nearly every scalar position; op-cost rises but the step graph is
    // unchanged (worst-case-sized windows). Reported as benchmarks.worstCase.
    const worstCaseProof: Step[] | undefined = v.worstCaseProof?.map(toStep);
    // tampered state limb (NFT-commitment mismatch) must be rejected — test at the
    // first vk_x step and at the final verdict step.
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking) }];
    const invalid: Step[][] = [tampered(0), tampered(valid.length - 1)];
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
