import { affineSingletonProofInputs } from './groth16-proof-inputs.js';
// BCH-native COMPLETE Groth16 verifier as a single-tx contract -- the full
// verification, not just a piece: vk_x computed on-chain from the public inputs,
// then the pairing check.
//
//   vk_x = IC0 + in0*IC1 + in1*IC2                                  (on-chain, G1)
//   require( e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1 )
//
// The ENTIRE verifier in ONE CashScript contract (Groth16Verify,
// groth16_cashscript/singleton/bn254/groth16.cash + lib/): the BN254 field tower
// (Fp2/Fp6/Fp12), the G1 scalar-mult for vk_x (Jacobian double-and-add + a final
// Fermat inverse), four optimal-ate Miller loops, their product, and the final
// exponentiation. The verifying key (alpha,beta,gamma,delta,IC) is hardcoded for
// the committed instance; the proof (A,B,C) and public inputs (in0,in1) are
// supplied at RUNTIME. A is negated in-script. The contract require()s the
// product == Fp12 ONE -- the verification verdict. Sound: vk_x is recomputed
// on-chain, so a forged vk_x cannot satisfy the equation. Every field/curve op is
// a reusable function (OP_DEFINE/OP_INVOKE). Verified against @noble/curves bn254.
//
// Input validation before any pairing work: public inputs in [0, r); the 8 proof
// coordinates in [0, p) (canonical encodings); A and C on y^2 = x^3 + 3; B on the twist
// and in G2 ([6x^2]B == psi(B)). The vectors ship 18 non-canonical-coordinate proofs
// (v + p / v - p) as extra invalid runs (rangeInvalid).
//
// Same curve (BN254) as scrypt-bn256, so a direct apples-to-apples size compare.
// Locking is cashc compiler-optimizations-8 output (size objective + rescheduleStacks,
// no post-passes): 7,847 B, ~771M op-cost on the committed proof (~97 standard BCH
// inputs). It fits the 10,000-byte standard script-size cap but not one input's
// op-cost budget -- on the real BCH 2026 VM it fails op-cost density. That is the
// honest result that motivates the chunked (multi-tx) verifier.
//
// Vectors: groth16_cashscript/singleton/bn254/build_vectors_groth16.mjs ->
// src/bch/groth16-singleton-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

const v = JSON.parse(readFileSync('src/bch/groth16-singleton-vectors.json', 'utf8')) as {
  lockingOK: string;
  unlocking: string;
  invalidUnlocking: string;
  // valid proofs with one coordinate replaced by v + p or v - p (same point mod p), from
  // groth16_cashscript/singleton/bn254/range_cases.mjs; each must be REJECTED
  rangeInvalid: { label: string; unlocking: string }[];
};

// Extra DISTINCT proofs minted under the SAME VK (same locking), so the benchmark
// can confirm this verifier is runtime-general rather than a single proof baked in.
// Built by groth16_contract/singleton/bn254/gen_multiproof.mjs. proofs[0] is the
// committed instance (== v above); proofs[1..] are the additional ones.
const mp = JSON.parse(readFileSync('src/bch/groth16-singleton-multiproof-vectors.json', 'utf8')) as {
  lockingOK: string;
  proofs: { publicInputs: string[]; unlocking: string; invalidUnlocking: string; committed: boolean }[];
  worstCaseProof?: { unlocking: string };
};

// Canonical ZERO public inputs (n0 = 0, n1 = 0, both) under the same VK. A zero scalar makes its
// MSM term the point at infinity; the verifier must still keep IC0 in vk_x, so each valid proof
// must verify and each tampered input must be rejected. Built by src/bch/gen-zero-input-proofs.mjs.
const zero = JSON.parse(readFileSync('src/bch/groth16-singleton-zero-input-vectors.json', 'utf8')) as {
  proofs: { label: string; publicInputs: string[]; unlocking: string; invalid: { label: string; unlocking: string }[] }[];
};

export const bchGroth16Singleton: Implementation = {
  id: 'bch-groth16-singleton',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts)
  publicInputs: [{ input: 0, push: 1, name: 'n0' }, { input: 0, push: 0, name: 'n1' }],
  name: 'BCH Groth16 verifier singleton (vk_x on-chain + full pairing, single-tx)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: affineSingletonProofInputs,
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in ONE contract ' +
    '(Groth16Verify, singleton/bn254/groth16.cash). Computes vk_x = IC0 + in0*IC1 ' +
    '+ in1*IC2 on-chain (G1 Jacobian double-and-add + Fermat inverse), then the full ' +
    'BN254 pairing e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) and require()s == 1. ' +
    'VK hardcoded; proof (A,B,C) + public inputs (in0,in1) at RUNTIME; A negated ' +
    'in-script; public inputs in [0, r), proof coordinates in [0, p), A/C on-curve, B on ' +
    'the twist and in G2. Sound (vk_x recomputed on-chain). Verified vs @noble/curves bn254. ' +
    'Same curve as scrypt-bn256. Plain cashc output (7,847-byte locking), ~771M op-cost ' +
    '(~97 BCH inputs) -- does NOT fit one input; motivates the chunked multi-tx verifier.',
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
      // tampered zero-input statements (n0/n1 flipped off zero, or the other input bumped)
      ...zero.proofs.flatMap((p) => p.invalid.map((t) => [{ ...valid[0]!, unlockingBytecode: hexToBin(t.unlocking) }])),
      // non-canonical proof coordinates (v + p / v - p): rejected by the 0 <= v < p range checks
      ...v.rangeInvalid.map((c) => [{ ...valid[0]!, unlockingBytecode: hexToBin(c.unlocking) }]),
    ];
    // extra DISTINCT proofs (proofs[1..]) against the SAME locking -- a
    // runtime-general verifier must accept every one of them.
    const extraValidProofs: Step[][] = mp.proofs
      .filter((p) => !p.committed)
      .map((p) => [{ ...valid[0]!, unlockingBytecode: hexToBin(p.unlocking) }])
      // valid proofs for n0 = 0, n1 = 0 and n0 = n1 = 0 (vk_x must keep IC0)
      .concat(zero.proofs.map((p) => [{ ...valid[0]!, unlockingBytecode: hexToBin(p.unlocking) }]));

    // worst-case run: the dense (near-r) proof from the multiproof fixture, through the SAME
    // locking. vk_x is a variable-scalar MSM, so op-cost is proof-DEPENDENT (dense inputs pay for
    // an add nearly every iteration). Without this the entry was measured on the committed proof
    // only, understating its op-cost by ~57M versus the same-proof number a chunked entry reports.
    const worstCaseProof: Step[] | undefined = mp.worstCaseProof
      ? [{ ...valid[0]!, unlockingBytecode: hexToBin(mp.worstCaseProof.unlocking) }]
      : undefined;

    // NOTE: input validation for this SINGLE-TX verifier is not benchmarked. groth16.cash
    // does enforce the on-curve + [6x^2]B==psi(B) subgroup checks, but a swapped point is
    // also rejected by the verification equation, so a naive adversarial-input run can't
    // DEMONSTRATE the checks (see harness/adversarial.ts). It shows NOT DEMONSTRATED.
    return { valid, invalid, extraValidProofs, worstCaseProof };
  },
};
