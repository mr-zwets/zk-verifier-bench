// BCH-native covenant-threaded chunked BLS12-381 Groth16 verifier (Phase 2), multi-transaction.
//
// The covenant-threaded counterpart of bch-groth16-bls12381-chunked: the same
// complete BLS12-381 verifier split so every step fits one BCH input, but here the
// cross-step state thread is carried through a covenant: category-anchored,
// transcript-bound, and forward-chained.
//
//   g2check (EIP-197 input validation, [|x|]B==psi(B), BATON GENESIS)  ->  4 chunks
//   vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus, runtime MSM)        -> 12 chunks
//   baked-G2 + prepared-VK optimal-ate Miller (boundary)               -> 30 chunks
//   final exponentiation (witnessed fp12 inverse) -> verdict==Fp12.ONE -> 22 chunks
//                                                                       = 68 chunks
//
// Covenant-thread construction (ported from the BN254 covenant verifier, exercised in
// groth16_cashscript/chunked/bls12-381/adversarial_covenant.mjs, 110/0):
//   - TRANSCRIPT anchors: NFT commitment = T0 = hash256(A,B,C), then T1 =
//     hash256(T0,in0,in1,vk); the Miller re-derives + binds T1, the seam re-emits it,
//     so the pairing uses the points that g2check validated / vk_x computed.
//   - FORWARD-CHAIN: each non-terminal chunk pins hash256(tx.outputs[0].lockingBytecode)
//     == the baked hash of the NEXT chunk -> the next/ordered step is fixed.
//   - CATEGORY ANCHOR + GENESIS BATON: category C originates by spending a deploy-time
//     MINTING baton through g2check_00 (mints the mutable thread token + recreates the baton).
//   - TERMINAL strips capability (mutable thread -> immutable 'none') for the verdict token.
//   - SHARED-TOWER RELOCATION + SINGLE-HASH-BIND: each deployed locking carries the tower fns
//     as hash-bound witness bodies (one blob-hash for ALL bodies, OP_EQUALVERIFY before any
//     OP_SPLIT/OP_DEFINE); a tampered witness body fails the bind.
//   - WITNESSED INVERSE: the BLS final exponentiation witnesses Fp12.inv(boundary); a wrong /
//     non-canonical / zero witness fails fp12Mul(z,f)==ONE.
//
// Vectors: groth16_cashscript/chunked/bls12-381/emit_bench_vectors.mjs ->
// src/bch/groth16-bls12381-chunked-covenant-vectors.json. The genesis chunk spends a minting
// baton and emits [thread, baton]; the terminal strips to immutable — both modeled via the
// covenant `inputCapability` / `secondOutputBaton` extensions (see harness/vm.ts). Same tx
// shape as the BN254 covenant verifier, so the existing harness patch covers it unchanged.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking?: string; checkpoint?: string;
  kind: 'genesis' | 'forward' | 'terminal'; expectReject?: boolean;
  covenant: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-chunked-covenant-vectors.json', 'utf8')) as {
  steps: RawStep[];
  // a VALIDATED Groth16 re-randomization (A'=A·r, B'=B·r⁻¹, C'=C; public inputs UNCHANGED; r=2024):
  // SAME verdict + SAME lockings as `steps`, DISTINCT unlockings/commitments => a 2nd accepting
  // proof under one fixed locking (proof-independence: the verifier bakes only the VK + structure).
  extraProofSteps?: RawStep[];
  // adversarial-point runs the verifier MUST reject: off-curve A (G1 cubic check, b=4) and
  // off-subgroup B (on-curve G2 outside the order-r subgroup; rejected at the [|x|]B==psi(B) chunk).
  invalidInputSteps?: { offCurveA: RawStep[]; offSubgroupB: RawStep[] };
};

// map a raw step -> Step, attaching the covenant context. A genesis chunk spends a MINTING
// baton (inputCapability) and emits a second baton output; a terminal chunk's output[0] is
// the immutable ('none') verdict token. Forward chunks are the legacy mutable->mutable shape.
const toStep = (s: RawStep): Step => ({
  label: s.label,
  lockingBytecode: hexToBin(s.locking),
  unlockingBytecode: hexToBin(s.unlocking),
  checkpoint: s.checkpoint,
  covenant: {
    category: hexToBin(s.covenant.category),
    capability: s.covenant.capability,
    inCommitment: hexToBin(s.covenant.inCommitment),
    outCommitment: hexToBin(s.covenant.outCommitment),
    outLockingBytecode: hexToBin(s.covenant.outLockingBytecode),
    inputCapability: s.kind === 'genesis' ? 'minting' : s.kind === 'terminal' ? 'mutable' : s.covenant.capability,
    secondOutputBaton: s.kind === 'genesis',
  },
});

export const bchGroth16Bls12381ChunkedCovenant: Implementation = {
  id: 'bch-groth16-bls12381-chunked-covenant',
  name: 'BCH Groth16 verifier, chunked, BLS12-381, covenant-threaded (68 chunks: baton genesis + transcript + forward-chain, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  // The thread is pinned by category continuity (C), capability constraint (mutable
  // thread, minting baton, immutable verdict), single-token flow, forward-chain locking, and
  // transcript binding of the pairing inputs. Enforced + adversarially tested (110/0).
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the COMPLETE BLS12-381 Groth16 verifier in 68 covenant-threaded ' +
    'chunks with a transcript-bound cross-step thread. g2check EIP-197 input validation ' +
    '([|x|]B==psi(B), baton genesis) -> vk_x runtime MSM -> baked-G2 + prepared-VK optimal-ate ' +
    'Miller -> final exponentiation (witnessed fp12 inverse) -> verdict==Fp12.ONE. State ' +
    'threaded as transcript-anchored NFT commitments (T0=hash(A,B,C), T1=hash(T0,in0,in1,vk)), ' +
    'forward-chain locking pins, a minting-baton category genesis, shared-tower relocation + ' +
    'single-hash-bind (tower fns hash-bound in the witness), and the BLS witnessed-inverse ' +
    'final exponentiation. The pairing is bound to the validated/computed points; chunks run ' +
    'in order, each pinned to the next, with the token category anchored ' +
    '(adversarial_covenant.mjs: 110/0). BCH-compatible: every step validates on the real BCH ' +
    '2026 VM (op-cost <= 8,032,800, scripts <= 10,000 B).',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    // tampered state limb (NFT-commitment / transcript mismatch) must be rejected -> test at
    // the genesis step, the vk_x assert (last vkx), the miller boundary (last miller), and the
    // terminal verdict (last finalexp). Indices: g2check 0-3, vkx 4-15, miller 16-45, finalexp 46-67.
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking!) }];
    const invalid: Step[][] = [tampered(0), tampered(15), tampered(45), tampered(valid.length - 1)];
    // 2nd VALID proof: a re-randomized Groth16 instance (same VK, same public inputs, same
    // verdict) verified against the SAME lockings -> empirically runtime-general (runtimeGeneral).
    const extraValidProofs: Step[][] = v.extraProofSteps ? [v.extraProofSteps.map(toStep)] : [];
    // adversarial inputs: off-curve A and off-subgroup B; each run must be REJECTED (EIP-197
    // on-curve + order-r G2-subgroup checks). Each run's last step is the rejecting chunk.
    const invalidInputs: Step[][] = v.invalidInputSteps
      ? [v.invalidInputSteps.offCurveA.map(toStep), v.invalidInputSteps.offSubgroupB.map(toStep)]
      : [];
    return { valid, invalid, extraValidProofs, invalidInputs };
  },
};
