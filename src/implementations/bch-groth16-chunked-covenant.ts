// BCH-native covenant-threaded chunked Groth16 verifier (E1+E2+E3), multi-transaction.
//
// The covenant-threaded counterpart of bch-groth16-chunked. Same complete verifier
// split so every step fits one BCH input, but here the cross-step state thread is carried
// through a covenant: category-anchored, transcript-bound, and forward-chained.
//
//   g2check (EIP-197 input validation, BATON GENESIS)            -> 8 chunks
//   vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus, runtime MSM)  -> 8 chunks
//   baked-G2 + prepared-VK optimal-ate Miller (boundary)         -> 21 chunks
//   final exponentiation (witnessed fp12 inverse) -> verdict==1  -> 11 chunks
//                                                                  = 48 chunks
//
// Covenant-thread construction (exercised in adversarial_covenant.mjs, 81/0):
//   - TRANSCRIPT anchors: NFT commitment = T0 = hash256(A,B,C), then T1 =
//     hash256(T0,in0,in1,vk_x); the Miller re-derives + binds T1, the seam re-emits it,
//     so the pairing uses the points that g2check validated / vk_x computed.
//   - FORWARD-CHAIN: each non-terminal chunk pins hash256(tx.outputs[0].lockingBytecode)
//     == the baked hash of the NEXT chunk -> the next/ordered step is fixed.
//   - CATEGORY ANCHOR + GENESIS BATON: category C originates by spending a deploy-time
//     MINTING baton through g2check_00 (mints the mutable thread token + recreates the baton,
//     custody-pinned to the chunk).
//   - TERMINAL strips capability (mutable thread -> immutable 'none') for the verdict token.
//   - SHARED-TOWER RELOCATION: each deployed locking carries the tower fns as hash-bound
//     witness bodies (OP_DUP OP_HASH256 <const> OP_EQUALVERIFY ... OP_DEFINE), shrinking the
//     locking; a tampered witness body fails OP_EQUALVERIFY.
//
// Vectors: groth16_cashscript/chunked/pairing/emit_bench_vectors.mjs ->
// src/bch/groth16-chunked-covenant-vectors.json. The genesis chunk spends a minting baton and
// emits [thread, baton]; the terminal strips to immutable — both modeled via the covenant
// `inputCapability` / `secondOutputBaton` extensions (see harness/vm.ts).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking?: string; checkpoint?: string;
  kind: 'genesis' | 'forward' | 'terminal'; expectReject?: boolean;
  covenant: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-chunked-covenant-vectors.json', 'utf8')) as {
  steps: RawStep[];
  // a VALIDATED Groth16 re-randomization (A'=A·r, B'=B·r⁻¹, C'=C; public inputs UNCHANGED; r=2024):
  // SAME verdict + SAME lockings as `steps`, DISTINCT unlockings/commitments => a 2nd accepting
  // proof under one fixed locking (proof-independence: the verifier bakes only the VK + structure).
  extraProofSteps?: RawStep[];
  // adversarial-point runs the verifier MUST reject: off-curve A (G1 cubic check at genesis) and
  // off-subgroup B (on-curve G2 outside the order-r subgroup; rejected at the [6x^2]B==psi(B) chunk).
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
    // genesis SPENDS a minting baton; the terminal SPENDS the mutable thread token (its
    // output is the immutable 'none' verdict). Forward chunks: input == output capability.
    inputCapability: s.kind === 'genesis' ? 'minting' : s.kind === 'terminal' ? 'mutable' : s.covenant.capability,
    secondOutputBaton: s.kind === 'genesis',
  },
});

export const bchGroth16ChunkedCovenant: Implementation = {
  id: 'bch-groth16-chunked-covenant',
  name: 'BCH Groth16 verifier, chunked, covenant-threaded (48 chunks: baton genesis + transcript + forward-chain, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  // The thread is pinned by category continuity (C), capability constraint (mutable
  // thread, minting baton, immutable verdict), single-token flow, forward-chain locking, and
  // transcript binding of the pairing inputs. Enforced + adversarially tested (see source).
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in 48 covenant-threaded chunks with ' +
    'a transcript-bound cross-step thread. g2check EIP-197 input validation (baton genesis) -> ' +
    'vk_x runtime MSM -> baked-G2 + prepared-VK optimal-ate Miller -> final exponentiation ' +
    '(witnessed fp12 inverse) -> verdict==1. State threaded as transcript-anchored NFT ' +
    'commitments (T0=hash(A,B,C), T1=hash(T0,in0,in1,vk_x)), forward-chain locking pins, a ' +
    'minting-baton category genesis, and shared-tower relocation (tower fns hash-bound in the ' +
    'witness). The pairing is bound to the validated/computed points; chunks run in order, ' +
    'each pinned to the next, with the token category anchored (adversarial_covenant.mjs: 81/0). ' +
    'BCH-compatible: every step validates on the real BCH 2026 VM (op-cost <= 8,032,800, ' +
    'scripts <= 10,000 B).',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    // tampered state limb (NFT-commitment / transcript mismatch) must be rejected -> test at
    // the genesis step, the vk_x assert, the miller boundary, and the terminal verdict.
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking!) }];
    const invalid: Step[][] = [tampered(0), tampered(15), tampered(36), tampered(valid.length - 1)];
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
