// BCH-native covenant-threaded chunked Groth16 verifier — RESIDUE stack (BLS12-381).
//
// A covenant-threaded BLS12-381 Groth16 verifier with the witnessed-residue final-exp lever
// collapsing the 317-cyclotomic-square hard part:
//   g2check ([|x|]B==psi(B) subgroup check, BATON GENESIS)         -> 4 chunks
//   vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus, runtime MSM)    -> 12 chunks
//   baked-G2 + prepared-VK 64-NAF Miller, c^-|x| FUSED into loop   -> 32 chunks (fused-miller)
//   inverse-free witnessed-residue final-exp tail -> verdict       -> 1 chunk   (was 22)
//                                                                    = 49 chunks
//
// The final-exponentiation hard part (317 cyclotomic squarings) is replaced by the gnark-faithful
// residue relation c^(q-u) == f·w with w in Fp6: the fused Miller folds c^-|x| into the boundary
// (fF = full·c^-|x|), and the inverse-free terminal tail checks  Frob(c,1) == fF·w  (the c^|x|
// cancels). Witness constraints (faithful port of the post-gnark-#1214-fix reference):
//   - c per-limb canonical (12 OP_MOD, 48-byte p) + c·cInv==ONE gate
//   - w in Fp6 (the 6 odd Fp12 limbs == 0)
//   - ONE committed (c,cInv) threaded through all fused chunks + tail (c^q on-chain)
//   - c bound into T1 (covIn at the fused-Miller genesis)
//
// Vectors: groth16_cashscript/chunked/bls12-381/{emit,assemble}_residue_vectors.mjs ->
// src/bch/groth16-bls12381-chunked-covenant-residue-vectors.json (deployed P2SH32, sized + driven
// on the STANDARD BCH-2026 VM).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking?: string; checkpoint?: string;
  kind: 'genesis' | 'forward' | 'terminal'; expectReject?: boolean;
  covenant: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-chunked-covenant-residue-vectors.json', 'utf8')) as {
  steps: RawStep[];
  extraProofSteps?: RawStep[];
  invalidInputSteps?: { offCurveA: RawStep[]; offSubgroupB: RawStep[] };
};

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

export const bchGroth16Bls12381ChunkedCovenantResidue: Implementation = {
  id: 'bch-groth16-bls12381-chunked-covenant-residue',
  name: 'BCH Groth16 verifier, chunked, BLS12-381, covenant-threaded, RESIDUE final-exp (49 chunks, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the complete BLS12-381 Groth16 verifier in 49 covenant-threaded chunks ' +
    'with a transcript-bound cross-step thread, using the witnessed-residue final-exp lever. ' +
    'g2check [|x|]B==psi(B) G2-subgroup check (baton genesis, 4 chunks) -> vk_x ' +
    'runtime MSM (12 chunks) -> baked-G2 + prepared-VK 64-NAF Miller with c^-|x| fused into the loop ' +
    '(32 chunks) -> inverse-free witnessed-residue final-exponentiation tail (ePrint 2024/640, ' +
    'c per-limb canonical + c·cInv==ONE + w in Fp6; verdict Frob(c,1)==fF·w, 1 chunk). ' +
    'State threaded as transcript-anchored NFT commitments (T0=hash(A,B,C), T1=hash(T0,in0,in1,vk_x)), ' +
    'forward-chain locking pins, a minting-baton category genesis, and shared-tower relocation. ' +
    'BCH-compatible: every step validates on the real BCH 2026 standard VM (op-cost <= 8,032,800, ' +
    'scripts <= 10,000 B).',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking!) }];
    // tamper at the genesis g2check, a vk_x assert, the fused-miller boundary, and the residue tail.
    const invalid: Step[][] = [tampered(0), tampered(15), tampered(valid.length - 2), tampered(valid.length - 1)];
    const extraValidProofs: Step[][] = v.extraProofSteps ? [v.extraProofSteps.map(toStep)] : [];
    const invalidInputs: Step[][] = v.invalidInputSteps
      ? [v.invalidInputSteps.offCurveA.map(toStep), v.invalidInputSteps.offSubgroupB.map(toStep)]
      : [];
    return { valid, invalid, extraValidProofs, invalidInputs };
  },
};
