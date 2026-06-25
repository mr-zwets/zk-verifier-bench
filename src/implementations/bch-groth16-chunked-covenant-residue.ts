// BCH-native covenant-threaded chunked Groth16 verifier — RESIDUE stack (BN254).
//
// A covenant-threaded Groth16 verifier with two op-cost levers that collapse the heaviest stages:
//   g2check (EIP-197 input validation, BATON GENESIS)              -> 4 chunks  (FAST-G2 endo,
//                                                                      ePrint 2022/348; was 8)
//   vk_x = IC0 + in0*IC1 + in1*IC2 (Shamir/Straus, runtime MSM)    -> 8 chunks
//   baked-G2 + prepared-VK Miller, c^-(6x+2) FUSED into the loop   -> 23 chunks (fused-miller)
//   witnessed-residue final-exp tail (ePrint 2024/640) -> verdict  -> 1 chunk   (was 12)
//                                                                    = 36 chunks
//
// The final-exponentiation HARD PART (192 cyclotomic squarings) is replaced by the witnessed
// residue relation: the prover supplies c in Fp12, the fused Miller folds c^-(6x+2) into the
// boundary (fF = fRaw·c^-(6x+2)), and the terminal tail checks  fF·w·c^(q²) == c^q·c^(q³)
// (<=>  c^λ == fRaw·w  <=>  finalExp(fRaw)==1). Witness constraints:
//   - c per-limb canonical (0<=c_j<p, 12 OP_MOD) + c·cInv==ONE gate (pins cInv, c!=0)
//   - w in Fp6 (odd Fp12 limbs == 0) AND w in the baked 27-coset {ω^j}
//   - ONE committed (c,cInv) threaded through all fused chunks + tail (c^q,c^q²,c^q³ on-chain)
//   - c bound into T1 (covIn at the fused-Miller genesis)
//
// Covenant-thread construction is identical to bch-groth16-chunked-covenant (transcript anchors
// T0=hash(A,B,C), T1; forward-chain locking pins; minting-baton category genesis; shared-tower
// relocation). The fast-G2 endo check + the residue final-exp are the only stage changes.
//
// Vectors: groth16_cashscript/chunked/pairing/{emit,assemble}_residue_vectors.mjs ->
// src/bch/groth16-chunked-covenant-residue-vectors.json (deployed P2SH32, sized + driven on the
// STANDARD BCH-2026 VM). The genesis chunk spends a minting baton and emits [thread, baton]; the
// terminal strips to immutable.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking?: string; checkpoint?: string;
  kind: 'genesis' | 'forward' | 'terminal'; expectReject?: boolean;
  covenant: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-chunked-covenant-residue-vectors.json', 'utf8')) as {
  steps: RawStep[];
  // a VALIDATED Groth16 re-randomization (A'=A·r, B'=B·r⁻¹, C'=C; public inputs UNCHANGED; r=2024):
  // SAME verdict + SAME lockings, DISTINCT unlockings => a 2nd accepting proof under one fixed
  // locking (proof-independence: the verifier bakes only the VK + structure).
  extraProofSteps?: RawStep[];
  // adversarial-point runs the verifier MUST reject: off-curve A (G1 cubic check at genesis) and
  // off-subgroup B (on-curve G2 outside the order-r subgroup; rejected at the fast-G2 endo chunk).
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

export const bchGroth16ChunkedCovenantResidue: Implementation = {
  id: 'bch-groth16-chunked-covenant-residue',
  name: 'BCH Groth16 verifier, chunked, covenant-threaded, RESIDUE final-exp + fast-G2 (36 chunks, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the COMPLETE Groth16 verifier in 36 covenant-threaded chunks with a ' +
    'transcript-bound cross-step thread, using two op-cost levers over the 48-chunk baseline. ' +
    'g2check EIP-197 input validation via the FAST-G2 endomorphism subgroup check (ePrint 2022/348, ' +
    'baton genesis, 4 chunks) -> vk_x runtime MSM (8 chunks) -> baked-G2 + prepared-VK optimal-ate ' +
    'Miller with the c^-(6x+2) residue factor FUSED into the loop (23 chunks) -> witnessed-residue ' +
    'final-exponentiation tail (ePrint 2024/640: c per-limb canonical + c·cInv==ONE + w in Fp6/27-coset ' +
    '+ c transcript-bound; verdict fF·w·c^q2==c^q·c^q3, 1 chunk). State threaded as transcript-anchored ' +
    'NFT commitments (T0=hash(A,B,C), T1=hash(T0,in0,in1,vk_x)), forward-chain locking pins, a ' +
    'minting-baton category genesis, and shared-tower relocation. The pairing is bound to the ' +
    'validated/computed points; chunks run in order, each pinned to the next, category anchored. ' +
    'BCH-compatible: every step validates on the real BCH 2026 ' +
    'standard VM (op-cost <= 8,032,800, scripts <= 10,000 B).',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking!) }];
    // tamper at the genesis g2check, a vk_x assert, the fused-miller boundary, and the residue tail.
    const invalid: Step[][] = [tampered(0), tampered(8), tampered(valid.length - 2), tampered(valid.length - 1)];
    const extraValidProofs: Step[][] = v.extraProofSteps ? [v.extraProofSteps.map(toStep)] : [];
    const invalidInputs: Step[][] = v.invalidInputSteps
      ? [v.invalidInputSteps.offCurveA.map(toStep), v.invalidInputSteps.offSubgroupB.map(toStep)]
      : [];
    return { valid, invalid, extraValidProofs, invalidInputs };
  },
};
