// BCH-native covenant-threaded chunked Groth16 verifier — RESIDUE stack (BN254).
//
// Source-reproducible covenant graph:
//   g2check (EIP-197 input validation, minting-baton genesis)       -> 3 chunks
//   vk_x = IC0 + in0*IC1 + in1*IC2 (four-scalar GLV MSM)           -> 4 chunks
//   prepared-VK Miller, c^-(6x+2) folded into the loop, with the
//   witnessed-residue verdict fused into the terminal chunk         -> 21 chunks
//                                                                     = 28 chunks
//
// The final-exponentiation HARD PART (192 cyclotomic squarings) is replaced by the witnessed
// residue relation: the prover supplies c in Fp12, the fused Miller folds c^-(6x+2) into the
// boundary (fF = fRaw·c^-(6x+2)), and the terminal checks fF·w·c^(q²) == c^q·c^(q³)
// (<=>  c^λ == fRaw·w  <=>  finalExp(fRaw)==1). Witness constraints:
//   - c and cInv per-limb canonical (0<=limb<p) + c·cInv==ONE gate (pins cInv, c!=0)
//   - w in Fp6 (odd Fp12 limbs == 0) AND w in the baked 27-coset {ω^j}
//   - one (c,cInv) pair introduced at the Miller genesis, committed by its first output,
//     threaded through every remaining Miller chunk, and checked at the terminal
//
// The fast-G2 terminal emits the exact validated (-A,B,C) tuple. GLV carries that tuple while
// computing vk_x, then emits exactly (-A,B,C,vk_x) for the stage-bound Miller genesis. State
// limbs are serialized canonically in 32 bytes. Every nonterminal contract pins its actual
// successor P2SH32 locking; the mutable token thread terminates as an immutable NFT.
//
// Vectors: groth16_cashscript/chunked/pairing/generate_covenant_residue.mjs ->
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
  // A second independently minted proof with different canonical public inputs: same lockings,
  // distinct unlockings, demonstrating that the verifier bakes only the VK and structure.
  extraProofSteps?: RawStep[];
  worstCaseSteps?: RawStep[];
  // Invalid-input runs the verifier MUST reject: a non-canonical coordinate, off-curve A/C
  // (G1 cubic checks), and on-curve G2 outside the order-r subgroup.
  invalidInputSteps?: { nonCanonicalA: RawStep[]; offCurveA: RawStep[]; offCurveC: RawStep[]; offSubgroupB: RawStep[] };
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
  name: 'BCH Groth16 verifier, chunked, covenant-threaded, GLV + residue (28 chunks, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the complete Groth16 verifier in 28 covenant-threaded chunks. ' +
    'g2check EIP-197 input validation via the FAST-G2 endomorphism subgroup check (ePrint 2022/348, ' +
    'minting-baton genesis, 3 chunks) -> four-scalar GLV vk_x runtime MSM (4 chunks) -> prepared-VK ' +
    'optimal-ate Miller with c^-(6x+2) folded into the loop and the witnessed-residue verdict fused ' +
    'into its terminal chunk (21 chunks; ePrint 2024/640). The validated (-A,B,C) tuple is carried ' +
    'through GLV and the Miller genesis consumes exactly (-A,B,C,vk_x), preventing cross-proof stage ' +
    'splices. Canonical 32-byte state limbs ride in NFT commitments. Every nonterminal contract pins ' +
    'the actual successor P2SH32 locking; category and capability are fixed; the genesis recreates its ' +
    'minting baton; the mutable thread terminates as an immutable NFT. Byte-exact vectors reproduce ' +
    'from groth16_cashscript/chunked/pairing/generate_covenant_residue.mjs. Every step validates on the BCH 2026 ' +
    'standard VM (op-cost <= 8,032,800, scripts <= 10,000 B).',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking!) }];
    // Tamper at the G2 genesis, GLV boundary, late Miller state, and terminal verdict.
    const invalid: Step[][] = [tampered(0), tampered(6), tampered(valid.length - 2), tampered(valid.length - 1)];
    const extraValidProofs: Step[][] = [
      ...(v.extraProofSteps ? [v.extraProofSteps.map(toStep)] : []),
      ...(v.worstCaseSteps ? [v.worstCaseSteps.map(toStep)] : []),
    ];
    const worstCaseProof: Step[] | undefined = v.worstCaseSteps?.map(toStep);
    const invalidInputs: Step[][] = v.invalidInputSteps
      ? Object.values(v.invalidInputSteps).map((steps) => steps.map(toStep))
      : [];
    return { valid, invalid, extraValidProofs, worstCaseProof, invalidInputs };
  },
};
