// BCH-native covenant-threaded chunked Groth16 verifier, residue final exponentiation (BLS12-381).
//
// Source-reproducible covenant graph of 27 single-input transactions (vector file generator
// chunked/bls12-381/generate_covenant_residue.mjs):
//   full-stage GLV vk_x = IC0 + in0*IC1 + in1*IC2 (baton genesis + 4 forward)  ->  5 transactions
//     the last GLV step takes (A, B, C) as witnesses and commits (-A, B, C, vk_x) exactly
//   input-validation-fused prepared Miller loop (64-NAF of |x|), c^-|x| folded  -> 21 transactions
//     the first Miller step range-checks A, B, C, vk_x, c, cInv, checks A and C on the curve and
//     B on the twist; the last one requires Rz != 0 and R == -psi(B) (exact G2 subgroup endpoint)
//   one-input Fp6 residue verdict (immutable terminal)                         ->  1 transaction
//
// Residue: c and cInv are committed at the Miller genesis and carried exactly. The terminal checks
// c*cInv == 1, w in Fp6 (six limbs, upper Fp12 half fixed to zero) and fF*w == frob(c,1). This
// is sound because r | p + |x| and p^6 - 1 divides (p^12 - 1)/r; zero is excluded by c*cInv == 1.
// There is no standalone g2check stage; the old 49-chunk layout (g2check, Shamir vk_x, 32 Miller
// chunks) is obsolete.
//
// Token lifecycle (enforced in every redeem): the genesis spends the minting baton and recreates
// it at its own locking with an empty commitment; there is exactly one input and the outputs are
// fixed; the mutable state thread carries hash256 of the 48-byte state limbs; every nonterminal pins
// its successor P2SH32 locking; and the terminal emits an immutable empty-commitment verdict locked
// to itself.
// Deployment premises (composition argument: groth16_cashscript chunked/pairing/README.md and
// chunked/bls12-381/README.md, "Covenant-residue composition"): the category genesis must create
// no NFT of the category other than minting batons at the genesis locking, and the bench category
// 0xbe..be is a placeholder. The verdict is unspendable and names no statement; a consumer reads
// (n0, n1) from the genesis unlocking at the end of the verdict's unique one-input ancestry:
// push 6 is in0 (n0) and push 5 is in1 (n1).
//
// Committed proof: 207,633 script B (945 locking + 206,688 unlocking) across 27 transactions;
// 156,963,474 op; largest step 7,592,796 op. The vector file's worst-case run (not loaded here)
// totals 190,454,163 op with largest step 7,845,354 op (the file's maxStepOperationCost). Evaluated on the standard BCH 2026 VM. The
// synthetic-key caveat of the BLS12-381 checkpoint applies.
//
// Reproduction (byte-identical; both 2026-10-27 reviews): groth16_cashscript
// 35561c7a7d7f07920a6b1a3d1f3dac8906c55837 (0cff585 also reproduces it), cashc
// compiler-optimizations-2 9fb14833713449403104c8a77cb10973130993e1, fixtures from bench 082da7c^:
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/bls12-381/generate_covenant_residue.mjs
// Shipped by bench 082da7c (co-2 regeneration).
// Vector SHA-256: 28d3778efd9bbcce198dc64e3217106fe0ca994b3a2ff70d856a0658da2cce95
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// 752daa10f3d52dd7f90a128d3eedaed23d54cdaa60ffc9365ad49998c1f4b072
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bls12381CovenantResidueProofInputs } from './groth16-proof-inputs.js';

interface RawStep {
  label: string; locking: string; unlocking: string; invalidUnlocking?: string; checkpoint?: string;
  kind: 'genesis' | 'forward' | 'terminal'; expectReject?: boolean;
  covenant: { category: string; capability: 'none' | 'mutable' | 'minting'; inCommitment: string; outCommitment: string; outLockingBytecode: string };
}
const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-chunked-covenant-residue-vectors.json', 'utf8')) as {
  steps: RawStep[];
  extraProofSteps?: RawStep[];
  worstCaseSteps?: RawStep[];
  // 17 isolated rejection runs, each a valid prefix ending in the rejecting step: point encoding
  // and curve/subgroup (nonCanonicalA, offCurveA, offCurveC, offSubgroupB, order13B), public-input
  // and GLV witness ranges, c/cInv/w ranges, and wrong canonical cInv / w.
  invalidInputSteps?: Record<string, RawStep[]>;
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
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts), located by
  // the maintainers. In each GLV input the pushes are k11, k20, k10, in1, in0 in ascending order
  // (genesis: 2, 3, 4, 5, 6). The slots named n0/n1 at pushes 6/5 (input 4: 15/14) are in0/in1;
  // the ones at pushes 4/2 (input 4: 13/11) are the GLV witnesses k10/k11. Those equal n0/n1
  // only for small scalars, as in the committed fixture, so grouping them under the same name
  // makes each mutation change all copies together. This is a mutation-test list, not a statement
  // locator; a consumer reads the statement from in0/in1 only.
  publicInputs: [
    { input: 0, push: 2, name: 'n1' }, { input: 0, push: 4, name: 'n0' }, { input: 0, push: 5, name: 'n1' },
    { input: 0, push: 6, name: 'n0' }, { input: 1, push: 2, name: 'n1' }, { input: 1, push: 4, name: 'n0' },
    { input: 1, push: 5, name: 'n1' }, { input: 1, push: 6, name: 'n0' }, { input: 2, push: 2, name: 'n1' },
    { input: 2, push: 4, name: 'n0' }, { input: 2, push: 5, name: 'n1' }, { input: 2, push: 6, name: 'n0' },
    { input: 3, push: 2, name: 'n1' }, { input: 3, push: 4, name: 'n0' }, { input: 3, push: 5, name: 'n1' },
    { input: 3, push: 6, name: 'n0' }, { input: 4, push: 11, name: 'n1' },
    { input: 4, push: 13, name: 'n0' }, { input: 4, push: 14, name: 'n1' },
    { input: 4, push: 15, name: 'n0' },
  ],
  name: 'BCH Groth16 verifier, chunked, BLS12-381, covenant-threaded, RESIDUE final-exp (27 transactions, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381CovenantResidueProofInputs,
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the complete BLS12-381 Groth16 verifier in 27 covenant-threaded ' +
    'single-input transactions. Five full-stage GLV vk_x steps start at the minting-baton genesis; ' +
    'the last one commits (-A,B,C,vk_x) exactly. 21 input-validation-fused prepared Miller steps ' +
    '(64-NAF of |x|, c^-|x| folded into the loop) range-check A, B, C, vk_x, c and cInv, check A and C ' +
    'on the curve and B on the twist, and end with the exact G2 subgroup endpoint Rz != 0 and ' +
    'R == -psi(B). A one-input Fp6 residue verdict checks c*cInv == 1, w in Fp6 and fF*w == frob(c,1). ' +
    'State rides in hash256 NFT commitments over 48-byte limbs; every nonterminal pins its successor ' +
    'P2SH32 locking; token category and capability are fixed; the genesis recreates its minting baton; ' +
    'the terminal emits an immutable empty-commitment verdict. Byte-exact vectors reproduce from ' +
    'groth16_cashscript 35561c7a7d7f07920a6b1a3d1f3dac8906c55837 with cashc ' +
    '9fb14833713449403104c8a77cb10973130993e1. BCH-compatible: every step validates on the standard ' +
    'BCH 2026 VM (op-cost <= 8,032,800, scripts <= 10,000 B).',
  load: async () => {
    const valid: Step[] = v.steps.map(toStep);
    const tampered = (i: number): Step[] => [{ ...valid[i]!, unlockingBytecode: hexToBin(v.steps[i]!.invalidUnlocking!) }];
    // tamper at the GLV genesis, a mid Miller step, the residue hand-off Miller step, and the verdict.
    const invalid: Step[][] = [tampered(0), tampered(15), tampered(valid.length - 2), tampered(valid.length - 1)];
    const extraValidProofs: Step[][] = v.extraProofSteps ? [v.extraProofSteps.map(toStep)] : [];
    // every isolated rejection run in the vector file (17), not a hand-picked subset
    const invalidInputs: Step[][] = Object.values(v.invalidInputSteps ?? {}).map((steps) => steps.map(toStep));
    return { valid, invalid, extraValidProofs, invalidInputs };
  },
};
