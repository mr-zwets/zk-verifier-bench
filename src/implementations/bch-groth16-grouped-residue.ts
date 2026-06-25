// BCH-native Groth16 verifier — GROUPED + RESIDUE (multi-tx, multi-input). The residue-
// optimized chunk graph packed with the grouped method, fewer transactions than plain grouped.
//
// Same grouped MECHANISM as bch-groth16-grouped (intra-tx OP_INPUTBYTECODE forward-checks
// within each tx; CashToken NFT hand-off across groups), but the underlying chunk graph uses
// two op-cost levers from the residue submission (ePrint 2022/348 + 2024/640):
//   - fast-G2 endomorphism subgroup check ([x0+1]B + psi([x0]B) + psi^2([x0]B) == psi^3([2x0]B),
//     ~63-bit [x0]B walk) -> 4 chunks (vs the 128-bit [6x^2]B walk's 8)
//   - c^-(6x+2)-FUSED batched Miller + a witnessed-residue final-exp TAIL (verdict
//     fF*w*c^q2 == c^q*c^q3) collapsing the 12-chunk hard-part exponentiation to ONE chunk.
// Net: the full verifier in 41 chunks packed into 5 STANDARD (<100,000 B) transactions (vs the
// 50-chunk / 6-tx plain grouped build). One fixed set of lockings verifies any proof for the VK.
//
// Vectors: groth16_contract/chunked/grouped/build_vectors_residue.mjs ->
// src/bch/groth16-grouped-residue-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string; group: number }
interface RawGroup {
  lo: number; hi: number;
  inToken: { capability: 'none' | 'mutable' | 'minting'; commitment: string } | null;
  outToken: { capability: 'none' | 'mutable'; commitment: string } | null;
  outLocking: string | null;
}
interface RawRun { steps: RawStep[]; groups: RawGroup[] }
interface Vectors {
  category: string;
  valid: RawRun;
  extraValidProofs?: RawRun[];
  worstCaseProof?: RawRun;
  invalid?: RawRun[];
}

const v = JSON.parse(readFileSync('src/bch/groth16-grouped-residue-vectors.json', 'utf8')) as Vectors;
const CATEGORY = hexToBin(v.category);

const toRun = (run: RawRun): Step[] => {
  const inputsByGroup = run.groups.map((g) =>
    run.steps.slice(g.lo, g.hi + 1).map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) })),
  );
  return run.steps.map((s, i) => {
    const g = run.groups[s.group]!;
    return {
      label: s.label,
      lockingBytecode: hexToBin(s.locking),
      unlockingBytecode: hexToBin(s.unlocking),
      checkpoint: s.checkpoint,
      grouped: {
        group: s.group,
        index: i - g.lo,
        inputs: inputsByGroup[s.group]!,
        category: CATEGORY,
        inToken: g.inToken ? { capability: g.inToken.capability, commitment: hexToBin(g.inToken.commitment) } : undefined,
        outToken: g.outToken ? { capability: g.outToken.capability, commitment: hexToBin(g.outToken.commitment) } : undefined,
        outLockingBytecode: g.outLocking ? hexToBin(g.outLocking) : undefined,
      },
    };
  });
};

export const bchGroth16GroupedResidue: Implementation = {
  id: 'bch-groth16-grouped-residue',
  name: 'BCH Groth16 verifier, grouped + RESIDUE (37 chunks in 4 standard <100KB transactions: fast-G2 endo + precomputed e(alpha,beta) + c^-(6x+2)-fused Miller + witnessed-residue final-exp tail)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the residue-optimized full BN254 Groth16 verifier packed with the ' +
    'grouped method. fast-G2 endomorphism subgroup check (ePrint 2022/348, 4 chunks) -> vk_x ' +
    'runtime MSM -> c^-(6x+2)-FUSED batched Miller with e(alpha,beta) PRECOMPUTED (pair 1 is a VK ' +
    'constant: its Miller value is baked and multiplied in once instead of folding ~88 lines) and ' +
    'the residue witness c,cInv threaded through every chunk -> witnessed-residue final-exp TAIL ' +
    '(ePrint 2024/640: c canonical + c*cInv==ONE + w in the cubic coset {1,w27,w27^2}; verdict ' +
    'fF*w*c^q2 == c^q*c^q3), 1 chunk. 37 chunks in 4 STANDARD (<100,000 B) transactions: within each group tx the inputs ' +
    'forward-check each other via tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE), and ' +
    'across groups the running state rides a CashToken NFT commitment. Fewer transactions than ' +
    'the 50-chunk / 6-tx plain grouped build, and far under the 36-tx residue covenant chain. ' +
    'One fixed set of lockings verifies any proof for the VK. Deployed P2SH32. Every step ' +
    'validates on the real BCH 2026 standard VM (op-cost <= 8,032,800, scripts <= 10,000 B).',
  load: async () => {
    const valid = toRun(v.valid);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
