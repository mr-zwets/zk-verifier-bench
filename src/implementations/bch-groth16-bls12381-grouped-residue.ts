// BCH-native BLS12-381 Groth16 verifier — GROUPED + RESIDUE (multi-tx, multi-input). The BLS
// counterpart of bch-groth16-grouped-residue, and the deployable, residue-optimized alternative
// to the ~49-tx covenant-residue chain: the SAME witnessed-residue chunk graph packed into ~5
// STANDARD (<100,000 B) transactions instead of ~49 sequential ones (well under BCH's default
// 50-tx mempool ancestor/descendant limit, and relayable under standard policy).
//
// Chunk graph (residue-optimized): g2check EIP-197 G2 subgroup validation -> GLV 4-scalar vk_x MSM
// -> c^-|x|-FUSED prepared-VK batched Miller (e(alpha,beta) baked; only e(-A,B) runs on-chain G2
// arithmetic) -> witnessed-residue tail. The Hayashida-Scott hard-part final exponentiation (23
// chunks in the plain grouped build) collapses to the residue tail: a ((w^|x|)*w)^9 mu_(27A)
// witness-subgroup walk plus the fF*w == frob(c,1) verdict (lambda = p + |x|). The residue witness
// (c, cInv) threads through every fused-Miller chunk; w enters the tail as an uncommitted witness.
//
// Mechanism (identical to bch-groth16-bls12381-grouped): within each group tx the inputs
// forward-check via OP_INPUTBYTECODE; across groups the running state rides a mutable CashToken NFT
// commitment (covout commits hash256(outBlob) to output[0], the next group's first chunk binds
// tx.inputs[0].nftCommitment == hash256(inBlob)); the token thread chains the groups in order.
//
// Vectors: groth16_contract/chunked/grouped/build_vectors_residue_bls.mjs ->
// src/bch/groth16-bls12381-grouped-residue-vectors.json.
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
interface Vectors { category: string; valid: RawRun; extraValidProofs?: RawRun[]; worstCaseProof?: RawRun; invalid?: RawRun[] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-grouped-residue-vectors.json', 'utf8')) as Vectors;
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

export const bchGroth16Bls12381GroupedResidue: Implementation = {
  id: 'bch-groth16-bls12381-grouped-residue',
  name: 'BCH BLS12-381 Groth16 verifier, grouped + residue (41 chunks in 5 standard <100KB transactions: GLV vk_x, fused Miller, witnessed-residue tail; intra-tx forward-checks within each tx, CashToken hand-off across them)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  // Cross-group hand-off pins the token thread: each group's last chunk requires
  // tx.outputs[0].nftCommitment == hash256(outBlob) AND tx.outputs[0].tokenCategory ==
  // tx.inputs[0].tokenCategory (category + capability continuity), perpetuated mutable end-to-end.
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the full BLS12-381 Groth16 verifier with the witnessed-residue final ' +
    'exponentiation (ePrint 2024/640 adapted to BLS12-381), packed grouped. Chunk graph: g2check ' +
    'EIP-197 G2 subgroup validation -> GLV 4-scalar 128-bit vk_x Straus (baked subset-sum table) -> ' +
    'c^-|x|-FUSED prepared-VK batched Miller (e(alpha,beta) baked as a constant, (vk_x,gamma)/(C,delta) ' +
    'line coeffs baked, only e(-A,B) runs on-chain G2 arithmetic; c^-|x| folded into the shared f) -> ' +
    'witnessed-residue tail (the 23-chunk Hayashida-Scott hard part collapses to a ((w^|x|)*w)^9 ' +
    'mu_(27A) witness-subgroup walk + the fF*w == frob(c,1) verdict, lambda = p + |x|). The 41 chunks ' +
    'are packed into ~5 STANDARD (<100,000 B) transactions: within each group tx the inputs ' +
    'forward-check each other via tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE), and across ' +
    'groups the running state rides a mutable CashToken NFT commitment (a group\'s last chunk commits ' +
    'hash256(outBlob) to output[0], the next group\'s first chunk binds tx.inputs[0].nftCommitment == ' +
    'hash256(inBlob)). Unlike the ~49-tx covenant-residue chain (against the default 50-deep mempool ' +
    'ancestor limit), every grouped tx is under the 100,000-byte standard size and the run is ~5 deep ' +
    '-- relayable under default standard policy. 48-byte limbs; c,cInv thread through the fused Miller ' +
    'as constant witness; w is an uncommitted tail witness. One fixed set of lockings verifies any ' +
    'proof for the VK. Deployed P2SH32.',
  load: async () => {
    const valid = toRun(v.valid);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
