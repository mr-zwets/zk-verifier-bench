// BCH-native BLS12-381 Groth16 verifier — GROUPED (multi-tx, multi-input), the BLS
// counterpart of bch-groth16-grouped and the deployable middle ground between:
//
//   - bch-groth16-bls12381-chunked: ~87 SEQUENTIAL transactions (one chunk each) — a chain
//     far deeper than BCH's default 50-tx mempool ancestor/descendant limit.
//   - bch-groth16-bls12381-intratx: the whole verifier in ONE ~0.7 MB transaction — over the
//     100,000-byte standard size, so non-standard (mine-direct).
//   - bch-groth16-bls12381-grouped (this): the SAME 87 chunks packed into ~9 STANDARD
//     (<100,000 B) transactions — under the chain limit AND relayable under standard policy.
//
// Mechanism (identical to the BN254 grouped, see bch-groth16-grouped): within each group tx the
// inputs forward-check via OP_INPUTBYTECODE; across groups the running state rides a CashToken
// NFT commitment (covout commits hash256(outBlob) to output[0], the next group's first chunk
// binds tx.inputs[0].nftCommitment == hash256(inBlob)); the token thread chains the groups in
// order. BLS specifics: 48-byte limbs, 4-R Miller state, the easy-part inverses ride as
// uncommitted witnesses. Same chunk math as bch-groth16-bls12381-chunked / -intratx.
//
// Vectors: groth16_contract/chunked/grouped/build_vectors_bls.mjs ->
// src/bch/groth16-bls12381-grouped-vectors.json.
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

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-grouped-vectors.json', 'utf8')) as Vectors;
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

export const bchGroth16Bls12381Grouped: Implementation = {
  id: 'bch-groth16-bls12381-grouped',
  name: 'BCH BLS12-381 Groth16 verifier, grouped (87 chunks in ~9 standard <100KB transactions: intra-tx forward-checks within each tx, CashToken hand-off across them)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the full BLS12-381 Groth16 verifier (g2check EIP-197 input ' +
    'validation -> vk_x -> batched 4-pair Miller -> final exponentiation -> assert verdict==1), ' +
    'the ~87 chunks packed into ~9 STANDARD (<100,000 B) transactions. The hybrid of ' +
    'bch-groth16-bls12381-intratx and bch-groth16-bls12381-chunked: within each group tx the ' +
    'inputs forward-check each other via tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE), ' +
    'and across groups the running state rides a CashToken NFT commitment — a group\'s last chunk ' +
    'commits hash256(outBlob) to output[0], the next group\'s first chunk binds its inBlob via ' +
    'tx.inputs[0].nftCommitment == hash256(inBlob). The token thread chains the groups in order. ' +
    'Unlike the ~87-tx covenant chain (far past the default 50-deep mempool ancestor limit) and ' +
    'the single ~0.7 MB intra-tx bundle (non-standard, mine-direct), every grouped tx is under ' +
    'the 100,000-byte standard size and the run is ~9 deep — relayable under default standard ' +
    'policy. 48-byte limbs, 4-R Miller state, easy-part inverses as uncommitted witnesses. Same ' +
    'chunk math as bch-groth16-bls12381-chunked / -intratx; one fixed set of lockings verifies ' +
    'any proof for the VK. Deployed P2SH32.',
  load: async () => {
    const valid = toRun(v.valid);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
