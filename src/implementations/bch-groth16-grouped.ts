// BCH-native Groth16 verifier — GROUPED (multi-tx, multi-input), the deployable middle
// ground between the two other chunked methods.
//
//   - bch-groth16-chunked / -covenant: 54 SEQUENTIAL transactions, one chunk each. That is a
//     54-deep unconfirmed chain — it exceeds BCH's default mempool ancestor/descendant limit
//     (50), so it cannot be broadcast as one standard unconfirmed package.
//   - bch-groth16-intratx: the whole verifier in ONE transaction. Fine at consensus, but the
//     tx is ~0.5 MB — over the 100,000-byte standard size, so it is NON-standard (mine-direct).
//   - bch-groth16-grouped (this): the SAME 54 chunks packed into ~6 STANDARD (<100,000 B)
//     transactions. Comfortably under the chain limit AND relayable under standard policy.
//
// Mechanism — a hybrid of the other two. WITHIN each group transaction the chunks bind each
// other exactly as in the intra-tx method: every chunk FORWARD-checks its successor's incoming
// blob via tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE). An input cannot spend an
// output created by its own transaction, so the cross-GROUP hand-off rides a CashToken NFT
// commitment exactly as in the covenant method: a group's last chunk commits hash256(outBlob)
// to output[0]'s NFT, and the next group's first chunk binds its inBlob via
// require(tx.inputs[0].nftCommitment == hash256(inBlob)). The token thread chains all groups in
// order. Group boundaries sit only at within-stage full-state links, so the stage-internal
// cross/terminal binding is preserved exactly as in the intra-tx build.
//
// Same validated chunk math as bch-groth16-chunked / -intratx; one fixed set of lockings
// verifies any proof for the VK. Vectors: groth16_contract/chunked/grouped/build_vectors.mjs ->
// src/bch/groth16-grouped-vectors.json.
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

const v = JSON.parse(readFileSync('src/bch/groth16-grouped-vectors.json', 'utf8')) as Vectors;
const CATEGORY = hexToBin(v.category);

// Turn one run into Step[]: partition by group, build each group's shared input array, and
// attach the grouped context (group index, position within the group, the group's inputs, and
// the cross-group token config) so the harness evaluates each input against its group's tx.
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

export const bchGroth16Grouped: Implementation = {
  id: 'bch-groth16-grouped',
  name: 'BCH Groth16 verifier, grouped (54 chunks in ~6 standard <100KB transactions: intra-tx forward-checks within each tx, CashToken hand-off across them)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  // Cross-group hand-off pins the token thread: each group's last chunk requires
  // tx.outputs[0].nftCommitment == hash256(outBlob) AND tx.outputs[0].tokenCategory ==
  // tx.inputs[0].tokenCategory (category + capability continuity — the BCH tokenCategory
  // introspection includes the capability byte), perpetuated mutable end-to-end. Verified
  // adversarially: the covout chunk rejects a wrong category / capability / commitment / missing
  // output token. Same enforcement as bch-groth16-grouped-residue and the covenant builds.
  tokenSafetyEnforced: true,
  source:
    'BCH-native CashScript: the full BN254 Groth16 verifier (validate G2 inputs -> vk_x -> ' +
    'batched 4-pair optimal-ate Miller -> final exponentiation -> assert product==1), the 54 ' +
    'chunks packed into ~6 STANDARD (<100,000 B) transactions. The hybrid of bch-groth16-intratx ' +
    'and bch-groth16-chunked: within each group tx the inputs forward-check each other via ' +
    'tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE), and across groups the running state ' +
    'rides a CashToken NFT commitment — a group\'s last chunk commits hash256(outBlob) to ' +
    'output[0], the next group\'s first chunk binds its inBlob via tx.inputs[0].nftCommitment == ' +
    'hash256(inBlob). The token thread chains the groups in order. Unlike the 54-tx covenant ' +
    'chain (which exceeds the default 50-deep mempool ancestor limit) and the single 0.5 MB ' +
    'intra-tx bundle (non-standard, mine-direct), every grouped tx is under the 100,000-byte ' +
    'standard size and the run is ~6 deep — relayable under default standard policy. Same chunk ' +
    'math as bch-groth16-chunked / -intratx; one fixed set of lockings verifies any proof for ' +
    'the VK. Deployed P2SH32 (each chunk\'s redeem rides in the scriptSig, counting toward the ' +
    'op-cost budget).',
  load: async () => {
    const valid = toRun(v.valid);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
