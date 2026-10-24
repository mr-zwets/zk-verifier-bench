// Frozen registered BN254 grouped26 correction: exact 228-byte table carrier at
// input 5 and exact 1664-byte terminal owner at input 25. Original positive argument,
// table, padding, group partition and NFT commitment/capability bytes are unchanged.
// The complete ordered graph, public statement and designated zero-FT mutable NFT
// lineage with valid ledger ancestry remain premises of the conditional theorem.
//
// Current original-positive observations: arithmetic oracle 78/78, declared BCH2026
// consensus 78/78, declared standard 75/78 (three operation-cost-density rejections).
// Native and standard admission HOLD; excluded from REGISTRY. No whole-transaction
// or network acceptance is inferred. Archived negative suites remain historical.
// This frozen repair does not execute or certify the current signed-Miller producer.
//
// Reproduce the positive-only artifact with the public source tool:
// node groth16_cashscript/chunked/grouped/repair_registered26.mjs \
//   src/bch/groth16-grouped-residue-vectors.json \
//   src/bch/groth16-grouped-residue-checked-vectors.json
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
  invalidInputs?: RawRun[];
}

const v = JSON.parse(readFileSync('src/bch/groth16-grouped-residue-checked-vectors.json', 'utf8')) as Vectors;
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
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 3, push: 0, offset: 0, encoding: 'le32', name: 'n0' },
    { input: 3, push: 0, offset: 32, encoding: 'le32', name: 'n1' },
    { input: 3, push: 0, offset: 64, encoding: 'le32', name: 'n0' },
    { input: 3, push: 0, offset: 98, encoding: 'le32', name: 'n1' },
    { input: 4, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 4, push: 0, offset: 128, encoding: 'le32', name: 'n1' },
    { input: 4, push: 0, offset: 160, encoding: 'le32', name: 'n0' },
    { input: 4, push: 0, offset: 194, encoding: 'le32', name: 'n1' },
    { input: 5, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 5, push: 0, offset: 128, encoding: 'le32', name: 'n1' },
    { input: 5, push: 0, offset: 160, encoding: 'le32', name: 'n0' },
    { input: 5, push: 0, offset: 194, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH Groth16 frozen grouped26 exact-frame correction (standalone; admission HOLD)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'multi-tx',
  proofBinding: 'runtime',
  // The cross-group hand-off pins the token thread exactly like the covenant build: each group's
  // last chunk commits hash256(outBlob) to output[0] AND requires tx.outputs[0].tokenCategory ==
  // tx.inputs[0].tokenCategory (category continuity), and the next group's first chunk binds its
  // inBlob to the spent token's commitment. Mutable token perpetuated end-to-end (genesis included)
  // — the "fixed category + perpetuated mutable commitment" model. Within a group the links are
  // sibling introspection (no token). Same enforcement as bch-groth16-chunked-covenant-residue.
  tokenSafetyEnforced: true,
  source:
    'Frozen 26-program BN254 grouped residue verifier with typed 228-byte table-carrier ' +
    'and 1664-byte terminal-state predicates. All original positive proof, public-input, ' +
    'state, table, padding, group and NFT metadata bytes are unchanged. Conditional finite ' +
    'accepted-equation soundness requires the complete ordered graph, public statement, ' +
    'finite point domain, designated zero-FT mutable NFT lineage and valid ledger ancestry. ' +
    'The current signed-Miller producer is independently unverified by this artifact repair. ' +
    'Three original graphs pass 78/78 arithmetic-oracle and 78/78 declared-consensus input ' +
    'evaluations; declared-standard acceptance is 75/78, with three cost-density rejections. ' +
    'These per-input observations do not establish whole-transaction/network admission. ' +
    'This positive-only standalone descriptor is excluded from the default registry; ' +
    'archived negative suites remain historical and are not validated for this correction.',
  load: async () => {
    const valid = toRun(v.valid);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    const invalidInputs = (v.invalidInputs ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
