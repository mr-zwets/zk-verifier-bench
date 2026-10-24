// Frozen authenticated42 correction: sixteen typed exact state-length predicates.
// Original positive proof/public/state/table/padding bytes are retained verbatim;
// only the selected stage-body pushes and matching 44-byte dispatcher digests change.
// The complete ordered 42-program graph and public statement remain external premises.
//
// Current original-positive observations: arithmetic oracle 126/126; declared BCH2026
// consensus 126/126; declared standard 42/126 (84 operation-cost-density rejections).
// These are per-input interpreter results, not whole-transaction/network admission.
// Native and standard admission HOLD: this standalone descriptor is excluded from REGISTRY.
// Archived negative suites are historical only and are not included or validated here.
//
// Reproduce the positive-only artifact with the public source tool:
// node groth16_cashscript/chunked/intratx/repair_authenticated42.mjs \
//   src/bch/groth16-intratx-authenticated-p2s-vectors.json \
//   src/bch/groth16-intratx-authenticated-p2s-checked-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-intratx-authenticated-p2s-checked-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array,
// so each step is evaluated against the same multi-input transaction (and its
// tx.inputs[idx±1] introspection resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({
    label: s.label,
    lockingBytecode: inputs[i]!.lockingBytecode,
    unlockingBytecode: inputs[i]!.unlockingBytecode,
    checkpoint: s.checkpoint,
    intraTx: { index: i, inputs },
  }));
};

export const bchGroth16IntratxAuthenticatedP2s: Implementation = {
  id: 'bch-groth16-intratx-authenticated-p2s',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 3, push: 0, offset: 0, encoding: 'le32', name: 'n0' },
    { input: 3, push: 0, offset: 32, encoding: 'le32', name: 'n1' },
    { input: 4, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 4, push: 0, offset: 128, encoding: 'le32', name: 'n1' },
    { input: 5, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 5, push: 0, offset: 128, encoding: 'le32', name: 'n1' },
    { input: 6, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 6, push: 0, offset: 128, encoding: 'le32', name: 'n1' },
    { input: 7, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 7, push: 0, offset: 128, encoding: 'le32', name: 'n1' },
    { input: 8, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 8, push: 0, offset: 128, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH Groth16 authenticated42 exact-frame correction (standalone; admission HOLD)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Frozen 42-program BN254 verifier with sixteen typed exact state-length predicates ' +
    'and authenticated DEFINE 999 / INVOKE dispatchers. The fixed original program set ' +
    'and guard manifest own this artifact; the newer 31-input producer is unchanged. ' +
    'Conditional finite accepted-equation soundness assumes the complete ordered graph, ' +
    'public statement, finite point domain and standard pairing/hash premises. ' +
    'All original positive argument and padding bytes are preserved. The three original ' +
    'graphs pass 126/126 arithmetic-oracle and 126/126 declared-consensus input evaluations; ' +
    'declared-standard acceptance is 42/126, with 84 cost-density rejections. These are ' +
    'per-input observations. Whole-transaction and network admission remain HOLD. ' +
    'This positive-only standalone descriptor is excluded from the default registry; ' +
    'the archived negative suite is historical and has not been validated for this correction.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
