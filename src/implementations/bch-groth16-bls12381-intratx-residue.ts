// Frozen BLS12-381 quotient24 correction: exact 432-byte GLV table carrier at
// input 4 and exact 1632-byte terminal root owner at input 23. All original positive
// proof/public/state/auxiliary/table/padding bytes remain unchanged.
// The conditional full equation is joined to the actual current arithmetic, helper
// namespaces, physical stack counts, push/header semantics and both typed predicates.
// The complete ordered 24-program graph and ordinary curve/pairing/hash premises remain.
//
// All three original graphs pass 72/72 input evaluations in each of the current
// repository arithmetic oracle, declared BCH2026 consensus and standard modes.
// These are per-input observations. The selected unlocking scripts alone occupy
// 191432, 192522 and 228434 bytes, exceeding the pinned 100000-byte standard tx cap.
// Whole-transaction/ledger/network admission remains HOLD; excluded from REGISTRY.
// Archived negative suites are historical and are not included or validated here.
// This frozen artifact is quotient mode; default Fp6 source has separate qualification.
//
// Reproduce the positive-only artifact with the public source tool:
// node groth16_cashscript/chunked/intratx/repair_registered_bls24.mjs \
//   src/bch/groth16-bls12381-intratx-residue-vectors.json \
//   src/bch/groth16-bls12381-intratx-residue-checked-vectors.json
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-intratx-residue-checked-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array, so each
// step is evaluated against the same multi-input transaction (its tx.inputs[idx±1] introspection
// resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({ label: s.label, lockingBytecode: inputs[i]!.lockingBytecode, unlockingBytecode: inputs[i]!.unlockingBytecode, checkpoint: s.checkpoint, intraTx: { index: i, inputs } }));
};

export const bchGroth16Bls12381IntratxResidue: Implementation = {
  id: 'bch-groth16-bls12381-intratx-residue-corrected',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 0, offset: 0, encoding: 'le32', name: 'n0' },
    { input: 0, push: 0, offset: 48, encoding: 'le32', name: 'n1' },
    { input: 0, push: 0, offset: 96, encoding: 'le32', name: 'n0' },
    { input: 0, push: 0, offset: 192, encoding: 'le32', name: 'n1' },
    { input: 1, push: 0, offset: 144, encoding: 'le32', name: 'n0' },
    { input: 1, push: 0, offset: 192, encoding: 'le32', name: 'n1' },
    { input: 1, push: 0, offset: 240, encoding: 'le32', name: 'n0' },
    { input: 1, push: 0, offset: 336, encoding: 'le32', name: 'n1' },
    { input: 2, push: 0, offset: 144, encoding: 'le32', name: 'n0' },
    { input: 2, push: 0, offset: 192, encoding: 'le32', name: 'n1' },
    { input: 2, push: 0, offset: 240, encoding: 'le32', name: 'n0' },
    { input: 2, push: 0, offset: 336, encoding: 'le32', name: 'n1' },
    { input: 3, push: 0, offset: 144, encoding: 'le32', name: 'n0' },
    { input: 3, push: 0, offset: 192, encoding: 'le32', name: 'n1' },
    { input: 3, push: 0, offset: 240, encoding: 'le32', name: 'n0' },
    { input: 3, push: 0, offset: 336, encoding: 'le32', name: 'n1' },
    { input: 4, push: 0, offset: 144, encoding: 'le32', name: 'n0' },
    { input: 4, push: 0, offset: 192, encoding: 'le32', name: 'n1' },
    { input: 4, push: 0, offset: 240, encoding: 'le32', name: 'n0' },
    { input: 4, push: 0, offset: 336, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 frozen quotient24 frame correction (standalone; admission HOLD)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Frozen 24-program quotient-torus BLS12-381 verifier with typed exact 432-byte ' +
    'table-carrier and 1632-byte terminal-root predicates. Current arithmetic and raw ' +
    'caller correspondence, actual P2SH/clean-stack argument ownership and both frame ' +
    'predicates establish the conditional finite full pairing equation. The complete ' +
    'ordered program graph and ordinary curve, pairing and hash premises remain explicit. ' +
    'All original positive proof/state/table/padding arguments are preserved. Three original ' +
    'graphs pass 72/72 input evaluations in each arithmetic-oracle, declared-consensus and ' +
    'declared-standard mode. These observations do not establish whole-transaction admission. ' +
    'Their unlocking-byte totals alone exceed the pinned 100000-byte standard transaction ' +
    'limit. This qualified positive-only descriptor is excluded from the default registry; ' +
    'native/network admission remains HOLD and archived negative suites are historical.',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
    invalidInputs: (v.invalidInputs ?? []).map(toRun),
  }),
};
