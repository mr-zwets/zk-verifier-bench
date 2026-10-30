import assert from 'node:assert/strict';
import { test } from 'node:test';

import { bchGroth16Singleton } from '../implementations/bch-groth16-singleton.js';
import { bchCell, correctnessOf, entryOf } from './entry.js';
import type { BenchmarkResult } from './types.js';

// Reporting inputs only: no VM execution or new proof/witness bytes. These counters
// describe the archived singleton run set; tests vary only reported outcomes.
const scenario = await bchGroth16Singleton.load();
const runs = 1 + (scenario.extraValidProofs?.length ?? 0);
const result: BenchmarkResult = {
  impl: bchGroth16Singleton,
  profileOnly: false, checked: true, validPassed: true,
  invalidRejected: 1, invalidTotal: 1, pass: true,
  proofBinding: 'runtime', proofsTested: runs, proofsPassed: runs,
  runtimeGeneral: true, proofIdentity: { declared: true, distinct: true },
  tokenThreaded: false, tokenSafetyEnforced: null,
  inputValidation: {
    tested: 0, rejected: 0, enforced: false, evidence: 'run-rejection-only',
    reason: 'domain enforcement requires independent review',
  },
  crossStageBinding: { applicable: false, seamsTested: 0, unboundSeams: 0 },
  redTeam: { present: false, stale: false, tested: 0, accepted: 0, kinds: [] },
  publicInputs: { declared: true, tested: 0, accepted: 0 },
  layout: { applicable: false, padsTested: 0, malleable: 0, dependencies: [] },
  bsvOpReturn: false, steps: [], checkpointStats: [], stepCount: scenario.valid.length,
  totalBytes: 0, totalPadBytes: 0, totalTxOverheadBytes: 0, txCount: 1,
  totalOperationCost: 0, maxStepOperationCost: 0,
  fitsStandardBudget: false, inputsForHeaviestStep: 0,
  bchCompatible: false, fitsBchStandardness: false,
  securePackaging: true, packagingType: 'p2s',
};

test('reports rejected extra honest runs as completeness failures', () => {
  const row = correctnessOf({ ...result, pass: false, runtimeGeneral: false, proofsPassed: runs - 1 });
  assert.equal(row.verdict, 'fail');
  assert.ok(row.failures.includes(`1/${runs} honest run(s) rejected (completeness)`));
});

test('does not promote an untested applicable seam check to a passing verdict', () => {
  const reason = 'no accepted, qualified distinct extra proof';
  const row = correctnessOf({
    ...result, pass: false,
    crossStageBinding: { applicable: true, seamsTested: 0, unboundSeams: 0, reason },
  });
  assert.equal(row.verdict, 'valid-only');
  assert.equal(row.crossStageBinding.bound, null);
  assert.equal(row.crossStageBinding.reason, reason);
});

test('keeps rejection counts separate from input-domain enforcement claims', () => {
  const row = entryOf({
    ...result,
    inputValidation: { ...result.inputValidation, tested: 1, rejected: 1 },
  });
  assert.equal(row.inputValidation.enforced, false);
  assert.equal(row.inputValidation.evidence, 'run-rejection-only');
  assert.match(row.inputValidation.detail, /NOT DEMONSTRATED/);
});

test('does not describe undeclared proof identity as runtime-general by construction', () => {
  const row = entryOf({
    ...result, runtimeGeneral: false,
    proofIdentity: { declared: false, distinct: false, reason: 'proof identity not declared' },
  });
  assert.equal(row.generality.runtimeGeneral, false);
  assert.match(row.generality.detail, /NOT DEMONSTRATED/);
});

test('names the real-VM failure when no size/op-cost blocker applies', () => {
  const detail = "step 1/1 (single) rejected: Program attempted an operation that would exceed the operation cost density limit.";
  const cell = bchCell({
    ...result,
    impl: { ...bchGroth16Singleton, vm: 'bch-spec' },
    steps: [{ label: 'single', lockingBytes: 35, unlockingBytes: 16_473, padBytes: 0, txOverheadBytes: 0, operationCost: 33_000_000, instructionCount: 0, accepted: true, error: undefined }],
    stepCount: 1, inputsForHeaviestStep: 1,
    bchCompatible: false, bchIncompatibleReason: 'op-cost', bchIncompatibleDetail: detail,
  });
  assert.deepEqual(cell.blockers, ['op-cost']);
  assert.equal(cell.detail, `real bch-spec VM: ${detail}`);
});

test('never leaves an incompatible row without a detail', () => {
  const cell = bchCell({ ...result, bchCompatible: false });
  assert.notEqual(cell.detail, '');
});
