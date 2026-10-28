// Positive-only validation of the standalone frozen corrected descriptors.
// It intentionally loads no invalid or mutation scenarios.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bchBnExactFrameCorrected} from '../implementations/bch-bn-exact-frame-corrected.ts';
import {evaluatePair, createRealVm, createStandardVm} from '../harness/vm.ts';

const output = process.argv[2];
assert(output, 'usage: validate-bn-exact-frame-corrected.mjs <result.json>');
const runnerBytes = readFileSync(new URL(import.meta.url));
const runnerSha256 = createHash('sha256').update(runnerBytes).digest('hex');
const result = {schema: 'bn254-exact-frame-correction-validation/v1', runnerSha256, positiveOnly: true, profiles: [], fixtureRuns: 0, evaluatedInputs: 0};

for (const implementation of bchBnExactFrameCorrected) {
  const scenario = await implementation.load();
  const runs = [{name: 'valid', steps: scenario.valid},
    ...(scenario.extraValidProofs ?? []).map((steps, index) => ({name: `extra-${index}`, steps})),
    ...(scenario.worstCaseProof ? [{name: 'worst-case', steps: scenario.worstCaseProof}] : [])];
  const profile = {id: implementation.id, runs: []};
  for (const run of runs) {
    for (const [mode, makeVm] of [['consensus', createRealVm], ['standard', createStandardVm]]) {
      const vm = makeVm();
      const outcomes = run.steps.map((step) => evaluatePair(vm, step.lockingBytecode, step.unlockingBytecode,
        undefined, step.intraTx, step.grouped));
      const failures = outcomes.map((outcome, index) => ({index, error: outcome.error ?? null, accepted: outcome.accepted}))
        .filter((outcome) => !outcome.accepted);
      profile.runs.push({name: run.name, mode, inputs: outcomes.length, accepted: failures.length === 0, failures});
      result.fixtureRuns += 1;
      result.evaluatedInputs += outcomes.length;
    }
  }
  result.profiles.push(profile);
}
result.status = result.profiles.every((profile) => profile.runs.every((run) => run.accepted))
  ? 'PASS_CORRECTED_BN_DESCRIPTOR_POSITIVES'
  : 'RECORDED_CORRECTED_BN_DESCRIPTOR_FAILURES';
writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`, {flag: 'wx'});
console.log(JSON.stringify({status: result.status, profiles: result.profiles.length, fixtureRuns: result.fixtureRuns, evaluatedInputs: result.evaluatedInputs, runnerSha256}));
