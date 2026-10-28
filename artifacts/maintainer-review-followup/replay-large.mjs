// Existing positive BLS-large replay only. No builders, invalid cases, or variant selection.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [repoArg, outputArg] = process.argv.slice(2);
assert(repoArg && outputArg && process.argv.length === 4,
  'usage: node replay-large.mjs benchmark-repo output.json');
const repo = resolve(repoArg);
const output = resolve(outputArg);
process.chdir(repo);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const importFromRepo = file => import(pathToFileURL(join(repo, file)).href);
const implementationModule = await importFromRepo('src/implementations/bch-groth16-bls12381-intratx-residue-large-corrected.ts');
const vmModule = await importFromRepo('src/harness/vm.ts');
const implementation = implementationModule.bchGroth16Bls12381IntratxResidueLargeCorrected;
const scenario = await implementation.load();
const runs = [
  {name: 'valid', steps: scenario.valid},
  ...(scenario.extraValidProofs ?? []).map((steps, index) => ({name: `extra-${index}`, steps})),
  ...(scenario.worstCaseProof ? [{name: 'worst-case', steps: scenario.worstCaseProof}] : []),
];
assert.equal(runs.length, 3);

const modes = [
  ['oracle', vmModule.createLoosenedVm],
  ['bch-spec-consensus', vmModule.createRealVmSpec],
  ['bch-spec-standard', vmModule.createStandardVmSpec],
];
const results = [];
for (const run of runs) {
  for (const [mode, makeVm] of modes) {
    const vm = makeVm();
    const outcomes = run.steps.map(step => vmModule.evaluatePair(
      vm, step.lockingBytecode, step.unlockingBytecode, undefined, step.intraTx, step.grouped));
    const failures = outcomes.map((outcome, index) => ({
      index, accepted: outcome.accepted, error: outcome.error ?? null,
      operationCost: outcome.operationCost,
    })).filter(outcome => !outcome.accepted);
    results.push({
      name: run.name, mode, inputs: outcomes.length,
      accepted: failures.length === 0, failures,
      operationCosts: outcomes.map(outcome => outcome.operationCost),
    });
  }
}

const vectorPath = join(repo, 'src/bch/groth16-bls12381-intratx-residue-large-checked-vectors.json');
const vectorSha256 = sha(readFileSync(vectorPath));
assert.equal(vectorSha256, '9b0ca5517eacf50d52a7991b90a89ded64e10c907fce9f2273c735a5a18af5d1',
  'unexpected checked BLS-large vector; use the pinned existing positive artifact');
const report = {
  schema: 'bls12381-residue-large-corrected-positive-replay/v1',
  status: results.every(result => result.accepted)
    ? 'PASS_EXISTING_POSITIVES_ORACLE_AND_BCH_SPEC'
    : 'RECORDED_EXISTING_POSITIVE_FAILURES',
  positiveOnly: true,
  implementation: implementation.id,
  vectorSha256,
  runs: results,
  fixtureRuns: results.length,
  evaluatedInputs: results.reduce((sum, result) => sum + result.inputs, 0),
  scope: 'Existing steps, extraValidProofs, and worstCaseProof only. No invalid fixtures, proof generation, builder, compiler variant, optimization, or cybersecurity execution.',
};
assert.equal(report.fixtureRuns, 9);
assert.equal(report.evaluatedInputs, 27);
assert.equal(report.status, 'PASS_EXISTING_POSITIVES_ORACLE_AND_BCH_SPEC');
assert(report.runs.every(result => result.accepted), 'all existing positive modes must accept');
writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, {flag: 'wx'});
console.log(JSON.stringify({status: report.status, fixtureRuns: report.fixtureRuns, evaluatedInputs: report.evaluatedInputs}));
