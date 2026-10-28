// Portable positive-only replay of the five archived BN254 slim graphs.
// This runner imports only the sealed benchmark descriptor and VM harness.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const [repoArg, outputArg] = process.argv.slice(2);
assert(repoArg && outputArg && process.argv.length === 4,
  'usage: node replay-slim.mjs benchmark-repo output.json');
const repo = resolve(repoArg);
const output = resolve(outputArg);
process.chdir(repo);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const importFromRepo = file => import(pathToFileURL(join(repo, file)).href);

const catalogPath = join(repo, 'src/bch/groth16-bn254-legacy-equation-checked-catalog.json');
const catalogBytes = readFileSync(catalogPath);
const catalogSha256 = sha(catalogBytes);
assert.equal(catalogSha256, '51ef1509eca342bc931b1f92ef57fc1af719948654399faeef5e4a9986d337c0');
const catalog = JSON.parse(catalogBytes.toString('utf8'));
const sourceOwner = catalog.ownerFiles.find(({file}) => file === 'repair.mjs');
assert.equal(sourceOwner?.sha256, 'cb676275cc4a8775151d9c4e12f9961f987c48afe5c633fa9a7faf6c567c9a77');

const implementationModule = await importFromRepo('src/implementations/bch-groth16-bn254-legacy-equation-checked.ts');
const vmModule = await importFromRepo('src/harness/vm.ts');
const targetId = 'bch-groth16-intratx-pairfold5-densless-msm-slim-equation-checked';
const implementation = implementationModule.bchGroth16Bn254LegacyEquationChecked.find(({id}) => id === targetId);
assert(implementation, `missing ${targetId}`);
const scenario = await implementation.load();
const runs = [
  {name: 'primary', steps: scenario.valid},
  ...(scenario.extraValidProofs ?? []).map((steps, index) => ({name: `extra-${index}`, steps})),
  {name: 'worst-case', steps: scenario.worstCaseProof},
];
assert.equal(runs.length, 5);

const modes = [
  ['oracle-loosened', vmModule.createLoosenedVm],
  ['consensus', vmModule.createRealVm],
];
const results = [];
for (const run of runs) {
  for (const [mode, makeVm] of modes) {
    const vm = makeVm();
    const outcomes = run.steps.map(step => vmModule.evaluatePair(
      vm, step.lockingBytecode, step.unlockingBytecode, undefined, step.intraTx, step.grouped));
    results.push({
      name: run.name,
      mode,
      inputs: outcomes.length,
      accepted: outcomes.every(({accepted}) => accepted),
      errors: outcomes.map(({error}) => error ?? null),
      operationCosts: outcomes.map(({operationCost}) => operationCost),
      lockingBytes: run.steps.map(({lockingBytecode}) => lockingBytecode.length),
      unlockingBytes: run.steps.map(({unlockingBytecode}) => unlockingBytecode.length),
    });
  }
}
const oracle = results.filter(({mode}) => mode === 'oracle-loosened');
const native = results.filter(({mode}) => mode === 'consensus');
assert.equal(oracle.length, 5);
assert(oracle.every(({accepted}) => accepted), 'oracle replay must accept all existing positives');
const nativeError = 'The provided locking bytecode exceeds the maximum bytecode length. Maximum bytecode length: 10000 bytes. Locking bytecode length: 10990 bytes.';
assert(native.every(({accepted, errors, lockingBytes}) => {
  return !accepted && lockingBytes[4] === 10990 && errors[4] === nativeError && errors.slice(0, 4).every(error => error === null);
}), 'native replay must record the terminal resource hold at input index 4');
const runnerSha256 = sha(readFileSync(new URL(import.meta.url)));
const report = {
  schema: 'bn254-legacy-slim-positive-replay/v2',
  status: 'PASS_EXISTING_SLIM_POSITIVES_ORACLE_NATIVE_HOLD',
  positiveOnly: true,
  targetId,
  catalogSha256,
  sourceRepairHelperSha256: sourceOwner.sha256,
  runs: results,
  fixtureRuns: results.length,
  evaluatedInputs: results.reduce((sum, result) => sum + result.inputs, 0),
  runnerSha256,
  scope: 'Existing primary, extraValidProofs, and worstCaseProof only. No invalid fixtures, builders, producers, compiler variants, optimization, or cybersecurity execution.',
};
writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, {flag: 'wx'});
console.log(JSON.stringify({status: report.status, fixtureRuns: report.fixtureRuns, evaluatedInputs: report.evaluatedInputs, runnerSha256}));
