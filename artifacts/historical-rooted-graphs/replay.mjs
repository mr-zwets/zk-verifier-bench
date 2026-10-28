// Positive-only replay for the rooted historical graph packet.
// Static checks independently verify prefix/code/P2SH identities before the
// saved existing positive cases are evaluated by the BCH VM.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {
  ConsensusBch2025, createInstructionSetBch2026, createVirtualMachine,
  createVirtualMachineBch2026, createVirtualMachineBchSpec,
  decodeAuthenticationInstructions,
  encodeDataPush, encodeLockingBytecodeP2sh32, hash256, ripemd160, secp256k1,
  sha1, sha256,
} from '@bitauth/libauth';

const [source, output, smoke] = process.argv.slice(2);
assert(source && output && (smoke === undefined || smoke === '--smoke'),
  'usage: node replay.mjs source-checkout result.json [--smoke]');

const here = file => new URL(file, import.meta.url);
const read = file => readFileSync(here(file));
const readPath = file => readFileSync(file);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = bytes => Buffer.from(bytes).toString('hex');
const bytes = value => Buffer.from(value, 'hex');
const locking = code => Buffer.from(encodeLockingBytecodeP2sh32(hash256(code)));

const rootedBytes = read('./rooted-positives.json');
const manifestBytes = read('./historical-rooted-graphs.json');
const rooted = JSON.parse(rootedBytes), manifest = JSON.parse(manifestBytes);
const originalCorrectedBytes = read('../historical-frame-repairs/corrected-positives.json');
const originalCorrected = JSON.parse(originalCorrectedBytes);
assert.equal(rooted.schema, 'historical-rooted-positive-set/v1');
assert.equal(manifest.schema, 'historical-rooted-graph-manifest/v1');
assert.equal(digest(originalCorrectedBytes), manifest.correctedPositivePacketSha256);
const sourceHelperBytes = readPath(source + '/' + manifest.sourceHelper);
const sourceFrameManifestBytes = readPath(source + '/' + manifest.sourceFrameManifest);
const sourceRootedManifestBytes = readPath(source + '/chunked/intratx/historical-rooted-graphs.json');
assert.equal(digest(sourceHelperBytes), manifest.sourceHelperSha256);
assert.equal(digest(sourceFrameManifestBytes), manifest.sourceFrameManifestSha256);
assert(sourceRootedManifestBytes.equals(manifestBytes), 'source rooted manifest must match artifact manifest');
assert.equal(rooted.profiles.length, manifest.profiles.length);

function decode(step) {
  const script = bytes(step.unlocking), instructions = decodeAuthenticationInstructions(script);
  assert(instructions.every(i => !('error' in i) &&
    (i.data !== undefined || i.opcode === 0 || i.opcode === 0x4f ||
      i.opcode >= 0x51 && i.opcode <= 0x60)), 'push-only unlocking');
  const code = Buffer.from(instructions.at(-1)?.data ?? []);
  const push = Buffer.from(encodeDataPush(code));
  assert(code.length > 0 && script.subarray(-push.length).equals(push));
  assert.equal(hex(locking(code)), step.locking);
  return {code, prefix: script.subarray(0, -push.length)};
}

function countGuard(count) {
  assert(Number.isInteger(count) && count > 0 && count < 256);
  const encoded = Buffer.from(encodeDataPush(Buffer.from([count])));
  return Buffer.concat([Buffer.from([0xc3]), encoded, Buffer.from([0x9d])]);
}

function rootGuard(count) { return Buffer.concat([Buffer.from([0xc0, 0x00, 0x9d]), countGuard(count)]); }
function successorGuard(owner) {
  assert.equal(owner.length, 35);
  return Buffer.concat([Buffer.from([0xc0, 0x8b, 0xc7, 0x23]), owner, Buffer.from([0x88])]);
}
function absolutePin(index, owner) {
  assert(index > 0 && index < 17);
  return Buffer.concat([Buffer.from(encodeDataPush(Buffer.from([index]))), Buffer.from([0xc7, 0x23]), owner, Buffer.from([0x88])]);
}

function staticCheck() {
  for (const profile of manifest.profiles) {
    const rootedProfile = rooted.profiles.find(candidate => candidate.id === profile.id);
    const sourceProfile = originalCorrected.profiles.find(candidate => candidate.id === profile.sourceProfileId);
    assert(rootedProfile && sourceProfile);
    assert.equal(rootedProfile.programCount, profile.programCount);
    assert.equal(rootedProfile.cases.length, profile.caseCount);
    assert.equal(rootedProfile.standardDensityHoldsMayOccur, profile.standardDensityHoldsMayOccur);
    const oldFirst = sourceProfile.cases[0].steps.map(decode);
    const newFirst = rootedProfile.cases[0].steps.map(decode);
    assert.equal(oldFirst.length, profile.programCount);
    assert.equal(newFirst.length, profile.programCount);
    for (let i = 0; i < profile.programCount; i++) {
      assert.equal(digest(oldFirst[i].code), profile.sourceCorrectedProgramSha256[i]);
      assert.equal(digest(newFirst[i].code), profile.rootedProgramSha256[i]);
      assert.equal(rootedProfile.cases[0].steps[i].locking, profile.rootedLockingHex[i]);
      assert(oldFirst[i].prefix.equals(newFirst[i].prefix), `payload prefix ${profile.id}/${i}`);
      const expected = profile.graphBinding.mode === 'root-absolute-pins'
        ? i === 0
          ? Buffer.concat([rootGuard(profile.programCount), ...oldFirst.slice(1).map((step, offset) => absolutePin(offset + 1, locking(step.code))), oldFirst[0].code])
          : oldFirst[i].code
        : Buffer.concat([
          i === 0 ? rootGuard(profile.programCount) : Buffer.alloc(0),
          i + 1 < profile.programCount ? successorGuard(locking(newFirst[i + 1].code)) : Buffer.alloc(0),
          oldFirst[i].code,
        ]);
      assert(newFirst[i].code.equals(expected), `rooted code composition ${profile.id}/${i}`);
    }
    for (let c = 0; c < profile.caseCount; c++) {
      const oldRun = sourceProfile.cases[c], newRun = rootedProfile.cases[c];
      assert.equal(oldRun.name, newRun.name);
      oldRun.steps.forEach((step, i) => {
        const oldStep = decode(step), newStep = decode(newRun.steps[i]);
        assert(oldStep.prefix.equals(newStep.prefix));
        assert(newStep.code.equals(newFirst[i].code));
        assert.equal(newRun.steps[i].locking, profile.rootedLockingHex[i]);
      });
    }
  }
}

const HUGE = Number.MAX_SAFE_INTEGER;
const currentVms = {
  oracle: createVirtualMachine(createInstructionSetBch2026(false, {consensus: {
    ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
    maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
    maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
    operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
    maximumBytecodeLength: HUGE, maximumOperationCount: HUGE, maximumStackDepth: HUGE,
    maximumControlStackDepth: HUGE,
  }, ripemd160, secp256k1, sha1, sha256})),
  consensus: createVirtualMachineBch2026(false),
  standard: createVirtualMachineBch2026(true),
};
const proposedVms = {
  oracle: currentVms.oracle,
  consensus: createVirtualMachineBchSpec(false),
  standard: createVirtualMachineBchSpec(true),
};

function expectedResourceHold(run, index, profile, mode, error) {
  if (mode === 'oracle') return false;
  if (profile.sourceProfileId === 'bch-groth16-historical-bn27-intratx-frame-corrected' &&
      (mode === 'consensus' || mode === 'standard') && [0, 1, 8, 9].includes(index)) {
    const expectedMessage = index === 0 || index === 8
      ? 'maximum stack item length' : 'maximum bytecode length';
    return error?.includes(expectedMessage) === true;
  }
  if (profile.sourceProfileId === 'bch-groth16-historical-bn13-frame-corrected' &&
      mode === 'standard' && index === 1 && (run.name === 'extra-0' || run.name === 'worst-case')) {
    return error?.includes('operation cost density limit') === true;
  }
  return false;
}

function evaluate(vm, run, index, profile, mode) {
  const steps = run.steps;
  const sourceOutputs = steps.map(step => ({lockingBytecode: bytes(step.locking), valueSatoshis: 1000n}));
  const state = vm.evaluate({inputIndex: index, sourceOutputs,
    transaction: {version: 2, inputs: steps.map(step => ({outpointTransactionHash: new Uint8Array(32),
      outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: bytes(step.unlocking)})),
      outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}], locktime: 0}});
  const accepted = !state.error && state.stack.length === 1 && hex(state.stack[0]) === '01';
  const resourceHold = expectedResourceHold(run, index, profile, mode, state.error);
  assert(accepted || resourceHold,
    `${profile.id}/${run.name}/${index}/${mode}: ${state.error ?? 'false or unclean result'}`);
  return {index, accepted, error: state.error ?? null,
    resourceHold, costKind: accepted ? 'completed' : 'halt', operationCost: state.metrics.operationCost};
}

staticCheck();
const results = [];
for (const profile of manifest.profiles) {
  const rootedProfile = rooted.profiles.find(candidate => candidate.id === profile.id);
  const vms = profile.declaredVm === 'bch-spec' ? proposedVms : currentVms;
  const runs = [];
  const selectedCases = smoke ? rootedProfile.cases.slice(0, 1) : rootedProfile.cases;
  for (const run of selectedCases) {
    const indices = smoke ? [0, rootedProfile.programCount - 1] : run.steps.map((_, index) => index);
    for (const [mode, vm] of Object.entries(vms)) {
      runs.push({case: run.name, mode, outcomes: indices.map(index => evaluate(vm, run, index, profile, mode))});
    }
  }
  results.push({id: profile.id, declaredVm: profile.declaredVm, runs});
}
const evaluations = results.flatMap(profile => profile.runs).flatMap(run => run.outcomes);
const accepted = evaluations.filter(result => result.accepted).length;
const resourceHolds = evaluations.filter(result => result.resourceHold).length;
const holds = evaluations.length - accepted;
const report = {
  schema: 'historical-rooted-graph-positive-replay/v1',
  status: holds === 0 ? (smoke ? 'PASS_ROOTED_SMOKE' : 'PASS_ALL_EXISTING_ROOTED_POSITIVES') : 'PASS_WITH_DECLARED_RESOURCE_HOLDS',
  positiveOnly: true, smoke: Boolean(smoke), node: process.version,
  replayToolSha256: digest(read('./replay.mjs')),
  rootedPacketSha256: digest(rootedBytes), manifestSha256: digest(manifestBytes),
  correctedPacketSha256: digest(originalCorrectedBytes), staticChecks: 'PASS',
  sourceHelperSha256: digest(sourceHelperBytes), sourceFrameManifestSha256: digest(sourceFrameManifestBytes),
  profiles: results, accepted, holds, resourceHolds,
  holdDetails: evaluations.filter(result => !result.accepted), evaluations: evaluations.length,
  scope: 'Existing corrected positive cases only. Proof/public/state/table/padding prefixes are byte-identical. No proof generation, negative cases, compiler/producer/planner invocation, grouped graph, whole-transaction, relay, neutral-domain, or mainnet conclusion.',
};
writeFileSync(output, JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
console.log(JSON.stringify({status: report.status, profiles: results.length, accepted, holds, evaluations: evaluations.length}));
