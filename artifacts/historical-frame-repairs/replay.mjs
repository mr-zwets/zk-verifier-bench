// Replay only the saved historical positives. No compiler, builder, prover or mutation path.
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {
  ConsensusBch2025, createInstructionSetBch2026, createVirtualMachine, createVirtualMachineBch2026, createVirtualMachineBchSpec,
  decodeAuthenticationInstructions, encodeAuthenticationInstructions, encodeDataPush,
  encodeLockingBytecodeP2sh32, hash256, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const [source, output, smoke] = process.argv.slice(2);
assert(source && output && (process.argv.length === 4 || smoke === '--smoke' && process.argv.length === 5),
  'usage: node artifacts/historical-frame-repairs/replay.mjs source-checkout new-report.json [--smoke]');
const read = file => readFileSync(new URL(file, import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = bytes => Buffer.from(bytes).toString('hex');
const bytes = value => Buffer.from(value, 'hex');
const q = JSON.parse(read('./qualification.json'));
const originalBytes = read('./original-positives.json'), correctedBytes = read('./corrected-positives.json');
assert.equal(sha(originalBytes), '45cdf5dd47d7b07aea07a635eb606ebc58f1d301007bedac568d37e2bbd8e066');
assert.equal(sha(correctedBytes), 'f88d2274794b0e38c5254187c04d97033080b7fa84fafbccd982f99e5b4f19b1');
assert.equal(q.originalPositivePacketSha256, sha(originalBytes));
assert.equal(q.correctedPositivePacketSha256, sha(correctedBytes));
const manifestBytes = readFileSync(source + '/' + q.sourceManifest);
assert.equal(sha(manifestBytes), q.sourceManifestSha256);
assert.equal(sha(readFileSync(source + '/' + q.sourceHelper)), q.sourceHelperSha256);
const manifest = JSON.parse(manifestBytes), original = JSON.parse(originalBytes), corrected = JSON.parse(correctedBytes);
assert.equal(manifest.profiles.length, q.profiles);
assert.equal(original.profiles.length, q.profiles);
assert.equal(corrected.profiles.length, q.profiles);

function decode(step) {
  const script = bytes(step.unlocking), instructions = decodeAuthenticationInstructions(script);
  assert(instructions.every(i => !('error' in i) && (i.data !== undefined || i.opcode === 0 ||
    i.opcode === 0x4f || i.opcode >= 0x51 && i.opcode <= 0x60)));
  const code = Buffer.from(instructions.at(-1).data), push = Buffer.from(encodeDataPush(code));
  assert(script.subarray(-push.length).equals(push));
  assert.equal(hex(encodeLockingBytecodeP2sh32(hash256(code))), step.locking);
  return {code, prefix: script.subarray(0, -push.length), instructions};
}

// Check every byte and program identity before executing any script.
for (const profile of manifest.profiles) {
  const old = original.profiles.find(p => p.id === profile.id), selected = corrected.profiles.find(p => p.id === profile.id);
  assert(old && selected);
  assert.equal(old.layout, profile.layout);
  assert.equal(selected.layout, profile.layout);
  assert.equal(old.originalFixtureSha256, profile.originalFixture.sha256);
  assert.equal(selected.originalFixtureSha256, profile.originalFixture.sha256);
  assert.equal(old.cases.length, profile.caseCount);
  assert.equal(selected.cases.length, profile.caseCount);
  for (let c = 0; c < profile.caseCount; c++) {
    const before = old.cases[c], after = selected.cases[c];
    assert.equal(before.name, after.name);
    assert.equal(before.steps.length, profile.programCount);
    assert.equal(after.steps.length, profile.programCount);
    before.steps.forEach((step, index) => {
      const a = decode(step), b = decode(after.steps[index]), gate = profile.gates.find(g => g.input === index);
      assert(a.prefix.equals(b.prefix), 'original proof/public/state/table/padding instructions');
      assert.equal(sha(a.code), profile.originalProgramSha256[index]);
      assert.equal(sha(b.code), profile.repairedProgramSha256[index]);
      const expected = gate ? Buffer.concat([a.code.subarray(0, gate.offset), bytes(gate.hex), a.code.subarray(gate.offset)]) : a.code;
      assert(b.code.equals(expected), 'only the two exact predicates may change');
      if (gate) {
        if (gate.comparison === 'less-than') assert(a.instructions[0].data.length < gate.length);
        else assert.equal(a.instructions[0].data.length, gate.length);
        assert.equal(a.instructions.length - 1, gate.depth + 2);
        const decoded = decodeAuthenticationInstructions(a.code);
        let offset = 0;
        const boundaries = decoded.map(i => { assert(!('error' in i)); const n = offset; offset += encodeAuthenticationInstructions([i]).length; return n; });
        assert(boundaries.includes(gate.offset));
      }
    });
    if (profile.layout === 'grouped') {
      assert.equal(before.groups.length, 3);
      assert.equal(after.groups.length, 3);
      after.groups.forEach((group, i) => {
        assert.deepEqual(group.inToken, before.groups[i].inToken);
        assert.deepEqual(group.outToken, before.groups[i].outToken);
        assert.equal(group.lo, before.groups[i].lo);
        assert.equal(group.hi, before.groups[i].hi);
        if (i + 1 === after.groups.length) assert.equal(group.outLocking, before.groups[i].outLocking);
        if (i + 1 < after.groups.length) {
          assert.equal(group.outLocking, after.steps[after.groups[i + 1].lo].locking);
          assert.deepEqual(group.outToken, after.groups[i + 1].inToken);
        }
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
const proposedVms = {oracle: currentVms.oracle, consensus: createVirtualMachineBchSpec(false), standard: createVirtualMachineBchSpec(true)};
const token = (category, value) => ({amount: 0n, category: bytes(category),
  nft: {capability: value.capability, commitment: bytes(value.commitment)}});

function evaluate(vm, run, profile, index, mode) {
  const group = profile.layout === 'grouped' ? run.groups.find(g => index >= g.lo && index <= g.hi) : null;
  const lo = group ? group.lo : 0, hi = group ? group.hi : run.steps.length - 1;
  const steps = run.steps.slice(lo, hi + 1);
  const sourceOutputs = steps.map((s, i) => ({lockingBytecode: bytes(s.locking), valueSatoshis: 1000n,
    ...(i === 0 && group?.inToken ? {token: token(profile.tokenCategoryHex, group.inToken)} : {})}));
  const outLocking = group?.outLocking ? bytes(group.outLocking) : Uint8Array.of(0x6a);
  const state = vm.evaluate({inputIndex: index - lo, sourceOutputs,
    transaction: {version: 2, inputs: steps.map((s, i) => ({outpointTransactionHash: new Uint8Array(32),
      outpointIndex: i, sequenceNumber: 0, unlockingBytecode: bytes(s.unlocking)})),
      outputs: [{lockingBytecode: outLocking, valueSatoshis: 1000n,
        ...(group?.outToken ? {token: token(profile.tokenCategoryHex, group.outToken)} : {})}], locktime: 0}});
  const accepted = !state.error && state.stack.length === 1 && hex(state.stack[0]) === '01';
  const expectedDensityHold = profile.standardDensityHoldsMayOccur && mode === 'standard' &&
    state.error?.includes('operation cost density limit');
  assert(accepted || expectedDensityHold, profile.id + '/' + run.name + '/' + index + ': ' + (state.error ?? 'false/unclean result'));
  return {index, accepted, error: state.error ?? null, costKind: accepted ? 'completed' : 'halt', operationCost: state.metrics.operationCost,
    unlockingBytes: bytes(run.steps[index].unlocking).length};
}

const results = [];
for (const profile of manifest.profiles) {
  const packet = corrected.profiles.find(p => p.id === profile.id);
  assert(profile.declaredVm === 'bch-2026' || profile.declaredVm === 'bch-spec');
  const vms = profile.declaredVm === 'bch-spec' ? proposedVms : currentVms;
  const runs = [];
  for (const run of smoke ? packet.cases.slice(0, 1) : packet.cases) {
    const indices = smoke ? profile.gates.map(g => g.input) : run.steps.map((_, i) => i);
    for (const [mode, vm] of Object.entries(vms)) runs.push({case: run.name, mode,
      outcomes: indices.map(i => evaluate(vm, run, profile, i, mode))});
  }
  results.push({id: profile.id, layout: profile.layout, declaredVm: profile.declaredVm, runs});
}
const evaluations = results.flatMap(p => p.runs).flatMap(r => r.outcomes);
const expectedEvaluations = manifest.profiles.reduce((n, p) => n + (smoke ? p.gates.length : p.programCount * p.caseCount) * 3, 0);
assert.equal(evaluations.length, expectedEvaluations);
const accepted = evaluations.filter(r => r.accepted).length;
const report = {schema: 'historical-frame-positive-replay/v1', status: smoke ? 'PASS_EXISTING_GUARDED_INPUT_SMOKE' : accepted === evaluations.length ? 'PASS_ALL_EXISTING_POSITIVES_PER_INPUT' : 'PASS_MATHEMATICS_DECLARED_RESOURCE_HOLDS',
  node: process.version, positiveOnly: true, replayToolSha256: sha(read('./replay.mjs')), sourceManifestSha256: q.sourceManifestSha256,
  sourceHelperSha256: q.sourceHelperSha256, originalPacketSha256: sha(originalBytes), correctedPacketSha256: sha(correctedBytes),
  profiles: results, accepted, evaluations: evaluations.length,
  scope: 'Saved positive bytes only; exact proof/public/state/table/padding instruction preservation and exact selected program identities verified. Complete ordered graphs and grouped valid ancestry remain premises. No whole-transaction, relay, neutral-domain or mainnet conclusion.'};
writeFileSync(output, JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
console.log(JSON.stringify({status: report.status, profiles: results.length, accepted, evaluations: evaluations.length}));
