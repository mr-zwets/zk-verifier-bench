import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
// Replay only the saved positive bytes; do not import a proof producer or compiler.
const [source, output] = process.argv.slice(2);
assert(source && output && process.argv.length === 4, 'usage: node artifacts/bls-default-fp6-reencoded-v2/replay.mjs source-checkout new-report.json');
const artifact = new URL('./encoded-vectors-v1.json', import.meta.url), original = new URL('../../src/bch/groth16-bls12381-intratx-residue-vectors.json', import.meta.url), assessment = new URL('./qualification.json', import.meta.url);
const load = p => JSON.parse(readFileSync(p));
const d = load(artifact), o = load(original), a = load(assessment);
const sha = b => createHash('sha256').update(b).digest('hex');
const hex = b => Buffer.from(b).toString('hex');
assert.equal(sha(readFileSync(artifact)), '672f206dac00d9626275b17dc63eaf75df252c37b9ec6978558a98ec1c277e17');
assert.equal(sha(readFileSync(original)), d.fixtureSha256);
for (const key of ['sourceHead', 'sourceVkSha256', 'fixtureSha256'])
    assert.equal(a[key], d[key]);
const binding = load(new URL('./fixture-binding.json', import.meta.url));
assert.equal(binding.fixtureSha256, d.fixtureSha256);
assert.equal(binding.sourceVkFileSha256, d.sourceVkSha256);
for (const [file, hash] of Object.entries(a.sourcePins))
    assert.equal(sha(readFileSync(source + '/' + file)), hash);
assert.equal(sha(readFileSync(source + '/singleton/bls12-381/bls_instance.mjs')), d.sourceVkSha256);
assert.equal(sha(readFileSync(source + '/chunked/bls12-381/gen_finalexp_residue.mjs')), a.sourceTailEmitterSha256);
const { decodeAuthenticationInstructions, encodeLockingBytecodeP2sh32, encodeTransactionBch, hash256, createVirtualMachineBch2026, createVirtualMachine, createInstructionSetBch2026, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256 } = await import('@bitauth/libauth');
const pushes = s => decodeAuthenticationInstructions(Buffer.from(s, 'hex')).map(i => { assert(!('error' in i)); return i.data; });
const old = [o.steps, o.extraValidProofs[0], o.worstCaseProof];
const HUGE = Number.MAX_SAFE_INTEGER;
const vms = { oracle: createVirtualMachine(createInstructionSetBch2026(false, { consensus: { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE }, ripemd160, secp256k1, sha1, sha256 })), consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true) };
const rows = [];
for (const c of d.cases) {
    const initial = pushes(c.steps[0].unlocking)[0], originalInitial = pushes(old[c.caseIndex][0].unlocking)[0];
    assert.equal(hex(initial.subarray(0, 96)), hex(originalInitial.subarray(0, 96)));
    const inputBytes = [hex(initial.subarray(0, 48)), hex(initial.subarray(48, 96))];
    assert.deepEqual(c.proofPublicIdentity.inputBytes, inputBytes);
    assert.deepEqual(c.proofPublicIdentity.inputs, inputBytes.map(x => BigInt('0x' + Buffer.from(x, 'hex').reverse().toString('hex')).toString()));
    assert.deepEqual(binding.cases[c.caseIndex].inputBytes, inputBytes);
    assert.deepEqual(binding.cases[c.caseIndex].inputs, c.proofPublicIdentity.inputs);
    assert.equal(c.sourceFixtureSha256, d.fixtureSha256);
    const genesis = pushes(c.steps[5].unlocking)[0], orig = pushes(old[c.caseIndex][5].unlocking)[0];
    assert.equal(genesis.length, 34 * 48);
    assert.equal(orig.length, 16 * 48);
    assert.equal(hex(genesis.subarray(24 * 48)), hex(orig.subarray(6 * 48)));
    assert.deepEqual(c.proofPublicIdentity.originalRuntimePointBytes, Array.from({ length: 10 }, (_, i) => hex(orig.subarray((6 + i) * 48, (7 + i) * 48))));
    assert.deepEqual(binding.cases[c.caseIndex].proofCoordinateBytes, c.proofPublicIdentity.originalRuntimePointBytes);
    const inputs = c.steps.map((s, i) => { const code = pushes(s.unlocking).at(-1); assert.equal(sha(code), d.sharedProgramSha256[i]); assert.equal(sha(Buffer.from(s.locking, 'hex')), d.sharedLockingSha256[i]); assert.equal(hex(encodeLockingBytecodeP2sh32(hash256(code))), s.locking); return { locking: Buffer.from(s.locking, 'hex'), unlocking: Buffer.from(s.unlocking, 'hex') }; });
    const transaction = { version: 2, inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlocking })), outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n }], locktime: 0 };
    const total = 1000n + BigInt(encodeTransactionBch(transaction).length), each = total / BigInt(inputs.length), rem = total % BigInt(inputs.length);
    const sourceOutputs = inputs.map((i, n) => ({ lockingBytecode: i.locking, valueSatoshis: each + (BigInt(n) < rem ? 1n : 0n) }));
    const result = { caseIndex: c.caseIndex, identity: 'PASS_ARCHIVED_PROOF_POINTS_AND_PUBLIC_INPUT_BYTES', modes: {} };
    for (const [name, vm] of Object.entries(vms)) {
        const results = inputs.map((_, inputIndex) => { const state = vm.evaluate({ transaction, sourceOutputs, inputIndex }); return { inputIndex, accepted: !state.error && state.stack.length === 1 && hex(state.stack[0]) === '01', error: state.error ?? null, operationCost: state.metrics?.operationCost ?? null }; });
        result.modes[name] = { accepted: results.filter(x => x.accepted).length, total: results.length, failures: results.filter(x => !x.accepted) };
    }
    for (const [name, mode] of Object.entries(result.modes)) {
        const expected = name === 'oracle' || c.caseIndex !== 2 ? [] : [1, 2, 3, 4];
        assert.deepEqual(mode.failures.map(x => x.inputIndex), expected);
        assert(mode.failures.every(x => x.error.includes('operation cost density limit')));
    }
    rows.push(result);
}
writeFileSync(output, JSON.stringify({ schema: 'saved-positive-artifact-replay/v1', node: process.version, artifactSha256: sha(readFileSync(artifact)), sourceSnapshotPinsChecked: Object.keys(a.sourcePins).length, sourceTailEmitterSha256: sha(readFileSync(source + '/chunked/bls12-381/gen_finalexp_residue.mjs')), cases: rows, scope: 'Saved bytes only; original proof/public bytes and shared programs verified. No compiler, producer, new proof, new input, or negative execution. Ordered graph remains an external deployment premise; resource-relaxed oracle passes are mathematical evidence only.' }, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify(rows));
