// Replay saved fixed-policy covenant bytes, preserving all archived proof/public-input objects.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { decodeAuthenticationInstructions, vmNumberToBigInt, hexToBin, hash256, encodeLockingBytecodeP2sh32, ConsensusBch2025, createInstructionSetBch2026, createVirtualMachine, createVirtualMachineBch2026, ripemd160, secp256k1, sha1, sha256 } from '@bitauth/libauth';
const [source, output] = process.argv.slice(2);
assert(source && output && process.argv.length === 4, 'usage: node artifacts/bls-covenant-reencoded/replay.mjs source-checkout new-report.json');
const read = p => readFileSync(new URL(p, import.meta.url)), load = p => JSON.parse(read(p)), sha = b => createHash('sha256').update(b).digest('hex'), hex = b => Buffer.from(b).toString('hex');
const q = load('./qualification.json'), d = load('./encoded-vectors.json');
assert.equal(q.artifactSha256, sha(read('./encoded-vectors.json')));
assert.equal(sha(read('./encoded-vectors.json')), '2773a19aec6b8cee7f2d2349e7173dc8d575f96d72221731ba8611a3a1aa6871');
for (const [file, hash] of Object.entries(q.sourcePins))
    assert.equal(sha(readFileSync(source + '/' + file)), hash);
const fixtureBytes = read('../../src/bch/groth16-bls12381-intratx-residue-vectors.json');
assert.equal(sha(fixtureBytes), q.fixtureSha256);
const fixture = JSON.parse(fixtureBytes), original = [fixture.steps, fixture.extraValidProofs[0], fixture.worstCaseProof];
const pushes = s => decodeAuthenticationInstructions(hexToBin(s)).map(i => { assert(!('error' in i)); if (i.data)
    return i.data; if (i.opcode === 0)
    return new Uint8Array(); if (i.opcode >= 0x51 && i.opcode <= 0x60)
    return Uint8Array.of(i.opcode - 0x50); if (i.opcode === 0x4f)
    return Uint8Array.of(0x81); throw Error('expected push-only unlocking'); });
const ints = ps => ps.map(p => { const v = vmNumberToBigInt(p, { requireMinimalEncoding: false }); assert.equal(typeof v, 'bigint'); return v; });
const args = s => ints(pushes(s).slice(1, -1)).reverse();
const le = n => { assert(n >= 0n && n < (1n << 384n)); return Buffer.from(n.toString(16).padStart(96, '0'), 'hex').reverse(); };
const HUGE = Number.MAX_SAFE_INTEGER;
const vms = { oracle: createVirtualMachine(createInstructionSetBch2026(false, { consensus: { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE }, ripemd160, secp256k1, sha1, sha256 })), consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true) };
const token = (category, capability, commitment) => ({ amount: 0n, category, nft: { capability, commitment } });
function evaluate(step, vm) { const c = step.covenant, category = hexToBin(c.category), locking = hexToBin(step.lockingHex), outLocking = hexToBin(c.outLockingHex); const out = () => ({ lockingBytecode: outLocking, valueSatoshis: 1000n, token: token(category, c.outputCapability, hexToBin(c.outCommitment)) }); const outputs = step.kind === 'genesis' ? [out(), { lockingBytecode: locking, valueSatoshis: 1000n, token: token(category, 'minting', new Uint8Array()) }] : [out()]; const s = vm.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: step.kind === 'genesis' ? 3000n : 1000n, token: token(category, c.inputCapability, hexToBin(c.inCommitment)) }], transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: hexToBin(step.unlockingHex) }], outputs, locktime: 0 } }); return { accepted: !s.error && s.stack.length === 1 && hex(s.stack[0]) === '01', error: s.error ?? null, operationCost: s.metrics.operationCost, costKind: s.error ? 'halt' : 'completed' }; }
const results = d.cases.map((run, index) => {
    const steps = run.steps;
    assert.equal(steps.length, 35);
    const oldPublic = pushes(original[index][0].unlocking)[0], oldMiller = pushes(original[index][5].unlocking)[0];
    assert.equal(oldPublic.length, 6 * 48);
    assert.equal(oldMiller.length, 16 * 48);
    const initial = args(steps[0].unlockingHex), final = args(steps[4].unlockingHex);
    assert.equal(initial.length, 6);
    assert.equal(final.length, 18);
    assert.deepEqual(final.slice(3, 5), initial.slice(0, 2));
    assert.equal(hex(Buffer.concat(initial.slice(0, 2).map(le))), hex(oldPublic.subarray(0, 96)));
    const p = Array.from({ length: 10 }, (_, i) => oldMiller.subarray((6 + i) * 48, (7 + i) * 48));
    const expected = [...p.slice(4, 6), ...p.slice(0, 4), ...p.slice(8, 10)];
    assert.deepEqual(final.slice(10, 18).map(n => hex(le(n))), expected.map(hex));
    steps.forEach((s, i) => { const c = s.covenant, redeem = pushes(s.unlockingHex).at(-1); assert.equal(hex(redeem), s.redeemHex); assert.equal(hex(encodeLockingBytecodeP2sh32(hash256(redeem))), s.lockingHex); assert.equal(s.lockingHex, d.cases[0].steps[i].lockingHex); assert.equal(c.category, 'be'.repeat(32)); assert.equal(c.inputCapability, i === 0 ? 'minting' : 'mutable'); assert.equal(c.outputCapability, i === 34 ? 'none' : 'mutable'); if (i + 1 < steps.length) {
        assert.equal(c.outLockingHex, steps[i + 1].lockingHex);
        assert.equal(c.outCommitment, steps[i + 1].covenant.inCommitment);
    }
    else {
        assert.equal(c.outLockingHex, s.lockingHex);
        assert.equal(c.outCommitment, '');
    } });
    const modes = Object.fromEntries(Object.entries(vms).map(([name, vm]) => { const r = steps.map(s => evaluate(s, vm)), failed = r.flatMap((v, i) => v.accepted ? [] : [{ index: i, ...v }]), expectedFailures = name === 'oracle' || index !== 2 ? [] : [1, 2, 3, 4]; assert.deepEqual(failed.map(x => x.index), expectedFailures); assert(failed.every(x => x.error.includes('operation cost density limit'))); return [name, { accepted: r.filter(x => x.accepted).length, total: r.length, failures: failed, completedOperationCosts: r.map(x => x.accepted ? x.operationCost : null) }]; }));
    return { caseIndex: index, proofPointsCompared: true, publicScalarsCompared: true, lockingAndCommitmentSeams: 34, modes };
});
const result = { status: 'PASS_ARITHMETIC_105_OF_105_NATIVE_HOLD_101_OF_105', node: process.version, artifactSha256: q.artifactSha256, scope: q.scope, cases: results };
writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
console.log(result.status);
