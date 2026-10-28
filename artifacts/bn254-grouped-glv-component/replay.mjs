// Replay saved aggregation components against the existing public inputs and VK.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { bn254 } from '@noble/curves/bn254.js';
import { decodeAuthenticationInstructions, vmNumberToBigInt, hexToBin, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026 } from '@bitauth/libauth';
const [output] = process.argv.slice(2);
assert(output && process.argv.length === 3, 'usage: node artifacts/bn254-grouped-glv-component/replay.mjs new-report.json');
const read = p => readFileSync(new URL(p, import.meta.url)), load = p => JSON.parse(read(p));
const sha = b => createHash('sha256').update(b).digest('hex'), hex = b => Buffer.from(b).toString('hex');
const q = load('./qualification.json'), d = load('./encoded-vectors.json');
assert.equal(q.artifactSha256, sha(read('./encoded-vectors.json')));
assert.equal(sha(read('./encoded-vectors.json')), 'e6c9b4b1168dbe8ed9a4bc723bb33ad7a0873b5ad5579f600232898613fcbdda');
const checkpointBytes = read('../../src/checkpoints/pairing-vectors.json'), fixtureBytes = read('../../src/bch/groth16-singleton-multiproof-vectors.json');
assert.equal(sha(checkpointBytes), q.checkpointSha256);
assert.equal(sha(fixtureBytes), q.existingProofFixtureSha256);
const checkpoint = JSON.parse(checkpointBytes), fixture = JSON.parse(fixtureBytes), original = [fixture.proofs[0], fixture.proofs[1], fixture.worstCaseProof];
const pushes = s => decodeAuthenticationInstructions(hexToBin(s)).map(i => { assert(!('error' in i)); if (i.data)
    return i.data; if (i.opcode === 0)
    return new Uint8Array(); if (i.opcode >= 0x51 && i.opcode <= 0x60)
    return Uint8Array.of(i.opcode - 0x50); if (i.opcode === 0x4f)
    return Uint8Array.of(0x81); throw Error('expected push-only unlocking'); });
const ints = ps => ps.map(p => { const v = vmNumberToBigInt(p, { requireMinimalEncoding: false }); assert.equal(typeof v, 'bigint'); return v; });
const le = n => { assert(n >= 0n && n < (1n << 256n)); return Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse(); };
const commit = state => hash256(Buffer.concat(state.map(s => le(BigInt(s)))));
const point = p => bn254.G1.Point.fromAffine({ x: BigInt(p.x), y: BigInt(p.y) }), ic = checkpoint.vk.ic.map(point);
const category = new Uint8Array(32).fill(0xcd), token = commitment => ({ amount: 0n, category, nft: { capability: 'mutable', commitment } });
const vms = { consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true) };
const run = (vm, locking, unlocking, inputCommit, outputCommit, outLocking) => { const s = vm.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: token(inputCommit) }], transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs: [{ lockingBytecode: outLocking, valueSatoshis: 1000n, token: token(outputCommit) }], locktime: 0 } }); assert(!s.error, s.error); assert.equal(s.stack.length, 1); assert.equal(hex(s.stack[0]), '01'); return { accepted: true, operationCost: s.metrics.operationCost }; };
const results = d.cases.map((c, index) => {
    const originalInputs = ints(pushes(original[index].unlocking)).slice(0, 2).reverse();
    assert.deepEqual(original[index].publicInputs, originalInputs.map(String));
    assert.deepEqual(c.publicInputs, originalInputs.map(String));
    assert.deepEqual(c.states.first.slice(0, 2), c.publicInputs);
    let expected = ic[0];
    originalInputs.forEach((n, i) => { if (n !== 0n)
        expected = expected.add(ic[i + 1].multiply(n)); });
    assert.deepEqual(c.states.final, [expected.toAffine().x.toString(), expected.toAffine().y.toString()]);
    const firstPush = pushes(c.raw.firstUnlocking), finalPush = pushes(c.raw.finalUnlocking);
    assert.deepEqual(ints(firstPush.slice(1, -1)).reverse().map(String), c.states.first);
    assert.deepEqual(ints(finalPush.slice(1, -1)).reverse().map(String), [...c.states.handoff, c.zInv]);
    const programFirst = firstPush.at(-1), programFinal = finalPush.at(-1);
    assert.equal(sha(programFirst), d.emitters.first.programSha256);
    assert.equal(sha(programFinal), d.emitters.final.programSha256);
    const firstLock = hexToBin(c.raw.firstLocking), finalLock = hexToBin(c.raw.finalLocking);
    assert.equal(hex(encodeLockingBytecodeP2sh32(hash256(programFirst))), c.raw.firstLocking);
    assert.equal(hex(encodeLockingBytecodeP2sh32(hash256(programFinal))), c.raw.finalLocking);
    if (index > 0) {
        assert.equal(c.raw.firstLocking, d.cases[0].raw.firstLocking);
        assert.equal(c.raw.finalLocking, d.cases[0].raw.finalLocking);
    }
    const modes = Object.fromEntries(Object.entries(vms).map(([name, vm]) => [name, [run(vm, firstLock, hexToBin(c.raw.firstUnlocking), commit(c.states.first), commit(c.states.handoff), finalLock), run(vm, finalLock, hexToBin(c.raw.finalUnlocking), commit(c.states.handoff), commit(c.states.final), finalLock)]]));
    return { name: c.name, publicInputs: c.publicInputs, expectedVkxIndependent: true, modes };
});
const result = { status: 'PASS_SIX_EXISTING_PUBLIC_INPUT_AGGREGATION_STAGES_PER_NATIVE_MODE', node: process.version, artifactSha256: q.artifactSha256, scope: q.scope, cases: results };
writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
console.log(result.status);
