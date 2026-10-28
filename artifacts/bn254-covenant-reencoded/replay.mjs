// Replay the fixed saved graph against existing proof/public inputs; no producers or compilers.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { decodeAuthenticationInstructions, vmNumberToBigInt, hexToBin, hash256, encodeLockingBytecodeP2sh32, ConsensusBch2025, createInstructionSetBch2026, createVirtualMachine, createVirtualMachineBch2026 } from '@bitauth/libauth';
const [source, output] = process.argv.slice(2);
assert(source && output && process.argv.length === 4, 'usage: node artifacts/bn254-covenant-reencoded/replay.mjs source-checkout new-report.json');
const read = p => readFileSync(new URL(p, import.meta.url)), load = p => JSON.parse(read(p)), sha = b => createHash('sha256').update(b).digest('hex'), hex = b => Buffer.from(b).toString('hex');
const q = load('./qualification.json'), d = load('./encoded-vectors.json');
assert.equal(q.artifactSha256, sha(read('./encoded-vectors.json')));
assert.equal(sha(read('./encoded-vectors.json')), '49f80dfd42790caf26ff56020b0bcd5ec916f9801d972475f147571863c51ed2');
for (const [file, hash] of Object.entries(q.sourcePins))
    assert.equal(sha(readFileSync(source + '/' + file)), hash);
const checkpointBytes = read('../../src/checkpoints/pairing-vectors.json'), fixtureBytes = read('../../src/bch/groth16-singleton-multiproof-vectors.json');
assert.equal(sha(checkpointBytes), q.checkpointSha256);
assert.equal(sha(fixtureBytes), q.multiproofSha256);
const checkpoint = JSON.parse(checkpointBytes), fixture = JSON.parse(fixtureBytes), original = [fixture.proofs[0], fixture.proofs[1], fixture.worstCaseProof], P = BigInt(checkpoint.p);
const pushes = s => decodeAuthenticationInstructions(hexToBin(s)).map(i => { assert(!('error' in i)); if (i.data)
    return i.data; if (i.opcode === 0)
    return new Uint8Array(); if (i.opcode >= 0x51 && i.opcode <= 0x60)
    return Uint8Array.of(i.opcode - 0x50); if (i.opcode === 0x4f)
    return Uint8Array.of(0x81); throw Error('expected push-only unlocking'); });
const ints = ps => ps.map(p => { const v = vmNumberToBigInt(p, { requireMinimalEncoding: false }); assert.equal(typeof v, 'bigint'); return v; });
const args = s => ints(pushes(s).slice(1, -1)).reverse();
const category = new Uint8Array(32).fill(0xcd), token = (capability, commitment) => ({ amount: 0n, category, nft: { capability, commitment } });
const vms = { oracle: createVirtualMachine(createInstructionSetBch2026(false, { consensus: { ...ConsensusBch2025, maximumBytecodeLength: 1000000, maximumStandardLockingBytecodeLength: 1000000, maximumStandardUnlockingBytecodeLength: 1000000 } })), consensus: createVirtualMachineBch2026(false), standard: createVirtualMachineBch2026(true) };
function evaluate(step, vm) { const locking = hexToBin(step.locking), outLocking = hexToBin(step.outLocking), output = () => ({ lockingBytecode: outLocking, valueSatoshis: 1000n, token: token(step.kind === 'terminal' ? 'none' : 'mutable', hexToBin(step.outCommit)) }); const outputs = step.kind === 'genesis' ? [output(), { lockingBytecode: locking, valueSatoshis: 1000n, token: token('minting', new Uint8Array()) }] : [output()]; const s = vm.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: step.kind === 'genesis' ? 3000n : 1000n, token: token(step.kind === 'genesis' ? 'minting' : 'mutable', hexToBin(step.commit)) }], transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: hexToBin(step.unlocking) }], outputs, locktime: 0 } }); return { accepted: !s.error && s.stack.length === 1 && hex(s.stack[0]) === '01', error: s.error ?? null, operationCost: s.metrics.operationCost, costKind: s.error ? 'halt' : 'completed' }; }
const results = d.runs.map((run, index) => {
    const steps = run.result.steps;
    assert.equal(steps.length, 27);
    const orig = ints(pushes(original[index].unlocking)).reverse();
    assert.equal(orig.length, 10);
    assert.deepEqual(orig.slice(8).map(String), original[index].publicInputs);
    assert.deepEqual(original[index].publicInputs, q.logicalPublicInputs[index]);
    const tuple = orig.slice(0, 8);
    tuple[1] = (P - tuple[1]) % P;
    assert.deepEqual(args(steps[0].unlocking), tuple);
    assert.deepEqual(args(steps[3].unlocking).slice(8, 10), orig.slice(8));
    if (index === 0) {
        const p = checkpoint.proof, flat = [p.a.x, p.a.y, p.b.x.c0, p.b.x.c1, p.b.y.c0, p.b.y.c1, p.c.x, p.c.y];
        assert.deepEqual(orig.slice(0, 8).map(String), flat);
        assert.deepEqual(original[0].publicInputs, checkpoint.publicInputs);
    }
    steps.forEach((s, i) => { assert.equal(hex(encodeLockingBytecodeP2sh32(hash256(pushes(s.unlocking).at(-1)))), s.locking); assert.equal(s.locking, d.runs[0].result.steps[i].locking); if (i + 1 < steps.length) {
        assert.equal(s.outLocking, steps[i + 1].locking);
        assert.equal(s.outCommit, steps[i + 1].commit);
    }
    else {
        assert.equal(s.outLocking, s.locking);
        assert.equal(s.outCommit, '');
    } });
    const modes = Object.fromEntries(Object.entries(vms).map(([name, vm]) => { const r = steps.map(s => evaluate(s, vm)), failed = r.flatMap((v, i) => v.accepted ? [] : [{ index: i, ...v }]); if (name === 'oracle')
        assert.equal(failed.length, 0);
    else {
        assert.equal(failed.length, 2);
        assert(failed.every(x => steps[x.index].unlocking.length / 2 > 10000));
    } return [name, { accepted: r.filter(x => x.accepted).length, total: r.length, failures: failed }]; }));
    return { tag: run.tag, publicInputs: original[index].publicInputs, proofPointsCompared: true, lockingAndCommitmentSeams: 26, modes };
});
const result = { status: 'PASS_ARITHMETIC_81_OF_81_NATIVE_HOLD_75_OF_81', node: process.version, artifactSha256: q.artifactSha256, scope: q.scope, commitmentScope: q.commitmentScope, cases: results };
writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
console.log(result.status);
