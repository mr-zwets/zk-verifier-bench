// Saved existing positive proofs only; no compiler, producer, or negative suite.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {bls12_381 as curve} from '@noble/curves/bls12-381.js';
import {
  bigIntToVmNumber, encodeDataPush,
  ConsensusBch2025, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  createVirtualMachine, createVirtualMachineBch2026,
  ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const [source, output] = process.argv.slice(2);
assert(source && output && process.argv.length === 4,
  'usage: node artifacts/bls-singleton-full-proof-domain/replay.mjs source-checkout new-report.json');
const read = name => readFileSync(new URL(name, import.meta.url));
const sha = data => createHash('sha256').update(data).digest('hex');
const q = JSON.parse(read('./qualification.json'));
assert.equal(sha(readFileSync(source + '/' + q.sourceFile)), q.sourceSha256);
for (const [name, expected] of Object.entries(q.sourceImports)) {
  assert.equal(sha(readFileSync(source + '/' + name)), expected);
}
const originalBytes = read('../../' + q.originalMultiproofFile);
assert.equal(sha(originalBytes), q.originalMultiproofSha256);
const original = JSON.parse(originalBytes);
const packetBytes = read('./positive-cases.json');
assert.equal(sha(packetBytes), q.positivePacketSha256);
const packet = JSON.parse(packetBytes);
assert.equal(packet.cases.length, 4);
assert.equal(original.proofs.length, 4);
packet.cases.forEach((entry, index) => {
  assert.equal(entry.index, index);
  assert.equal(entry.unlocking, original.proofs[index].unlocking);
});
const lockingHex = read('./compiled-locking.hex').toString('utf8').trim();
assert(/^(?:[0-9a-f]{2})+$/.test(lockingHex));
const locking = Buffer.from(lockingHex, 'hex');
assert.equal(locking.length, q.lockingBytes);
assert.equal(sha(locking), q.lockingSha256);

// Decode the same archived mathematical proof through its published reversible
// coordinates; no scalar-generated proof point is used as a replay input.
const neutralBytes = read('./' + q.neutralCaseFile);
assert.equal(sha(neutralBytes), q.neutralCaseSha256);
const neutral = JSON.parse(neutralBytes);
const le = data => BigInt('0x' + Buffer.from(data).reverse().toString('hex'));
const p = curve.fields.Fp.ORDER, r = curve.fields.Fr.ORDER;
const mod = value => (value % p + p) % p;
function unitPoint(u, v) {
  assert(v !== 0n);
  return curve.G1.Point.fromAffine({x: mod(u * curve.fields.Fp.inv(v)),
    y: mod(-curve.fields.Fp.inv(mod(2n * v)))});
}
const stored = Object.fromEntries(Object.entries(neutral.sourcePushes)
  .map(([name, entry]) => [name, Buffer.from(entry.hex, 'hex')]));
assert.equal(stored.glvPublicInput.length, 96);
assert.equal(stored.millerGenesis.length, 14 * 48);
const inputs = [le(stored.glvPublicInput.subarray(0, 48)), le(stored.glvPublicInput.subarray(48))];
assert.deepEqual(inputs, [1n, r - 1n]);
const limbs = Array.from({length: 14}, (_, i) => le(stored.millerGenesis.subarray(i * 48, (i + 1) * 48)));
const A = unitPoint(limbs[10], limbs[11]).negate();
const B = curve.G2.Point.fromAffine({x: {c0: limbs[6], c1: limbs[7]}, y: {c0: limbs[8], c1: limbs[9]}});
const transformedC = curve.G1.Point.fromAffine({x: le(stored.transformedCx), y: le(stored.transformedCy)});
const C = transformedC.subtract(curve.G1.Point.BASE.multiply(29n)).multiply(curve.fields.Fr.inv(11n));
[A, B, C].forEach(point => { point.assertValidity(); assert(!point.is0()); });
assert(unitPoint(limbs[12], limbs[13]).equals(A), 'stored fixed-collapse D at neutral vk_x');
const vkx = curve.G1.Point.BASE.multiply(2n)
  .add(curve.G1.Point.BASE.multiply(4n).multiply(inputs[0]))
  .add(curve.G1.Point.BASE.multiply(6n).multiply(inputs[1]));
assert(vkx.is0());
const a = A.toAffine(), b = B.toAffine(), c = C.toAffine();
const args = [a.x, a.y, b.x.c0, b.x.c1, b.y.c0, b.y.c1, c.x, c.y, ...inputs];
assert.deepEqual(args.map(String), neutral.singletonArgs);
const neutralUnlocking = Buffer.concat(args.slice().reverse().map(value => encodeDataPush(bigIntToVmNumber(value))));
assert.equal(neutralUnlocking.toString('hex'), neutral.unlocking);
assert.equal(sha(neutralUnlocking), neutral.unlockingSha256);
const cases = [...packet.cases, {index: 'archived-neutral-vkx', unlocking: neutral.unlocking}];

const HUGE = Number.MAX_SAFE_INTEGER;
const vms = {
  oracle: createVirtualMachine(createInstructionSetBch2026(false, {consensus: {
    ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
    maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
    maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
    operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
    maximumVmNumberByteLength: HUGE, maximumBytecodeLength: HUGE,
    maximumOperationCount: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  }, ripemd160, secp256k1, sha1, sha256})),
  consensus: createVirtualMachineBch2026(false),
  standard: createVirtualMachineBch2026(true),
};

function evaluate(entry, mode, vm) {
  const program = createTestAuthenticationProgramBch({lockingBytecode: locking,
    unlockingBytecode: Buffer.from(entry.unlocking, 'hex'), valueSatoshis: 1000n});
  const state = vm.evaluate(program);
  const accepted = !state.error && state.stack.length === 1 &&
    Buffer.from(state.stack[0]).equals(Buffer.from([1]));
  if (mode === 'oracle') assert(accepted, state.error ?? 'false or unclean arithmetic result');
  else assert(!accepted && state.error ===
    `The provided locking bytecode exceeds the maximum bytecode length. Maximum bytecode length: 10000 bytes. Locking bytecode length: ${q.lockingBytes} bytes.`);
  return {mode, accepted, error: state.error ?? null,
    ...(mode === 'oracle' ? {} : {verifyResult: vm.verify(program)}),
    costKind: accepted ? 'completed' : 'admission-halt', operationCost: state.metrics.operationCost};
}

const results = cases.map(entry => ({index: entry.index,
  outcomes: Object.entries(vms).map(([mode, vm]) => evaluate(entry, mode, vm))}));
const report = {schema: 'bls-full-proof-domain-existing-positive-replay/v1',
  status: 'PASS_EXISTING_POSITIVES_ARITHMETIC_NATIVE_ADMISSION_HOLD', node: process.version,
  sourceSha256: q.sourceSha256, lockingSha256: q.lockingSha256,
  fixtureSha256: q.originalMultiproofSha256, positivePacketSha256: sha(packetBytes),
  neutralCaseSha256: sha(neutralBytes), neutralComputedVkx: true,
  replayToolSha256: sha(read('./replay.mjs')), results,
  scope: 'Four unchanged existing singleton positives and one reversibly reencoded archived positive with neutral computed vk_x. The unchanged positive payloads use finite external points; separate compiled symbolic certificates own infinity and strict-G1 coverage. No new proof, negative case, compiler, optimization, whole-transaction or mainnet conclusion.'};
writeFileSync(output, JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
console.log(JSON.stringify({status: report.status, existingProofs: results.length}));
