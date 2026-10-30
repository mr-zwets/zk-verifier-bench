#!/usr/bin/env node
// Mechanical public key/ABI anchor check.
// Usage: node check.mjs <pr11-benchmark-root> <auth42-benchmark-root>
// Reads only public JSON artifacts; it does not run a VM, producer, prover,
// compiler, negative fixture, or network operation.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const [pr11Root, auth42Root] = process.argv.slice(2);
if (!pr11Root || !auth42Root) {
  console.error('usage: node check.mjs <pr11-benchmark-root> <auth42-benchmark-root>');
  process.exit(2);
}

const EXPECTED = {
  pairing: 'e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e',
  intratx: '9ed76575922d82af5cb1cd39c78e06ef7840a3bd14359694c60d2c0d171357ab',
  grouped: 'b8aed2b6062ce3fa9b283764774467a8e475c61cc012e0ff7611e6fb3fbc93a5',
  originalAuth: '34bb01c525668364b30c04232a912af5485318c8cde8f3a9267b2705ead31074',
  checkedAuth: 'a33b25eb132d1222d6550b0bf94df08ec48760eb2f7d30bf6ff9b97bf361fcd3',
  proofBlob: 'e8d1b60dac29422889d9b41398fe8bff3b18f1872fd6c9da10b567f979cc1d1b',
  scalarBlob: 'ce02ce1a17239280c5210126efe441ac9d4ddd04c37bdb345cadc2054b23e3aa',
  stateBlob: '47425fd5490e20ce904b684503abb3ce9c1d879d98b8d9ad3992efb34dc8af45',
  millerBlob: 'ab13a947b1f093e942ffe7ebc402881d1c1b148c9bd8a38a5c013a478b893b27',
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const readBytes = (root, relative) => readFileSync(join(root, relative));
const readJson = (root, relative) => JSON.parse(readBytes(root, relative));
const fail = (message) => {
  throw new Error(message);
};
const check = (condition, message) => {
  if (!condition) fail(message);
};
const checkFile = (root, relative, expected) => {
  const bytes = readBytes(root, relative);
  check(sha256(bytes) === expected, `${relative}: SHA-256 mismatch`);
  return bytes;
};

const pairingBytes = checkFile(pr11Root, 'src/checkpoints/pairing-vectors.json', EXPECTED.pairing);
checkFile(pr11Root, 'src/bch/groth16-intratx-vectors.json', EXPECTED.intratx);
checkFile(pr11Root, 'src/bch/groth16-grouped-vectors.json', EXPECTED.grouped);
checkFile(pr11Root, 'src/bch/groth16-intratx-authenticated-p2s-vectors.json', EXPECTED.originalAuth);
const checkedBytes = checkFile(auth42Root, 'src/bch/groth16-intratx-authenticated-p2s-checked-vectors.json', EXPECTED.checkedAuth);

const pairing = JSON.parse(pairingBytes.toString('utf8'));
const checked = JSON.parse(checkedBytes.toString('utf8'));
const originalPackets = [
  ['native42', readJson(pr11Root, 'src/bch/groth16-intratx-vectors.json').steps],
  ['grouped42', readJson(pr11Root, 'src/bch/groth16-grouped-vectors.json').valid.steps],
  ['authenticated42', readJson(pr11Root, 'src/bch/groth16-intratx-authenticated-p2s-vectors.json').steps],
];
check(String(pairing.curve).toLowerCase().startsWith('bn254'), 'pairing vector is not BN254');
check(pairing.vk?.ic?.length === 3, 'pairing vector does not have IC0/IC1/IC2');
check(checked.numInputs === 42 && checked.steps?.length === 42, 'checked authenticated packet is not the 42-input packet');
check(checked.repair?.originalFixtureSha256 === EXPECTED.originalAuth, 'checked packet original fixture anchor mismatch');
check(checked.repair?.statement === 'Every accepting complete selected42-program graph satisfies e(-A,B)*e(alpha,beta)*e(IC0+u0*IC1+u1*IC2,gamma)*e(C,delta)=1.', 'checked packet statement mismatch');
check(Array.isArray(checked.repair?.selectedProgramSha256) && checked.repair.selectedProgramSha256.length === 42, 'selected program catalog is not 42 rows');

// Minimal push decoder for the first data item of the public unlocking scripts.
const firstPush = (hex) => {
  const bytes = Buffer.from(hex, 'hex');
  const op = bytes[0];
  let offset = 1;
  let length;
  if (op <= 0x4b) length = op;
  else if (op === 0x4c) { length = bytes[offset]; offset += 1; }
  else if (op === 0x4d) { length = bytes[offset] + (bytes[offset + 1] << 8); offset += 2; }
  else if (op === 0x4e) { length = bytes.readUInt32LE(offset); offset += 4; }
  else fail(`unlocking begins with non-push opcode ${op}`);
  check(offset + length <= bytes.length, 'first push exceeds unlocking length');
  return bytes.subarray(offset, offset + length);
};
const le = (value) => {
  let n = BigInt(value);
  const out = Buffer.alloc(32);
  for (let i = 0; i < out.length; i += 1) { out[i] = Number(n & 255n); n >>= 8n; }
  check(n === 0n, 'value does not fit in 32 bytes');
  return out;
};
const leInt = (bytes) => {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) n = (n << 8n) + BigInt(bytes[i]);
  return n;
};
const blob = (index) => firstPush(checked.steps[index].unlocking);
for (const [name, steps] of originalPackets) {
  check(steps.length === 42, `${name}: expected 42 existing inputs`);
  for (const index of [0, 3, 8, 9]) {
    check(firstPush(steps[index].unlocking).equals(blob(index)), `${name} step ${index}: statement anchor differs`);
  }
}
const assertBlobHash = (index, expected, label) => {
  const bytes = blob(index);
  check(sha256(bytes) === expected, `${label}: anchor blob hash mismatch`);
  return bytes;
};

const p = BigInt(pairing.p);
const r = BigInt(pairing.r);
const mod = (value) => ((value % p) + p) % p;
const inverse = (value) => {
  let base = mod(value), exponent = p - 2n, result = 1n;
  while (exponent > 0n) {
    if (exponent & 1n) result = result * base % p;
    base = base * base % p;
    exponent >>= 1n;
  }
  return result;
};
const add = (left, right) => {
  if (left === null) return right;
  if (right === null) return left;
  if (left.x === right.x && mod(left.y + right.y) === 0n) return null;
  const slope = left.x === right.x
    ? mod(3n * left.x * left.x) * inverse(2n * left.y) % p
    : mod(right.y - left.y) * inverse(right.x - left.x) % p;
  const x = mod(slope * slope - left.x - right.x);
  return { x, y: mod(slope * (left.x - x) - left.y) };
};
const multiply = (point, scalar) => {
  let result = null;
  let base = point;
  let n = scalar;
  while (n > 0n) {
    if (n & 1n) result = add(result, base);
    base = add(base, base);
    n >>= 1n;
  }
  return result;
};
const g1 = (point) => ({ x: BigInt(point.x), y: BigInt(point.y) });
const ic = pairing.vk.ic.map(g1);
const u0 = BigInt(pairing.publicInputs[0]);
const u1 = BigInt(pairing.publicInputs[1]);
check(u0 >= 0n && u0 < r && u1 >= 0n && u1 < r, 'public scalar outside Fr');
const vkx = add(add(ic[0], multiply(ic[1], u0)), multiply(ic[2], u1));
check(String(vkx.x) === pairing.golden.vkXAffine.x && String(vkx.y) === pairing.golden.vkXAffine.y, 'independent VKx does not match golden vector');

const proof = [
  BigInt(pairing.proof.a.x),
  mod(-BigInt(pairing.proof.a.y)),
  BigInt(pairing.proof.b.x.c0),
  BigInt(pairing.proof.b.x.c1),
  BigInt(pairing.proof.b.y.c0),
  BigInt(pairing.proof.b.y.c1),
  BigInt(pairing.proof.c.x),
  BigInt(pairing.proof.c.y),
];
const proofBytes = Buffer.concat(proof.map(le));
check(sha256(proofBytes) === EXPECTED.proofBlob, 'independent proof ABI blob mismatch');
const proofBlob = assertBlobHash(0, EXPECTED.proofBlob, 'proof');
check(proofBlob.equals(proofBytes), 'checked proof blob does not equal vector proof limbs');

const scalarBlob = assertBlobHash(3, EXPECTED.scalarBlob, 'scalar');
check(scalarBlob.length === 64 && leInt(scalarBlob.subarray(0, 32)) === u0 && leInt(scalarBlob.subarray(32, 64)) === u1, 'checked scalar genesis order/value mismatch');
const stateBlob = assertBlobHash(8, EXPECTED.stateBlob, 'state');
const state = Array.from({ length: 5 }, (_, i) => leInt(stateBlob.subarray(i * 32, (i + 1) * 32)));
check(JSON.stringify(state.map(String)) === JSON.stringify(['0', '1', '0', String(u0), String(u1)]), 'checked VKx state order/value mismatch');
const millerBlob = assertBlobHash(9, EXPECTED.millerBlob, 'Miller');
check(millerBlob.length === 320 && millerBlob.subarray(0, 256).equals(proofBytes), 'Miller proof prefix mismatch');
check(leInt(millerBlob.subarray(256, 288)) === vkx.x && leInt(millerBlob.subarray(288, 320)) === vkx.y, 'Miller VKx suffix mismatch');
check(checked.steps[0].locking.startsWith('76aa20') && checked.steps[0].locking.length === 88, 'checked packet is not the authenticated P2S dispatcher');

console.log(JSON.stringify({
  status: 'PASS_PUBLIC_KEY_ABI_ANCHOR',
  inputs: { originalPublicBenchmark: 'PR11', checkedPacket: 'src/bch/groth16-intratx-authenticated-p2s-checked-vectors.json' },
  publicHashes: EXPECTED,
  checkedInputs: 42,
  vkx: { x: vkx.x.toString(), y: vkx.y.toString() },
  anchors: { proofBytes: proofBytes.length, scalarBytes: scalarBlob.length, stateBytes: stateBlob.length, millerBytes: millerBlob.length },
  vmExecutions: 0,
  newFixtures: 0,
}, null, 2));
