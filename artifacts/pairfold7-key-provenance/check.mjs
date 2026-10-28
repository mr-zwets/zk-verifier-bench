#!/usr/bin/env node
// Read-only PairFold-7 packet checker.
// It binds the packet VK directly to the pinned source declaration, recomputes
// the raw BN254 alpha/beta Miller factor from those coordinates, and extracts
// the twelve terminal PUSH32 limbs from the pinned original vector. It never
// imports builders/provers/planners and never executes a VM case.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const args = Object.fromEntries(process.argv.slice(2).reduce((a, value, i, all) => {
  if (!value.startsWith('--')) return a;
  a.push([value.slice(2), all[i + 1] ?? '']);
  return a;
}, []));

const required = ['source', 'benchmark', 'packet', 'factor-cert'];
for (const name of required) {
  if (!args[name]) throw new Error(`missing --${name}`);
}

const packetPath = resolve(args.packet);
const packetDocument = JSON.parse(readFileSync(packetPath, 'utf8'));
let packet = packetDocument;
if (packetDocument.basePacketPath) {
  const basePacketBytes = readFileSync(resolve(packetPath, '..', packetDocument.basePacketPath));
  expect(sha256(basePacketBytes) === packetDocument.basePacketSha256, 'base packet SHA-256 mismatch');
  packet = JSON.parse(basePacketBytes);
}
const source = packet.keyDeclaration;
const benchmark = packet.benchmark;
const factorExpected = packet.factorCertificate;

function git(root, command, ...values) {
  return execFileSync('git', ['-C', root, command, ...values], {
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
  });
}

function gitBlob(root, revision, path) {
  return git(root, 'rev-parse', `${revision}:${path}`).toString('utf8').trim();
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha1(bytes) {
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

function literal(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function roleCall(text, name, values) {
  const pattern = `${literal(name)}\\s*\\(\\s*${values.map(literal).join('\\s*,\\s*')}\\s*\\)`;
  return new RegExp(pattern, 'm').test(text);
}

function reverseBytes(hex) {
  return (hex.match(/../g) ?? []).reverse().join('');
}

function checkGitBlob(root, revision, path, expectedSha1, expectedBytes, label) {
  const bytes = git(root, 'show', `${revision}:${path}`);
  expect(gitBlob(root, revision, path) === expectedSha1, `${label}: Git blob SHA-1 mismatch`);
  expect(bytes.length === expectedBytes, `${label}: byte length mismatch`);
  expect(sha1(bytes) === expectedSha1, `${label}: independently recomputed blob SHA-1 mismatch`);
  return bytes;
}

// Parse only pushdata in the transaction unlocking script. Non-push opcodes
// are skipped; the final push is the terminal redeem program in the pinned
// positive vector. No script execution is performed.
function pushInstructions(bytes) {
  const rows = [];
  let offset = 0;
  while (offset < bytes.length) {
    const opcodeOffset = offset;
    const opcode = bytes[offset++];
    let length;
    if (opcode <= 75) length = opcode;
    else if (opcode === 76) length = bytes[offset++];
    else if (opcode === 77) {
      length = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2;
    } else if (opcode === 78) {
      length = bytes[offset] | (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
      offset += 4;
    } else {
      continue;
    }
    expect(offset + length <= bytes.length, 'pushdata exceeds unlocking length');
    rows.push({ opcodeOffset, opcode, length, dataOffset: offset, data: bytes.subarray(offset, offset + length) });
    offset += length;
  }
  expect(offset === bytes.length, 'unlocking parser did not consume all bytes');
  return rows;
}

function littleEndian(value) {
  return Buffer.from(value.toString(16).padStart(64, '0'), 'hex').reverse();
}

const sourceBytes = checkGitBlob(
  args.source,
  source.revision,
  source.path,
  source.blobSha1,
  source.bytes,
  'VK declaration',
);
const sourceText = sourceBytes.toString('utf8');
const vectorBytes = checkGitBlob(
  args.benchmark,
  benchmark.revision,
  benchmark.vectorPath,
  benchmark.vectorBlobSha1,
  benchmark.vectorBytes,
  'PairFold vector',
);
expect(sha256(vectorBytes) === benchmark.vectorSha256, 'PairFold vector SHA-256 mismatch');
const implementationBytes = git(args.benchmark, 'show', `${benchmark.revision}:${benchmark.implementationPath}`);
expect(gitBlob(args.benchmark, benchmark.revision, benchmark.implementationPath) === benchmark.implementationBlobSha1, 'implementation Git blob SHA-1 mismatch');
expect(sha1(implementationBytes) === benchmark.implementationBlobSha1, 'implementation blob SHA-1 recomputation mismatch');

const vk = source.vk;
const alphaBeta = [vk.beta.x.c0, vk.beta.x.c1, vk.beta.y.c0, vk.beta.y.c1, vk.alpha.x, vk.alpha.y];
const gamma = [vk.gamma.x.c0, vk.gamma.x.c1, vk.gamma.y.c0, vk.gamma.y.c1, 'vkxX', 'vkxY'];
const delta = [vk.delta.x.c0, vk.delta.x.c1, vk.delta.y.c0, vk.delta.y.c1, 'Cx', 'Cy'];
expect(roleCall(sourceText, 'millerSingle', alphaBeta), 'alpha/beta are not bound to fixed millerSingle role');
expect(roleCall(sourceText, 'millerSingle', gamma), 'gamma is not bound to millerSingle(vkxX,vkxY)');
expect(roleCall(sourceText, 'millerSingle', delta), 'delta is not bound to millerSingle(Cx,Cy)');
expect(roleCall(sourceText, 'g1ScalarMul', ['in0', vk.ic[1].x, vk.ic[1].y]), 'IC1 is not bound to in0 scalar multiplication');
expect(roleCall(sourceText, 'g1ScalarMul', ['in1', vk.ic[2].x, vk.ic[2].y]), 'IC2 is not bound to in1 scalar multiplication');
expect(roleCall(sourceText, 'jacAddG1', [vk.ic[0].x, vk.ic[0].y, '1', 'r1x', 'r1y', 'r1z']), 'IC0 is not bound as affine first MSM point');

// Resolve the pinned benchmark checkout's dependency without relying on the
// evidence directory's own module ancestry.
const benchmarkRequire = createRequire(resolve(args.benchmark, 'package.json'));
const noblePath = benchmarkRequire.resolve('@noble/curves/bn254.js');
const { bn254 } = await import(pathToFileURL(noblePath).href);
const g1 = (point) => bn254.G1.Point.fromAffine({ x: BigInt(point.x), y: BigInt(point.y) });
const g2 = (point) => bn254.G2.Point.fromAffine({
  x: { c0: BigInt(point.x.c0), c1: BigInt(point.x.c1) },
  y: { c0: BigInt(point.y.c0), c1: BigInt(point.y.c1) },
});
const alpha = g1(vk.alpha);
const beta = g2(vk.beta);
alpha.assertValidity();
beta.assertValidity();
[vk.gamma, vk.delta].forEach(point => g2(point).assertValidity());
vk.ic.forEach(point => g1(point).assertValidity());
const rawFactor = bn254.pairing(alpha, beta, false);
const flattened = [
  rawFactor.c0.c0.c0,
  rawFactor.c0.c0.c1,
  rawFactor.c0.c1.c0,
  rawFactor.c0.c1.c1,
  rawFactor.c0.c2.c0,
  rawFactor.c0.c2.c1,
  rawFactor.c1.c0.c0,
  rawFactor.c1.c0.c1,
  rawFactor.c1.c1.c0,
  rawFactor.c1.c1.c1,
  rawFactor.c1.c2.c0,
  rawFactor.c1.c2.c1,
];
const expectedLittleEndian = flattened.map(littleEndian);

const vectors = JSON.parse(vectorBytes);
const terminalStep = vectors.steps?.at(-1);
expect(terminalStep?.label === 'terminal', 'pinned vector last step is not terminal');
const unlocking = Buffer.from(terminalStep.unlocking, 'hex');
const pushes = pushInstructions(unlocking);
const terminalPush = pushes.at(-1);
expect(terminalPush?.opcode === 77, 'terminal redeem program is not the final PUSHDATA2 push');
expect(terminalPush.length === 5809, 'terminal redeem program length mismatch');
const terminal = terminalPush.data;
expect(sha256(terminal) === '6bd2a76ca98ba62c6bbd368bbccf4be86ca80a18ca9415c6db62a9edc56faf9b', 'terminal redeem SHA-256 mismatch');
const terminalOffsets = [2206, 2239, 2276, 2313, 2350, 2387, 2424, 2461, 2498, 2535, 2572, 2609];
const terminalLimbs = terminalOffsets.map((opcodeOffset, index) => {
  expect(terminal[opcodeOffset] === 0x20, `terminal limb ${index} is not PUSH32`);
  const dataOffset = opcodeOffset + 1;
  const data = terminal.subarray(dataOffset, dataOffset + 32);
  expect(data.length === 32, `terminal limb ${index} is truncated`);
  expect(data.equals(expectedLittleEndian[index]), `terminal limb ${index} differs from direct alpha/beta pairing`);
  return { index, opcodeOffset, dataOffset, littleEndian: data.toString('hex') };
});
const terminalConcat = Buffer.concat(terminalLimbs.map((limb) => Buffer.from(limb.littleEndian, 'hex')));

// The old factor certificate is corroborating historical evidence only. The
// direct packet-coordinate/vector comparison above is the binding check.
const factorBytes = readFileSync(resolve(args['factor-cert']));
const factor = JSON.parse(factorBytes);
expect(sha256(factorBytes) === factorExpected.sha256, 'factor-equality certificate SHA-256 mismatch');
expect(factor.schema === 'pairfold7-fixed-alpha-beta-factor-equality/v1', 'unexpected factor certificate schema');
const factorMatchesDirect = factor.computedBigEndian.every((value, index) =>
  value === reverseBytes(terminalLimbs[index].littleEndian));

console.log(JSON.stringify({
  status: 'PASS_DIRECT_PACKET_KEY_TERMINAL_FACTOR_BINDING',
  packetSchema: packetDocument.schema,
  sourceRevision: source.revision,
  sourceBlobSha1: source.blobSha1,
  benchmarkRevision: benchmark.revision,
  vectorSha256: benchmark.vectorSha256,
  implementationBlobSha1: benchmark.implementationBlobSha1,
  roleBindings: ['alpha/beta', 'gamma', 'delta', 'IC0', 'IC1', 'IC2'],
  roleCoordinateCount: 20,
  directPairing: {
    library: '@noble/curves/bn254.js',
    moduleResolution: 'benchmark checkout dependency via createRequire(package.json)',
    finalExponentiation: false,
    flattenOrder: factor.flattenOrder,
    terminalLimbCount: terminalLimbs.length,
    terminalLimbSha256LittleEndian: sha256(terminalConcat),
    terminalRedeemSha256: sha256(terminal),
    terminalPush: { opcodeOffset: terminalPush.opcodeOffset, dataOffset: terminalPush.dataOffset, length: terminalPush.length },
    limbs: terminalLimbs,
  },
  historicalFactorCertificate: {
    sha256: sha256(factorBytes),
    matchesDirectPacketPairing: factorMatchesDirect,
    usedAs: 'additional historical corroboration, not the source of the direct binding',
  },
  scope: 'Exact packet key-coordinate/source-role and pinned-vector terminal-factor readback only. No proof producer, fixture generation, negative suite, or VM execution. This does not establish the historical exporter link or full verifier soundness.',
}, null, 2));
