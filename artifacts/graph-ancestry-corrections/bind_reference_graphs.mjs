// Bind exact program owners around frozen positive references. No compiler,
// producer, prover, planner, new proof, or resource-policy selection is used.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  bigIntToVmNumber, decodeAuthenticationInstructions, encodeDataPush,
  encodeLockingBytecodeP2sh32, hash256, OpcodesBCH as O,
} from '@bitauth/libauth';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const bytes = value => Buffer.from(value, 'hex');
const hex = value => Buffer.from(value).toString('hex');
const number = value => Buffer.from(encodeDataPush(bigIntToVmNumber(BigInt(value))));
const locking = code => Buffer.from(encodeLockingBytecodeP2sh32(hash256(code)));
const ops = (...names) => Buffer.from(names.map(name => {
  assert(Number.isInteger(O[name]), `unknown opcode ${name}`);
  return O[name];
}));
const join = (...parts) => Buffer.concat(parts);

function decodeStep(step) {
  const unlocking = bytes(step.unlocking);
  const instructions = decodeAuthenticationInstructions(unlocking);
  assert(instructions.every(i => !('error' in i) &&
    (i.data !== undefined || i.opcode === O.OP_0 || i.opcode === O.OP_1NEGATE ||
      i.opcode >= O.OP_1 && i.opcode <= O.OP_16)), 'push-only saved unlocking required');
  const code = Buffer.from(instructions.at(-1)?.data ?? []);
  assert(code.length > 0, 'missing redeem program');
  const codePush = Buffer.from(encodeDataPush(code));
  assert(unlocking.subarray(-codePush.length).equals(codePush), 'canonical redeem push required');
  assert.equal(hex(locking(code)), step.locking, 'saved P2SH32 owner mismatch');
  return {code, prefix: unlocking.subarray(0, -codePush.length)};
}

function absoluteRootPrefix(owners) {
  assert(owners.length > 0);
  const pins = owners.slice(1).map((owner, index) => {
    assert.equal(owner.length, 35);
    return join(number(index + 1), ops('OP_UTXOBYTECODE'),
      Buffer.from(encodeDataPush(owner)), ops('OP_EQUALVERIFY'));
  });
  return join(ops('OP_INPUTINDEX'), number(0), ops('OP_NUMEQUALVERIFY'),
    ops('OP_TXINPUTCOUNT'), number(owners.length), ops('OP_NUMEQUALVERIFY'), ...pins);
}

function tokenThreadPrefix(count, nextOwner) {
  // The profile carries one mutable NFT thread. Compare category bytes rather
  // than interpreting 32-byte identifiers as VM numbers.
  const mutable = join(number(0), ops('OP_UTXOTOKENCATEGORY'), number(32),
    ops('OP_SPLIT', 'OP_NIP'), number(1), ops('OP_EQUALVERIFY'));
  const siblings = Array.from({length: count - 1}, (_, index) => join(
    number(index + 1), ops('OP_UTXOTOKENCATEGORY', 'OP_SIZE'), number(0),
    ops('OP_NUMNOTEQUAL', 'OP_IF'),
    number(32), ops('OP_SPLIT', 'OP_DROP'),
    number(0), ops('OP_UTXOTOKENCATEGORY'), number(32), ops('OP_SPLIT', 'OP_DROP'),
    ops('OP_EQUAL', 'OP_NOT', 'OP_VERIFY', 'OP_ELSE', 'OP_DROP', 'OP_ENDIF'),
  ));
  const outputCount = join(ops('OP_TXOUTPUTCOUNT'), number(1), ops('OP_NUMEQUALVERIFY'));
  const terminal = nextOwner === undefined
    // EQUALVERIFY consumes both the category and the empty byte array.
    ? join(number(0), ops('OP_OUTPUTTOKENCATEGORY'), number(0), ops('OP_EQUALVERIFY'))
    : join(number(0), ops('OP_OUTPUTBYTECODE'), Buffer.from(encodeDataPush(nextOwner)),
      ops('OP_EQUALVERIFY'), number(0), ops('OP_UTXOTOKENCATEGORY'),
      number(0), ops('OP_OUTPUTTOKENCATEGORY'), ops('OP_EQUALVERIFY'));
  return join(mutable, ...siblings, outputCount, terminal);
}

function bindCases(cases, specifications, expectedHashes) {
  const first = cases[0].steps.map(decodeStep);
  const oldCodes = first.map(step => step.code), oldOwners = oldCodes.map(locking);
  if (expectedHashes !== undefined) assert.deepEqual(oldCodes.map(sha256), expectedHashes);
  for (const run of cases) {
    assert.equal(run.steps.length, oldCodes.length);
    run.steps.forEach((step, index) => {
      assert(decodeStep(step).code.equals(oldCodes[index]), `case program differs at ${index}`);
      assert.equal(step.locking, hex(oldOwners[index]));
    });
  }
  const codes = [...oldCodes], prefixes = new Map();
  for (const specification of specifications.slice().reverse()) {
    const {start, count, tokenThread, next} = specification;
    assert(start >= 0 && start + count <= codes.length);
    const graph = absoluteRootPrefix(oldOwners.slice(start, start + count));
    const prefix = tokenThread ? join(graph, tokenThreadPrefix(count,
      next === undefined ? undefined : locking(codes[next]))) : graph;
    codes[start] = join(prefix, oldCodes[start]);
    prefixes.set(start, prefix);
  }
  const owners = codes.map(locking);
  const boundCases = cases.map(run => ({
    name: run.name,
    steps: run.steps.map((step, index) => {
      const original = decodeStep(step);
      const unlocking = join(original.prefix, Buffer.from(encodeDataPush(codes[index])));
      assert(unlocking.subarray(0, original.prefix.length).equals(original.prefix));
      if (!prefixes.has(index)) assert.equal(hex(unlocking), step.unlocking);
      return {label: step.label, locking: hex(owners[index]), unlocking: hex(unlocking)};
    }),
    ...(run.groups === undefined ? {} : {groups: run.groups.map((group, index) => ({
      ...group,
      outLocking: specifications[index].next === undefined
        ? group.outLocking : hex(owners[specifications[index].next]),
    }))}),
  }));
  return {
    cases: boundCases,
    sourceProgramSha256: oldCodes.map(sha256), rootedProgramSha256: codes.map(sha256),
    rootBindings: specifications.map(({start, count, next, tokenThread}) => ({
      start, count, next: next ?? null, tokenThread: tokenThread === true,
      prefixHex: hex(prefixes.get(start)), prefixBytes: prefixes.get(start).length,
      sourceCodeSha256: sha256(oldCodes[start]), rootedCodeSha256: sha256(codes[start]),
      sourceCodeBytes: oldCodes[start].length, rootedCodeBytes: codes[start].length,
      rootedLocking: hex(owners[start]),
      originalUnlockingBytes: cases.map(run => bytes(run.steps[start].unlocking).length),
      rootedUnlockingBytes: boundCases.map(run => bytes(run.steps[start].unlocking).length),
    })),
    preservation: {
      sharedProgramSetAcrossCases: true, arithmeticBodiesByteIdentical: true,
      proofPublicStateTablePaddingPrefixesByteIdentical: true,
      nonRootProgramsAndUnlockingsByteIdentical: true,
    },
  };
}

export function bindDefaultGraph(packetBytes) {
  assert.equal(sha256(packetBytes), '672f206dac00d9626275b17dc63eaf75df252c37b9ec6978558a98ec1c277e17');
  const source = JSON.parse(packetBytes);
  assert.equal(source.cases.length, 3);
  const cases = source.cases.map((run, index) => ({name: `case-${index}`, steps: run.steps}));
  assert(cases.every(run => run.steps.length === 35));
  return {schema: 'root-bound-reference-graph/v1', id: 'bls-default-fp6-root-bound',
    sourcePacketSha256: sha256(packetBytes), topology: 'one-transaction',
    transactionInputCounts: [35], ...bindCases(cases, [{start: 0, count: 35}]),
    qualification: 'Graph binding transfers the prior finite-domain arithmetic theorem. Native resource admission, actual funding UTXOs and relay/mainnet admission remain separate.'};
}

export function bindGroupedGraph(packetBytes, frameManifestBytes) {
  assert.equal(sha256(packetBytes), 'f88d2274794b0e38c5254187c04d97033080b7fa84fafbccd982f99e5b4f19b1');
  assert.equal(sha256(frameManifestBytes), '5193b245337b0758120164142f956327ff25a4673e2147899dbdbf12ac9fbdb2');
  const id = 'bch-groth16-historical-bn27-grouped-frame-corrected';
  const source = JSON.parse(packetBytes).profiles.find(profile => profile.id === id);
  const frame = JSON.parse(frameManifestBytes).profiles.find(profile => profile.id === id);
  assert(source && frame && source.layout === 'grouped');
  assert.equal(source.cases.length, 3);
  assert(source.cases.every(run => run.steps.length === 27 && run.groups.length === 3));
  const specifications = [
    {start: 0, count: 9, tokenThread: true, next: 9},
    {start: 9, count: 9, tokenThread: true, next: 18},
    {start: 18, count: 9, tokenThread: true},
  ];
  for (const run of source.cases) assert.deepEqual(run.groups.map(group => [group.lo, group.hi]),
    [[0, 8], [9, 17], [18, 26]]);
  return {schema: 'root-bound-reference-graph/v1', id: 'bn254-grouped-root-bound',
    sourcePacketSha256: sha256(packetBytes), sourceFrameManifestSha256: sha256(frameManifestBytes),
    sourceProfileId: id, topology: 'three-group-baton-chain', transactionInputCounts: [9, 9, 9],
    ...bindCases(source.cases, specifications, frame.repairedProgramSha256),
    qualification: 'Exact group owners, mutable NFT continuation and terminal burn are enforced by stack-neutral prefixes around the prior finite-domain arithmetic. A designated initial root and valid ledger ancestry remain explicit premises.'};
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [profile, input, output, frameManifest, ...extra] = process.argv.slice(2);
  assert(profile && input && output && extra.length === 0,
    'usage: node bind_reference_graphs.mjs default|grouped input.json output.json [frame-manifest.json]');
  assert.notEqual(resolve(input), resolve(output));
  const packet = readFileSync(input);
  let result;
  if (profile === 'default') result = bindDefaultGraph(packet);
  else {
    assert.equal(profile, 'grouped');
    assert(frameManifest, 'grouped binding requires the corrected frame manifest');
    result = bindGroupedGraph(packet, readFileSync(frameManifest));
  }
  writeFileSync(output, JSON.stringify(result, null, 2) + '\n', {flag: 'wx'});
  console.log(JSON.stringify({id: result.id, cases: result.cases.length, roots: result.rootBindings}));
}
