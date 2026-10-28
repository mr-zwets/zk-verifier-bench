// Exact compiled-body transfer under static function-identifier renaming only.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const [checkout, oldArtifact, newArtifact, output] = process.argv.slice(2);
assert(checkout && oldArtifact && newArtifact && output && process.argv.length === 6);
const require = createRequire(resolve(checkout, 'package.json'));
const {decodeAuthenticationInstructions, encodeAuthenticationInstruction, OpcodesBCH: O, vmNumberToBigInt} =
  await import(pathToFileURL(require.resolve('@bitauth/libauth')));
const sha = data => createHash('sha256').update(data).digest('hex');
function literal(instruction) {
  assert(instruction);
  if (instruction.opcode === O.OP_0) return 0;
  if (instruction.opcode >= O.OP_1 && instruction.opcode <= O.OP_16) return instruction.opcode - 80;
  assert(instruction.data !== undefined, 'Call identifiers must be static pushes');
  const value = vmNumberToBigInt(instruction.data, {requireMinimalEncoding: false});
  assert.equal(typeof value, 'bigint');
  const result = Number(value); assert(Number.isSafeInteger(result)); return result;
}
function parse(path) {
  const code = Buffer.from(readFileSync(path, 'utf8').trim(), 'hex');
  const instructions = decodeAuthenticationInstructions(code);
  assert(instructions.every(item => !('error' in item)));
  const definitions = new Map(); let index = 0;
  while (instructions[index]?.data && instructions[index + 2]?.opcode === O.OP_DEFINE) {
    const id = literal(instructions[index + 1]);
    assert(!definitions.has(id));
    definitions.set(id, {id, bytes: instructions[index].data,
      body: decodeAuthenticationInstructions(instructions[index].data)});
    index += 3;
  }
  const main = instructions.slice(index);
  const fingerprints = new Map(); const visiting = new Set();
  function tokens(body) {
    return body.map((instruction, position) => {
      assert.notEqual(instruction.opcode, O.OP_DEFINE, 'No namespace mutation after preamble');
      if (body[position + 1]?.opcode === O.OP_INVOKE) {
        const callee = literal(instruction);
        assert(definitions.has(callee));
        return `STATIC_CALLEE:${fingerprint(callee)}`;
      }
      if (instruction.opcode === O.OP_INVOKE) assert(position > 0 && definitions.has(literal(body[position - 1])));
      return Buffer.from(encodeAuthenticationInstruction(instruction)).toString('hex');
    });
  }
  function fingerprint(id) {
    if (fingerprints.has(id)) return fingerprints.get(id);
    assert(!visiting.has(id), 'Recursive call transfer is not supported');
    visiting.add(id);
    const result = sha(JSON.stringify(tokens(definitions.get(id).body)));
    fingerprints.set(id, result); visiting.delete(id); return result;
  }
  const rows = [...definitions.values()].map(entry => ({id: entry.id, bytes: entry.bytes.length,
    bodySha256: sha(entry.bytes), recursiveFingerprint: fingerprint(entry.id)}));
  const mainTokens = tokens(main);
  return {path, artifactSha256: sha(code), bytes: code.length, definitions: rows, mainTokens,
    mainInstructions: main.length, rawStaticInvokes: [...definitions.values()].reduce((sum, entry) =>
      sum + entry.body.filter(item => item.opcode === O.OP_INVOKE).length, 0) + main.filter(item => item.opcode === O.OP_INVOKE).length};
}
const old = parse(oldArtifact), current = parse(newArtifact);
const matches = old.definitions.map(before => ({oldId: before.id, oldBodySha256: before.bodySha256,
  recursiveFingerprint: before.recursiveFingerprint,
  newMatches: current.definitions.filter(after => after.recursiveFingerprint === before.recursiveFingerprint)
    .map(after => ({id: after.id, bodySha256: after.bodySha256, exactRawBody: after.bodySha256 === before.bodySha256}))}));
let suffix = 0;
while (suffix < Math.min(old.mainTokens.length, current.mainTokens.length) &&
  old.mainTokens.at(-suffix - 1) === current.mainTokens.at(-suffix - 1)) suffix++;
const report = {schema: 'compiled-callee-semantics-transfer/v1', status: 'EXACT_STATIC_IDENTIFIER_RENAMING_TRANSFER',
  toolSha256: sha(readFileSync(new URL(import.meta.url))),
  old: {...old, mainTokens: undefined}, current: {...current, mainTokens: undefined}, matches,
  commonMainSuffix: {instructions: suffix, oldStart: old.mainInstructions - suffix,
    currentStart: current.mainInstructions - suffix,
    qualification: 'Exact normalized instructions only; transfer additionally requires actual equal stack operands and entry shape at this boundary.'},
  untransferredOldIds: matches.filter(entry => entry.newMatches.length === 0).map(entry => entry.oldId),
  activity: {compilerRuns: 0, vmRuns: 0, newProofCases: 0, negativeCases: 0, cybersecurityTesting: false, byteOptimization: false}};
assert.equal(old.artifactSha256, 'bec94008264eefa667247df1cbb3376299a5061cdcb5a1e4cda8b92c9a91abbb');
assert.equal(current.artifactSha256, 'c34b223e101f14b5a53bb9d6ab9fed3fd6a7174501a9a4fb1ddc36897f466ca1');
writeFileSync(output, JSON.stringify(report, null, 2) + '\n', {flag: 'wx'});
console.log(JSON.stringify({oldDefinitions: old.definitions.length, currentDefinitions: current.definitions.length,
  transferred: matches.filter(entry => entry.newMatches.length > 0).length,
  untransferredOldIds: report.untransferredOldIds, commonMainSuffix: report.commonMainSuffix,
  currentStaticInvokes: current.rawStaticInvokes}));
