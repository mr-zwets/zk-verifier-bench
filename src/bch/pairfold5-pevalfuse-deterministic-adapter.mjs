// In-memory transport for the five exact archived positive payload sets.
// This module has no CLI, file writes, producer imports, or VM dependency.
// The caller supplies the sealed historical static catalog bytes and hash.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

export const originalArtifactSha256 = '898a83fe59c33392651aa09b83346486841ae3e0c5713982d2b4f5798ac87e12';
const sourceHead = '1e7c52ab3b6af132c3f3f87effd38821828c874d';
const benchmarkHead = 'aede1967237b3d7e28f9ca74ab52232e7e6d5421';
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const hash256 = bytes => sha256(sha256(bytes));

function bytes(hex) {
  assert.equal(typeof hex, 'string');
  assert(/^(?:[0-9a-f]{2})*$/.test(hex), 'expected canonical hexadecimal');
  return Buffer.from(hex, 'hex');
}

// Return original instruction boundaries. Payload instructions are never rebuilt.
function pushes(script) {
  const result = [];
  let offset = 0;
  while (offset < script.length) {
    const start = offset, opcode = script[offset++];
    let length, data;
    if (opcode === 0) data = Buffer.alloc(0);
    else if (opcode === 79) data = Buffer.from([129]);
    else if (opcode >= 81 && opcode <= 96) data = Buffer.from([opcode - 80]);
    else {
      if (opcode >= 1 && opcode <= 75) length = opcode;
      else if (opcode === 76) {
        assert(offset + 1 <= script.length, 'truncated PUSHDATA1 length');
        length = script[offset++];
      } else if (opcode === 77) {
        assert(offset + 2 <= script.length, 'truncated PUSHDATA2 length');
        length = script.readUInt16LE(offset); offset += 2;
      } else if (opcode === 78) {
        assert(offset + 4 <= script.length, 'truncated PUSHDATA4 length');
        length = script.readUInt32LE(offset); offset += 4;
      } else assert.fail('original unlocking contains a non-push instruction');
      assert(length <= script.length - offset, 'truncated push data');
      data = script.subarray(offset, offset + length); offset += length;
    }
    result.push({start, end: offset, data});
  }
  return result;
}

// Used only for newly inserted static pages and replacement static redeems.
function push(data) {
  const length = data.length;
  if (length === 0) return Buffer.from([0]);
  if (length === 1 && data[0] >= 1 && data[0] <= 16) return Buffer.from([80 + data[0]]);
  if (length === 1 && data[0] === 129) return Buffer.from([79]);
  let header;
  if (length <= 75) header = Buffer.from([length]);
  else if (length <= 255) header = Buffer.from([76, length]);
  else if (length <= 65535) {
    header = Buffer.alloc(3); header[0] = 77; header.writeUInt16LE(length, 1);
  } else {
    assert(length <= 4294967295, 'push length exceeds serialization format');
    header = Buffer.alloc(5); header[0] = 78; header.writeUInt32LE(length, 1);
  }
  return Buffer.concat([header, data]);
}

function p2sh32(redeem) {
  return Buffer.concat([Buffer.from([170, 32]), hash256(redeem), Buffer.from([135])]);
}

/**
 * Adapt only the five archived positive cases, in memory, without changing payload instructions.
 * catalog schema is documented in catalog-interface-v1.json.
 * The supplied catalog hash binds all static selected code/page bytes. This does
 * not establish their mathematics, provenance, or resource admission by itself.
 */
export function adaptExistingPositives({artifactBytes, catalogBytes, expectedCatalogSha256}) {
  assert(Buffer.isBuffer(artifactBytes) && Buffer.isBuffer(catalogBytes));
  assert.equal(sha256(artifactBytes).toString('hex'), originalArtifactSha256);
  assert(/^[0-9a-f]{64}$/.test(expectedCatalogSha256));
  assert.equal(sha256(catalogBytes).toString('hex'), expectedCatalogSha256);
  const artifact = JSON.parse(artifactBytes.toString('utf8'));
  const catalog = JSON.parse(catalogBytes.toString('utf8'));
  assert.equal(catalog.schema, 'verifier.cash/benchmark32-static-equation-pages/v1');
  assert.equal(catalog.sourceHead, sourceHead);
  assert.equal(catalog.benchmarkHead, benchmarkHead);
  assert.equal(catalog.originalArtifactSha256, originalArtifactSha256);
  for (const side of ['original', 'selected']) {
    assert.equal(catalog[side].redeems.length, 5);
    assert.equal(catalog[side].lockings.length, 5);
    catalog[side].redeems.forEach((redeem, i) => {
      const code = bytes(redeem); assert(code.length > 0);
      assert.deepEqual(bytes(catalog[side].lockings[i]), p2sh32(code));
    });
  }
  assert.equal(catalog.selected.equationPages.length, 3);
  const pages = catalog.selected.equationPages.map(bytes);
  for (let i = 0; i < 3; i++) {
    assert.equal(catalog.selected.redeems[i], '75' + catalog.original.redeems[i],
      'selected worker must prepend exactly the page-consuming DROP');
  }
  assert.equal(artifact.extraValidProofs.length, 3);
  const cases = [
    {label: 'steps', steps: artifact.steps},
    ...artifact.extraValidProofs.map((steps, i) => ({label: `extraValidProofs[${i}]`, steps})),
    {label: 'worstCaseProof', steps: artifact.worstCaseProof},
  ];
  const positiveCases = cases.map(({label, steps}) => {
    assert.equal(steps.length, 5);
    return {label, steps: steps.map((step, i) => {
      assert.equal(step.locking, catalog.original.lockings[i]);
      const original = bytes(step.unlocking), instructions = pushes(original);
      assert.equal(instructions.length, [6, 6, 6, 39, 46][i]);
      const last = instructions.at(-1);
      assert.equal(last.end, original.length);
      assert.equal(last.data.toString('hex'), catalog.original.redeems[i]);
      const originalPayloadInstructions = original.subarray(0, last.start);
      const selectedRedeem = push(bytes(catalog.selected.redeems[i]));
      const unlocking = Buffer.concat(i < 3
        ? [originalPayloadInstructions, push(pages[i]), selectedRedeem]
        : [originalPayloadInstructions, selectedRedeem]);
      return {...step, locking: catalog.selected.lockings[i], unlocking: unlocking.toString('hex')};
    })};
  });
  return {originalArtifactSha256, staticCatalogSha256: expectedCatalogSha256, positiveCases};
}
