// Positive-only transport of sealed static corrections over archived payloads.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {decodeAuthenticationInstructions, encodeDataPush} from '@bitauth/libauth';

const sha256 = bytes => createHash('sha256').update(bytes).digest();
const hash256 = bytes => sha256(sha256(bytes));

export function adaptExistingPositives(artifactBytes, profile) {
  assert.equal(sha256(artifactBytes).toString('hex'), profile.originalSha256);
  const artifact = JSON.parse(artifactBytes);
  const cases = [{name: 'primary', steps: artifact.steps},
    ...artifact.extraValidProofs.map((steps, i) => ({name: `extra-${i}`, steps})),
    {name: 'worst-case', steps: artifact.worstCaseProof}];
  assert.equal(cases.length, 5);
  return cases.map(({name, steps}) => ({name, steps: steps.map((step, i) => {
    assert.equal(step.locking, profile.originalLockings[i]);
    const original = Buffer.from(step.unlocking, 'hex');
    const last = decodeAuthenticationInstructions(original).at(-1);
    assert.equal(Buffer.from(last.data).toString('hex'), profile.originalPrograms[i]);
    const oldPush = Buffer.from(encodeDataPush(last.data));
    assert(original.subarray(-oldPush.length).equals(oldPush));
    const prefix = original.subarray(0, -oldPush.length);
    const program = Buffer.from(profile.programs[i], 'hex');
    const locking = Buffer.from(profile.lockings[i], 'hex');
    if (profile.guardPlacement === 'locking' && i === profile.guardInput) {
      // The slim terminal keeps the original redeem hash prefix, then appends
      // the mandatory equation guard and the unchanged legacy locking tail.
      // Other profiles use the ordinary hash-wrapped transport below.
      const terminalHashPrefix = Buffer.concat([Buffer.from([0xaa, 0x20]), hash256(program), Buffer.from([0x88])]);
      assert(locking.subarray(0, terminalHashPrefix.length).equals(terminalHashPrefix));
      assert(locking.subarray(-program.length).equals(program));
      assert.equal(profile.programs[i], profile.originalPrograms[i]);
    } else {
      assert(locking.equals(Buffer.concat([Buffer.from([0xaa, 0x20]), hash256(program), Buffer.from([0x87])])));
    }
    return {...step, locking: locking.toString('hex'),
      unlocking: Buffer.concat([prefix, Buffer.from(encodeDataPush(program))]).toString('hex')};
  })}));
}
