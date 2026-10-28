// Standalone reference successors; excluded from the default registry and feed.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {hexToBin} from '@bitauth/libauth';
import {adaptExistingPositives, type Profile, type RawStep} from '../bch/bn254-legacy-equation-checked-adapter.mjs';
import type {Implementation, Step} from '../harness/types.js';

const bytes = readFileSync('src/bch/groth16-bn254-legacy-equation-checked-catalog.json');
assert.equal(createHash('sha256').update(bytes).digest('hex'), '51ef1509eca342bc931b1f92ef57fc1af719948654399faeef5e4a9986d337c0');
const catalog = JSON.parse(bytes.toString('utf8')) as {schema: string; profiles: Profile[]};
assert.equal(catalog.schema, 'bn254-legacy-equation-checked-static-code/v1');

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map(step => ({lockingBytecode: hexToBin(step.locking), unlockingBytecode: hexToBin(step.unlocking)}));
  return raw.map((step, index) => ({label: step.label, ...inputs[index]!, checkpoint: step.checkpoint,
    intraTx: {index, inputs}}));
};

export const bchGroth16Bn254LegacyEquationChecked: Implementation[] = catalog.profiles.map(profile => ({
  id: profile.id,
  publicInputs: [{input: profile.guardInput, push: profile.n0Push, name: 'n0'},
    {input: profile.guardInput, push: profile.n1Push, name: 'n1'}],
  name: `${profile.originalId} with mandatory equation check (native HOLD)`,
  vm: profile.declaredVm,
  proofSystem: 'Groth16', field: 'BN254', structure: 'single-tx', proofBinding: 'runtime',
  source: profile.verificationKeyScope + '. Standalone positive-only mathematical reference. A mandatory copied fixed-key checker binds the actual public scalars and proof tuple before the legacy program. Legacy auxiliary checks only restrict acceptance. Existing payload instructions are preserved. Slim uses a bare terminal locking to preserve its archived reverse-offset state readers. Native resources and relay admission remain HOLD; no universal completeness, independent legacy soundness, or score claim.',
  load: async () => {
    const cases = adaptExistingPositives(readFileSync(`src/bch/${profile.file}`), profile);
    return {valid: toRun(cases[0]!.steps), extraValidProofs: cases.slice(1, 4).map(c => toRun(c.steps)),
      worstCaseProof: toRun(cases[4]!.steps), invalid: [], invalidInputs: []};
  },
}));
