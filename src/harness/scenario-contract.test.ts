import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from './types.js';
import { assertHonestRuns, assertRunShape } from './scenario-contract.js';
import type { ProofInput } from './types.js';
import { bchGroth16Singleton } from '../implementations/bch-groth16-singleton.js';
import { bchGroth16SingletonOpcodeOptimized } from '../implementations/bch-groth16-singleton-opcode-optimized.js';
import { bchGroth16Bls12381Singleton } from '../implementations/bch-groth16-bls12381-singleton.js';
import { bchGroth16Bls12381SingletonOpcodeOptimized } from '../implementations/bch-groth16-bls12381-singleton-opcode-optimized.js';
import { bchGroth16Grouped } from '../implementations/bch-groth16-grouped.js';

type MultiproofFixture = {
  lockingOK: string;
  proofs: { unlocking: string; committed: boolean }[];
};

const readFixture = (path: string): MultiproofFixture =>
  JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8')) as MultiproofFixture;

const bn254 = readFixture('../bch/groth16-singleton-multiproof-vectors.json');
const bls12381 = readFixture('../bch/groth16-bls12381-singleton-multiproof-vectors.json');
type IntraRawStep = { label: string; locking: string; unlocking: string };
const bls12381Intra = JSON.parse(
  readFileSync(new URL('../bch/groth16-bls12381-intratx-vectors.json', import.meta.url), 'utf8'),
) as { steps: IntraRawStep[] };

const step = (locking: string, unlocking: string, label: string): Step => ({
  label,
  lockingBytecode: hexToBin(locking),
  unlockingBytecode: hexToBin(unlocking),
});

const implementation = (proofInputs?: ProofInput[]): Implementation => ({
  id: 'scenario-contract-test',
  name: 'scenario contract test',
  proofSystem: 'fixture',
  field: '-',
  structure: 'single-tx',
  source: 'checked-in fixture',
  load: async () => ({ valid: [] }),
  ...(proofInputs === undefined ? {} : { proofInputs }),
}) as Implementation;

const valid = step(bn254.lockingOK, bn254.proofs[0]!.unlocking, 'BN254 primary');
const extra = step(bn254.lockingOK, bn254.proofs[1]!.unlocking, 'BN254 extra');

const toIntraRun = (raw: IntraRawStep[]): Step[] => {
  const inputs = raw.map((entry) => ({ lockingBytecode: hexToBin(entry.locking), unlockingBytecode: hexToBin(entry.unlocking) }));
  return raw.map((entry, index) => ({
    label: entry.label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    intraTx: { index, inputs },
  }));
};

const bls12381IntraValid = toIntraRun(bls12381Intra.steps);

test('rejects empty valid and extra runs before any VM work', () => {
  assert.throws(
    () => assertHonestRuns(implementation([{ input: 0, push: 0 }]), { valid: [] }),
    /valid.*run must be non-empty/,
  );
  assert.throws(
    () => assertHonestRuns(implementation([{ input: 0, push: 0 }]), { valid: [valid], extraValidProofs: [[]] }),
    /extra proof #1.*run must be non-empty/,
  );
  assert.throws(() => assertRunShape([], 'direct empty run'), /direct empty run.*non-empty/);
});

test('fingerprints only declared VM-number proof components from original multiproof bytes', () => {
  const result = assertHonestRuns(
    implementation([
      { input: 0, push: 2 },
      { input: 0, push: 3 },
    ]),
    { valid: [valid], extraValidProofs: [[extra]] },
  );
  assert.equal(result.proofIdentity.declared, true);
  assert.equal(result.proofIdentity.distinct, true);
  assert.deepEqual(result.distinctExtraProofs, [[extra]]);
});

test('reports a declared identity as not distinct when no extra honest proof is supplied', () => {
  const result = assertHonestRuns(implementation([{ input: 0, push: 2 }]), { valid: [valid] });
  assert.deepEqual(result.proofIdentity, {
    declared: true,
    distinct: false,
    reason: 'no distinct extra valid proof run supplied',
  });
  assert.deepEqual(result.distinctExtraProofs, []);
});

test('allows a worst-case run to reuse an existing honest proof fingerprint', () => {
  const result = assertHonestRuns(implementation([{ input: 0, push: 2 }]), {
    valid: [valid],
    worstCaseProof: [valid],
  });
  assert.equal(result.proofIdentity.declared, true);
  assert.equal(result.proofIdentity.distinct, false);
});

test('accepts the archived BLS12-381 intra-tx context and its shared sibling arrays', () => {
  const result = assertHonestRuns(implementation(), { valid: bls12381IntraValid });
  assert.equal(result.proofIdentity.declared, false);
  assert.equal(result.distinctExtraProofs.length, 0);
});

test('rejects a mismatched archived intra-tx sibling locking', () => {
  const mismatched = bls12381IntraValid.map((entry, index) => {
    if (index !== 0 || entry.intraTx === undefined) return entry;
    const inputs = entry.intraTx.inputs.map((input, inputIndex) =>
      inputIndex === 1 ? { ...input, lockingBytecode: bls12381IntraValid[0]!.lockingBytecode } : input,
    );
    return { ...entry, intraTx: { ...entry.intraTx, inputs } };
  });
  assert.throws(
    () => assertHonestRuns(implementation(), { valid: bls12381IntraValid, extraValidProofs: [mismatched] }),
    /extra proof #1 step 0.*intraTx\.inputs\[1\].lockingBytecode does not match/,
  );
});

test('rejects a worst-case run with the wrong count or deployed program', () => {
  assert.throws(
    () => assertHonestRuns(implementation(), { valid: [valid], worstCaseProof: [] }),
    /worst-case proof.*run must be non-empty/,
  );
  assert.throws(
    () => assertHonestRuns(implementation(), { valid: [valid], worstCaseProof: [valid, valid] }),
    /worst-case proof.*step count 2 differs from primary count 1/,
  );
  const mismatched = step(bls12381.lockingOK, bls12381.proofs[0]!.unlocking, 'wrong worst-case program');
  assert.throws(
    () => assertHonestRuns(implementation(), { valid: [valid], worstCaseProof: [mismatched] }),
    /worst-case proof.*lockingBytecode differs/,
  );
});

test('fingerprints a fixed packed byte slice from the existing proof region', () => {
  const result = assertHonestRuns(
    implementation([{ input: 0, push: 2, encoding: 'bytes', offset: 0, length: 4 }]),
    { valid: [valid], extraValidProofs: [[extra]] },
  );
  assert.equal(result.proofIdentity.declared, true);
  assert.equal(result.proofIdentity.distinct, true);
});

test('accepts the four declared affine singleton loaders and their archived honest runs', async () => {
  const implementations = [
    bchGroth16Singleton,
    bchGroth16SingletonOpcodeOptimized,
    bchGroth16Bls12381Singleton,
    bchGroth16Bls12381SingletonOpcodeOptimized,
  ];
  await Promise.all(
    implementations.map(async (candidate) => {
      const result = assertHonestRuns(candidate, await candidate.load());
      assert.equal(result.proofIdentity.declared, true, candidate.id);
      assert.equal(result.proofIdentity.distinct, true, candidate.id);
    }),
  );
});

test('rejects inconsistent effective grouped token metadata within one archived group', async () => {
  const scenario = await bchGroth16Grouped.load();
  const run = scenario.valid;
  const first = run[0]!;
  const firstGroup = first.grouped!.group;
  const siblingIndex = run.findIndex((entry, index) => index !== 0 && entry.grouped?.group === firstGroup);
  assert.ok(siblingIndex > 0);
  const foreign = run.find((entry) => entry.grouped?.group !== firstGroup && entry.grouped?.outToken !== undefined);
  assert.ok(foreign?.grouped?.outToken !== undefined);
  assert.notDeepEqual(foreign.grouped.outToken, first.grouped!.outToken);
  const mismatched = run.map((entry, index) =>
    index === siblingIndex
      ? { ...entry, grouped: { ...entry.grouped!, outToken: foreign.grouped!.outToken } }
      : entry,
  );
  assert.throws(
    () => assertRunShape(mismatched, 'grouped metadata mismatch'),
    /grouped metadata mismatch.*grouped\.outToken differs from group context/,
  );
});

test('rejects a duplicate existing proof fingerprint', () => {
  assert.throws(
    () => assertHonestRuns(implementation([{ input: 0, push: 2 }]), { valid: [valid], extraValidProofs: [[{ ...valid, label: 'same primary proof' }]] }),
    /extra proof #1.*duplicates valid/,
  );
  assert.throws(
    () =>
      assertHonestRuns(
        implementation([{ input: 0, push: 2 }, { input: 0, push: 3 }]),
        { valid: [valid], extraValidProofs: [[extra], [{ ...extra, label: 'same proof, different label' }]] },
      ),
    /extra proof #2.*duplicates extra proof #1/,
  );
});

test('rejects an existing BLS12-381 program when the honest program is BN254', () => {
  const mismatched = step(bls12381.lockingOK, bls12381.proofs[0]!.unlocking, 'BLS12-381 fixture');
  assert.throws(
    () => assertHonestRuns(implementation([{ input: 0, push: 0 }]), { valid: [valid], extraValidProofs: [[mismatched]] }),
    /extra proof #1.*lockingBytecode differs/,
  );
});

test('does not infer proof identity when locators are absent', () => {
  const result = assertHonestRuns(implementation(), { valid: [valid], extraValidProofs: [[extra]] });
  assert.deepEqual(result.proofIdentity, {
    declared: false,
    distinct: false,
    reason: 'proofInputs locators are missing; no extra proof can be qualified',
  });
  assert.deepEqual(result.distinctExtraProofs, []);
});

test('rejects malformed declared byte locators explicitly', () => {
  assert.throws(
    () => assertHonestRuns(implementation([{ input: 0, push: 2, encoding: 'bytes', length: 0 }]), { valid: [valid] }),
    /proofInputs\[0\].*positive length/,
  );
  assert.throws(
    () => assertHonestRuns(implementation([{ input: 0, push: 99 }]), { valid: [valid] }),
    /proofInputs\[0\].*out of bounds/,
  );
});
