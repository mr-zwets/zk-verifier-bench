// Standalone component correction; excluded from REGISTRY and the public feed.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {hexToBin} from '@bitauth/libauth';
import type {Implementation, Step} from '../harness/types.js';

interface RawStep {
  label: string; locking: string; unlocking: string; checkpoint?: string;
  covenant: {category: string; capability: 'none' | 'mutable' | 'minting';
    inCommitment: string; outCommitment: string; outLockingBytecode: string};
}
const catalogBytes = readFileSync('src/bch/vkx-bls12381-successor-corrected-catalog.json');
assert.equal(createHash('sha256').update(catalogBytes).digest('hex'), '5fbfb1b0995d2a555058203752d7800e4e4e82299156c8ab46d6a3675b30a1b1');
const catalog = JSON.parse(catalogBytes.toString('utf8')) as {
  fixture: {path: string; originalSha256: string}; originalLockings: string[]; selectedLockings: string[];
};
const toRun = (raw: RawStep[]): Step[] => raw.map((step, index) => {
  assert.equal(step.locking, catalog.originalLockings[index]);
  const locking = catalog.selectedLockings[index]!;
  const outLocking = catalog.selectedLockings[index + 1] ?? locking;
  return {label: step.label, checkpoint: step.checkpoint,
    lockingBytecode: hexToBin(locking), unlockingBytecode: hexToBin(step.unlocking),
    covenant: {category: hexToBin(step.covenant.category), capability: step.covenant.capability,
      inCommitment: hexToBin(step.covenant.inCommitment), outCommitment: hexToBin(step.covenant.outCommitment),
      outLockingBytecode: hexToBin(outLocking)}};
});

export const bchVkxBls12381SuccessorCorrected: Implementation = {
  id: 'bch-vkx-bls12381-successor-corrected',
  name: 'BLS12-381 vk_x successor-bound component (standalone; admission HOLD)',
  proofSystem: 'Groth16 vk_x (BCH-native)', field: 'BLS12-381', structure: 'multi-tx', proofBinding: 'runtime',
  source: 'Component-only correction of the existing eleven-stage public-input aggregation. Each nonterminal now hash-pins output[0] to the exact next program, while the original compiled suffix and all unlocking/commitment bytes are preserved. The terminal has no successor predicate. A designated connected NFT lineage and valid ledger ancestry remain composition premises; no complete pairing verifier, token lifecycle, whole-transaction or relay admission claim.',
  load: async () => {
    const bytes = readFileSync(catalog.fixture.path);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), catalog.fixture.originalSha256);
    const fixture = JSON.parse(bytes.toString('utf8')) as {steps: RawStep[]; extraValidProofs: RawStep[][]};
    return {valid: toRun(fixture.steps), extraValidProofs: fixture.extraValidProofs.map(toRun), invalid: [], invalidInputs: []};
  },
};
