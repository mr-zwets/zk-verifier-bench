// Standalone positive-only correction. Native resource admission remains HOLD.
// Deliberately excluded from the default REGISTRY.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';
import { adaptExistingPositives, type RawStep } from '../bch/pairfold5-pevalfuse-deterministic-adapter.mjs';
import type { Implementation, Step } from '../harness/types.js';

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((step) => ({
    lockingBytecode: hexToBin(step.locking),
    unlockingBytecode: hexToBin(step.unlocking),
    valueSatoshis: 1000n,
    sequenceNumber: 0,
  }));
  return raw.map((step, index) => ({
    label: step.label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: step.checkpoint,
    valueSatoshis: 1000n,
    sequenceNumber: 0,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16IntratxPairfold5PevalfuseDeterministic: Implementation = {
  id: 'bch-groth16-intratx-pairfold5-pevalfuse-deterministic',
  publicInputs: [{ input: 3, push: 37, name: 'n0' }, { input: 3, push: 36, name: 'n1' }],
  name: 'BCH Groth16 native5 deterministic equation guard (native resource HOLD)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Standalone positive-only packet for chunked/bn254/pairfold5-pevalfuse-deterministic. ' +
    'The exact authenticated checker and mandatory genesis bridge own the complete fixed-VK equation. ' +
    'Historical observations on these exact selected programs: 25/25 resource-loosened arithmetic-oracle ' +
    'inputs accepted; 40/50 unchanged declared BCH2026 inputs accepted, with all ten failures at genesis ' +
    'operation-cost density. Zero complete declared graphs passed. Native resource admission is HOLD. ' +
    'The current artifact and harness/runtime sources match the recorded identity; no fresh current-checkout ' +
    'execution, whole-transaction admission, independent legacy PIT soundness or universal producer totality is claimed.',
  load: async () => {
    const { positiveCases } = adaptExistingPositives({
      artifactBytes: readFileSync('src/bch/groth16-intratx-pairfold5-pevalfuse-vectors.json'),
      catalogBytes: readFileSync('src/bch/groth16-intratx-pairfold5-pevalfuse-deterministic-catalog.json'),
      expectedCatalogSha256: 'f2d6afdbeb47e29afcd674f97e6788838e0ab4af4e313e138633eaeb51af9316',
    });
    return {
      valid: toRun(positiveCases[0]!.steps),
      extraValidProofs: positiveCases.slice(1, 4).map(({ steps }) => toRun(steps)),
      worstCaseProof: toRun(positiveCases[4]!.steps),
      invalid: [],
      invalidInputs: [],
    };
  },
};
