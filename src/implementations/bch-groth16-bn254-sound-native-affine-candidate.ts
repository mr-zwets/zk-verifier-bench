/**
 * BN254 fixed-VK degree-six candidate; committed existing proof vectors.
 * Conditional mathematical scope and provenance: artifacts/bn254-native-affine-candidate/docs/submission-claims.md.
 * External constructive review and upstream admission remain pending.
 * C7553 SHA-256: 63f12474082916e22ab62faf6c6f0483bedcbb08a9700e4d7eb02415c9d8c242
 * R61 SHA-256: 0563cd756e2d300b7653e10fd2e39ba5951e404210ba78f18d8ba4549719a030
 * P2SH32 locking SHA-256: a32303cca71026a88ad8cd74bf38c6c8f6a8794cfa3065af7e7e207d8cf9d2c7
 */
import {readFileSync} from 'node:fs';
import {hexToBin} from '@bitauth/libauth';
import type {Implementation, Step} from '../harness/types.js';
import {bn254SoundNativeProofInputs} from './groth16-proof-inputs.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[] }
interface ExistingInvalidCase { id: number; label: string; exactArchivedPrefixSha256: string; steps: RawStep[] }
interface ExistingInvalidVectors { cases: ExistingInvalidCase[] }

const vectors = JSON.parse(
  readFileSync('src/bch/bch-groth16-bn254-sound-native-affine-candidate-positive-vectors.json', 'utf8'),
) as Vectors;
const existingInvalid = JSON.parse(
  readFileSync('src/bch/bch-groth16-bn254-sound-native-affine-candidate-existing-invalid-vectors.json', 'utf8'),
) as ExistingInvalidVectors;

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
    intraTx: {index, inputs},
  }));
};

export const bchGroth16Bn254SoundNativeAffineCandidate: Implementation = {
  id: 'bch-groth16-bn254-sound-native-affine-candidate',
  name: 'BCH Groth16 BN254 degree-six prefix extraction',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  vm: 'bch-2026',
  publicInputs: [
    {input: 2, push: 1, name: 'n0', offset: 256, encoding: 'le32'},
    {input: 2, push: 1, name: 'n1', offset: 288, encoding: 'le32'},
  ],
  proofInputs: bn254SoundNativeProofInputs,
  source: 'Fixed benchmark VK and declared finite curve domain. Conditional local mathematical review, exact artifacts, build provenance and existing-fixture evidence are documented in artifacts/bn254-native-affine-candidate/docs/submission-claims.md. External constructive review and upstream admission remain pending.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: existingInvalid.cases.filter((item) => item.id !== 12 && item.id !== 13).map((item) => toRun(item.steps)),
    invalidInputs: existingInvalid.cases.filter((item) => item.id === 12 || item.id === 13).map((item) => toRun(item.steps)),
  }),
};
