// Standalone frozen BN254 exact-frame corrections. Deliberately excluded from
// the default REGISTRY: these are positive-only repaired artifacts and remain
// admission-HOLD until the surrounding mathematical and ledger premises are
// independently accepted.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {hexToBin} from '@bitauth/libauth';
import type {Implementation, Step} from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string; group?: number }
interface RawGroup {
  lo: number; hi: number;
  inToken?: {capability: 'none' | 'mutable' | 'minting'; commitment: string} | null;
  outToken?: {capability: 'none' | 'mutable' | 'minting'; commitment: string} | null;
  outLocking?: string | null;
}
interface RawRun { steps: RawStep[]; groups?: RawGroup[] }
interface Vectors {
  category?: string;
  steps?: RawStep[];
  valid?: RawRun;
  extraValidProofs?: RawStep[][] | RawRun[];
  worstCaseProof?: RawStep[] | RawRun;
}
interface Profile {
  id: string;
  vectorFile: string;
  originalId: string;
  structure: 'single-tx' | 'multi-tx' | 'single-tx-component';
  claim: string;
  correctedVectorSha256: string;
}
interface Catalog {schema: string; sourceBaseRevision: string; benchmarkBase: string; sourceHelper: {file: string; sha256: string}; profiles: Profile[]}

const catalogBytes = readFileSync('src/bch/bn-exact-frame-corrected-catalog.json');
const catalogHash = createHash('sha256').update(catalogBytes).digest('hex');
const EXPECTED_CATALOG_SHA256 = '4def718ae32d905504053ea30e73df6b274c36722142c1597bef3e97c2bb179d';
assert.equal(catalogHash, EXPECTED_CATALOG_SHA256, 'catalog seal mismatch');
const catalog = JSON.parse(catalogBytes.toString('utf8')) as Catalog;
assert.equal(catalog.schema, 'bn254-exact-frame-correction-catalog/v1');

const publicInputsById: Record<string, {input: number; push: number; offset: number; encoding: 'le32'; name: string}[]> = {
  'bch-groth16-intratx-exact-frame-corrected': [
    {input: 3, push: 0, offset: 0, encoding: 'le32', name: 'n0'}, {input: 3, push: 0, offset: 32, encoding: 'le32', name: 'n1'},
    {input: 4, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 4, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 5, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 5, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 6, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 6, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 7, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 7, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 8, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 8, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
  ],
  'bch-groth16-grouped-exact-frame-corrected': [
    {input: 3, push: 0, offset: 0, encoding: 'le32', name: 'n0'}, {input: 3, push: 0, offset: 32, encoding: 'le32', name: 'n1'},
    {input: 4, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 4, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 5, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 5, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 6, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 6, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 7, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 7, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 8, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 8, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
  ],
  'bch-groth16-intratx-residue-exact-frame-corrected': [
    {input: 0, push: 0, offset: 0, encoding: 'le32', name: 'n0'}, {input: 0, push: 0, offset: 32, encoding: 'le32', name: 'n1'},
    {input: 0, push: 0, offset: 64, encoding: 'le32', name: 'n0'}, {input: 0, push: 0, offset: 98, encoding: 'le32', name: 'n1'},
    {input: 1, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 1, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 1, push: 0, offset: 160, encoding: 'le32', name: 'n0'}, {input: 1, push: 0, offset: 194, encoding: 'le32', name: 'n1'},
  ],
  'bch-groth16-grouped-residue-exact-frame-corrected': [
    {input: 3, push: 0, offset: 0, encoding: 'le32', name: 'n0'}, {input: 3, push: 0, offset: 32, encoding: 'le32', name: 'n1'},
    {input: 3, push: 0, offset: 64, encoding: 'le32', name: 'n0'}, {input: 3, push: 0, offset: 98, encoding: 'le32', name: 'n1'},
    {input: 4, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 4, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 4, push: 0, offset: 160, encoding: 'le32', name: 'n0'}, {input: 4, push: 0, offset: 194, encoding: 'le32', name: 'n1'},
    {input: 5, push: 0, offset: 96, encoding: 'le32', name: 'n0'}, {input: 5, push: 0, offset: 128, encoding: 'le32', name: 'n1'},
    {input: 5, push: 0, offset: 160, encoding: 'le32', name: 'n0'}, {input: 5, push: 0, offset: 194, encoding: 'le32', name: 'n1'},
  ],
};

const toRun = (vector: Vectors, raw: RawRun): Step[] => {
  if (!raw.groups) {
    const inputs = raw.steps.map((step) => ({lockingBytecode: hexToBin(step.locking), unlockingBytecode: hexToBin(step.unlocking)}));
    return raw.steps.map((step, index) => ({label: step.label, ...inputs[index]!, checkpoint: step.checkpoint, intraTx: {index, inputs}}));
  }
  const category = hexToBin(vector.category!);
  const inputsByGroup = raw.groups.map((group) => raw.steps.slice(group.lo, group.hi + 1)
    .map((step) => ({lockingBytecode: hexToBin(step.locking), unlockingBytecode: hexToBin(step.unlocking)})));
  return raw.steps.map((step, index) => {
    const groupIndex = step.group!;
    const group = raw.groups![groupIndex]!;
    const token = (value: RawGroup['inToken']) => value ? {capability: value.capability, commitment: hexToBin(value.commitment)} : undefined;
    return {
      label: step.label,
      lockingBytecode: hexToBin(step.locking), unlockingBytecode: hexToBin(step.unlocking), checkpoint: step.checkpoint,
      grouped: {
        group: groupIndex, index: index - group.lo, inputs: inputsByGroup[groupIndex]!, category,
        inToken: token(group.inToken), outToken: token(group.outToken),
        outLockingBytecode: group.outLocking ? hexToBin(group.outLocking) : undefined,
      },
    };
  });
};

const positive = (vector: Vectors): RawRun[] => vector.steps
  ? [{steps: vector.steps}, ...(vector.extraValidProofs as RawStep[][] ?? []).map((steps) => ({steps})), ...(vector.worstCaseProof ? [{steps: vector.worstCaseProof as RawStep[]}] : [])]
  : [vector.valid!, ...(vector.extraValidProofs as RawRun[] ?? []), ...(vector.worstCaseProof ? [vector.worstCaseProof as RawRun] : [])];

const implementationFor = (profile: Profile): Implementation => {
  const vectorBytes = readFileSync(`src/bch/${profile.vectorFile}`);
  assert.equal(createHash('sha256').update(vectorBytes).digest('hex'), profile.correctedVectorSha256,
    `${profile.id}: corrected vector seal mismatch`);
  const vector = JSON.parse(vectorBytes.toString('utf8')) as Vectors;
  const runs = positive(vector);
  return {
    id: profile.id,
    publicInputs: publicInputsById[profile.id] ?? [],
    name: `${profile.originalId} exact-frame correction (standalone; admission HOLD)`,
    proofSystem: profile.structure === 'single-tx-component' ? 'Pairing component' : 'Groth16',
    field: 'BN254', structure: profile.structure === 'single-tx-component' ? 'single-tx' : profile.structure,
    proofBinding: 'runtime',
    source: `Frozen positive-only exact-frame correction for ${profile.originalId}. ${profile.claim}. ` +
      `The original witness/state/table/padding instructions are preserved; only the exact frame predicate and coherent successor bindings are repaired. ` +
      `Catalog SHA-256 ${catalogHash}. This descriptor is outside the default REGISTRY; native, standard-admission and whole-transaction claims remain HOLD.`,
    load: async () => ({
      valid: toRun(vector, runs[0]!),
      extraValidProofs: runs.slice(1, vector.worstCaseProof ? -1 : undefined).map((run) => toRun(vector, run)),
      worstCaseProof: vector.worstCaseProof ? toRun(vector, runs.at(-1)!) : undefined,
      invalid: [], invalidInputs: [],
    }),
  };
};

export const bchBnExactFrameCorrected: Implementation[] = catalog.profiles.map(implementationFor);
