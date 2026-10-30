// Current-BCH BLS12-381 FS-PIT, 11 P2SH32 inputs, all 21 logical stages.
// Qualified source: c5c3a91e976c07da36c88bbdaaec706e655fd613; owner SHA256: 3dcf2e852d2a3ce6e2bfe278cd40d1b195fe75ba36593e34f14d07025022aec0.
// Coordinator-tail helper SHA256: 79b0a3efda96f27475613a16194baebf472ca9b0d90e6da70a991195784d942e.
// Compiler efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4; complete buildFlags in vectors.
// 61835 script + 493 overhead = 62328 total challenge bytes.
// Default-off RPA_COORDINATOR_TAIL_BYTES=1024 requires paired-eval6 Regular triples.
// Move1024B of coordinator code into existing funding payloads at logical5/8;
// the coordinator shrinks983B after loader/DEFINE/INVOKE overhead. No funding added.
// Original immutable sibling-locking check remains inline before imported logic.
// Suffix starts at a balanced control-flow cut after that check, excludes DEFINE,
// ACTIVEBYTECODE/CODESEPARATOR/RETURN, and uses only existing literal callees.
// Raw function key12 is guarded unused. Re-pin final worker locking digest, then
// load the tail from authenticated sibling redeems, DEFINE and INVOKE it once.
// Tail excludes the expected worker hash; construction has no hash fixed point.
// Existing PUSHDATA2/DROP widths, carrier program lengths and suffix owners exact.
// Four new controls change code or rebind a valid producer: coordinator rejects.
// All archived proof/witness/public/root/quotient/aux/challenge/state values fixed.
// Existing528B arithmetic library, transcript/parsers/equations/verdict retained.
// Native primary C/STD: 37856918/38030358; maximum: 49489638/49841638.
// Minimum sampled margins C/STD: 21279/15519.
// Ten normal exports: 3140 owning/whole source checks. Actual native:
// 956 contexts, 220 reconciled positive input prices; failures null.
// All150 prior invalids/307 direct origins, 157 source cases,
// 7 hash flips, plus4carrier controls retained as154 unique transactions.
// Both flag-off10/11 whole reports exact. Adapter executable body and all spec entries exact.
// FS-PIT/exact-G2/cofactor-equivalent-G1 and input-validation/security grades unchanged.
// Finite supplied cohort only: no universal resource/soundness or live relay claim.
// Locking-set SHA256: 7be1c6475d0a377a27aa2a73d92e4d81704784dcccfa621e1ac531e864af8419. Vector SHA256: 6fbbe82d51876bbd4b992089530cafc752e6a4a7db530d9cf62b3414f0740cf8.
import { readFileSync } from 'node:fs';

import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';
import { bls12381IntratxFsProofInputs } from './groth16-proof-inputs.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
}

interface Vectors {
  steps: RawStep[];
  extraValidProofs: RawStep[][];
  worstCaseProof: RawStep[];
  invalid: RawStep[][];
}

const vectors = JSON.parse(readFileSync(
  'src/bch/groth16-bls12381-intratx-fs-regular-initializer-vectors.json',
  'utf8',
)) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map(({ locking, unlocking }) => ({
    lockingBytecode: hexToBin(locking),
    unlockingBytecode: hexToBin(unlocking),
  }));
  return raw.map(({ label }, index) => ({
    label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16Bls12381IntratxFsRegularInitializer: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-regular-initializer',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT with Regular arithmetic initializer (11 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The unchanged 535-byte arithmetic initializer is carried by the Regular representative. The externally anchored coordinator commits to the 10 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'Regular14/AdditionMiddle15, Regular2/3 and Regular5/6/7,8/9/10,11/12/13,16/17/18 each share an input and initialized arithmetic; Regular19/Terminal20 share another; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
    'an exact G2 subgroup check. A/C are on-curve and equation-binding, while unique G1 ' +
    'subgroup encodings and the separate harness input-validation grade are not claimed. ' +
    'One locking set accepts all ten supplied equation-valid fixtures. The candidate has ' +
    'finite ten-fixture source and current-native coverage only; universal operation-cost ' +
    'and resource certification remains pending.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: vectors.extraValidProofs.map(toRun),
    worstCaseProof: toRun(vectors.worstCaseProof),
    invalid: vectors.invalid.map(toRun),
  }),
};
