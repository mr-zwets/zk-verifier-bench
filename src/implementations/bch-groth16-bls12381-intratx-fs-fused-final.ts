// Complete current-BCH BLS12-381 Groth16 Fiat-Shamir PIT verifier,21 P2SH32 inputs.
// Runtime statement, all21 logical Miller payloads and the complete q132 quotient
// remain committed before their original SHA-256-derived challenges.
// Regular19 and Terminal20 share one physical input; Terminal reuses the535-byte
// arithmetic library already installed by Regular. Its private/helper/main keys
// move13->113,15->115,16->116 with inverse-checked code transformations.
// B receives the exact G2 subgroup check. A/C are on-curve and pairing-equivalent;
// unique G1 encodings and the separate harness input-validation grade are not claimed.
// FS-PIT soundness bound in the SHA-256 ROM: (23*q_beta + 160*q_alpha)/2^256 +
// 3*N(N-1)/2^257, q = adversary plus verifier SHA-256 queries, q_beta/q_alpha the
// challenge queries among them, N = q plus fewer than 2^22 + 2^7 setup hashes
// (groth16_cashscript chunked/bls12-381/README.md, section 5).
// Qualified source: groth16_cashscript 1003775dc379e0232ca7302d3f0964066b88e8ce.
// Owner SHA256: 3fac418a06ffc8a009d01ba400a76e0593d2d3b15fe4b2f185248cc62ccf88d6.
// Compiler: zk-language efc6ab80d9cbbea06c3c364b8fd5e915b9da84b4.
// Compact minus-one flags and coordinator scheduling remain; add RPA_SCHEDULE_PIC_AUTH=1.
// Set RPA_PIC_BLOCK2_DENSITY_PADDING=0; the former145-byte prefix is unnecessary.
// RPA_FUSE_FINAL_PAIR=1; final stages share installed535-byte arithmetic.
// The same PIC helper source/arguments and public commitments are retained. The
// new compiler size scheduler emits no function definitions or invocations.
// All archived proof/root/quotient/state/challenge values and invalid controls
// remain fixed. Adapter executable code and registry/scorer behavior unchanged.
// Primary:64403 script B +923 overhead B =65326 challenge B.
// Prior same-count point:65603 B ->65326 B; -277 B.
// Native primary:37904829 consensus /38085821 standard;
// maximum:48926249 /49285801; minimum margins:4054 /1878.
// Maximum fixture:85486 challenge B.
// All10 fresh source exports pass (340 producer controls). This
// profile passes20 positive and132 negative native transactions;
// 420 positive input costs reconcile. Full old/new comparison:320
// native contexts and1,720 cost identities. Source defaults remain unchanged.
// Libauth and native prices are separate. Finite supplied-corpus evidence only;
// no universal resource bound or live relay/admission claim.
// Vector SHA256: 6318ec085b58412c4d5751c9240a23eaa2961733af0ee945e346a2dd4d30ca23.
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
  'src/bch/groth16-bls12381-intratx-fs-fused-final-vectors.json',
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

export const bchGroth16Bls12381IntratxFsFusedFinal: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs-fused-final',
  // where the claimed public inputs live (public-input binding gate, harness/gates.ts): every copy
  // of n0, n1 in the valid run (32-byte fields packed in larger pushes), located by the maintainers
  publicInputs: [
    { input: 0, push: 1, offset: 193, encoding: 'le32', name: 'n0' },
    { input: 0, push: 1, offset: 225, encoding: 'le32', name: 'n1' },
  ],
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT fused final pair (21 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  proofInputs: bls12381IntratxFsProofInputs,
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 20 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'Regular19 and Terminal20 share one physical input and installed arithmetic; the original21 logical stages and transcript leaves remain. The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
    'an exact G2 subgroup check. A/C are on-curve and equation-binding, while unique G1 ' +
    'subgroup encodings and the separate harness input-validation grade are not claimed. ' +
    'One locking set accepts all ten supplied equation-valid fixtures. The candidate has ' +
    'finite supplied-source and current-native coverage only; complete-graph operation-cost ' +
    'and resource certification remains pending.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: vectors.extraValidProofs.map(toRun),
    worstCaseProof: toRun(vectors.worstCaseProof),
    invalid: vectors.invalid.map(toRun),
  }),
};
