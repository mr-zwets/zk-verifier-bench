// Complete BLS12-381 Groth16 verification in one current-BCH standard transaction.
//
// Entry name: bch-groth16-bls12381-intratx-fs (intra-tx packing + Fiat-Shamir
// polynomial-identity checking). The Fp6/torus relations are checked at
// SHA-256-derived challenges rather than computed exactly, so this entry sits in
// the separate Fiat-Shamir PIT security-model category defined in
// groth16_cashscript/verifiers.md; the residue entries remain the unconditional
// frontier. "qsplit tail-22" is the internal build codename.
// Twenty-two P2SH32 inputs jointly enforce
//
//   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1,
//   vk_x = IC0 + input0*IC1 + input1*IC2.
//
// The runtime proof and public inputs are committed before the Fiat-Shamir
// challenges. Each Miller-block payload is committed before beta, and the 132
// quotient coefficients are committed as one logical leaf before alpha. The
// quotient is carried physically as a fixed 110-coefficient head followed by a
// fixed 22-coefficient tail; both consumers enforce the exact lengths, order,
// sibling programs, recurrence, and terminal residue relation.
//
// The fixed Miller data and authenticated public-input table are derived only
// from public verification-key points. The repository's published synthetic VK
// scalar relations are used only to mint equation-valid benchmark fixtures;
// locking-program compilation and table generation do not consume them. No
// proof value, setup secret, or private witness is specialized. All ten supplied
// fixtures use the same locking set. B is checked on-curve and in the exact
// order-r G2 subgroup by the psi relation with the mid-walk nonzero guard. A and
// C have canonical field encodings and are checked on-curve; cofactor-equivalent
// G1 points remain equivalent for the pairing verdict, so this entry does not
// claim a separate unique-G1-encoding grade. These vectors also do not supply
// isolated point-validation runs, so the entry does not claim the harness's
// separate input-validation grade.
//
// The 24 pre-beta relations have cancellation degree at most 23, and the alpha
// identity has degree at most 137. In the SHA-256 random-oracle model, the
// conservative union bound is 160/(2^256-1), less than 161/2^256.
//
// Largest supplied valid fixture:
//   22 inputs, 78,982 script B, 79,178 wire B, 79,948 challenge-score B
//   55,081,462 consensus opcost, 55,430,774 standard opcost
// Committed fixture:
//   53,133,274 consensus opcost, 53,482,586 standard opcost
// Every supplied valid fixture passes the current BCH consensus and standard
// VMs, remains below the 100,000-byte relay limit, and pays exactly 1 sat/byte.
// All density padding is zero. Six existing inputs authenticate ordered
// 6/4/5/6/6/5 public-input batches; only the coordinator is compiled for size.
//
// PIC factor/path extraction uses one tuple split. Both original resource
// classes pass with minimum universal margins 23,838 / 122,142.
//
// Source revision:
//   groth16_cashscript d15ed7038b541593b0e57e6d0236ab730da73208 (local candidate)
// Source artifact:
//   groth16_cashscript/chunked/bls12-381/measure_d3_two_chart_binary.mjs
//   sha256 83d2b28f27ead5a89e595a9a645492cb677f68f0f05c001f3a86d555d9860024
// Resource export sha256:
//   d8195cb000a8488770a0cc9e038656e7bd3bbb68602d429abd3f7a68caa88ade
// Benchmark vector sha256:
//   8de05bd09f1ffb648a508bc8bc8ec48e3b0cd0ca62b22708f9ced8a533fcdb40
// Length-prefixed locking-set sha256:
//   4d7e68150d02a5f170cb3845bd117fed6af903ad8cddce16a132a2d8d70e51b3
// Individual locking-bytecode sha256 values, input order:
//   00 ab58add070158c4af0c40a23543cd45ab2823d90b2bdab4567571c763316315c
//   01 c715b500676eb918ab411662d331d5451efd70beb9e8e51c594b669dd25c5940
//   02 9071aef853a3bb359ad9cf42304dbb29b3676f5efc8f603d4c75bbf6199d4a5d
//   03 6f4c7751aabad38a98ba7449fb29a4db0f5c0974308bb5f9e3c544b267a39eea
//   04 8a231574ed2adb8e097affd1e0d2bba0ed8c0e826edaf94b29fbe2505886fdf8
//   05 a9a597bc2dbabeb7b9ba8c02fa98d2765d1ed0924f196a9547ec9b8a6f1e4ff2
//   06 e4362256fce64abe6dca0b372012964a09b9f62440b3d46e74f7d0695a6a6f38
//   07 6de3cb1119b72100f0ffd779ce6d07f1025497ebc5e04cac3ea77c475cae90dd
//   08 f02af931d5af4b757b5b3f4712b25402ac76e8cf86f023a5b58341c5466870df
//   09 99b6fbd147a2a642ab0c2cc337a4d07cee342b27968bb9c1ed07c78882a65406
//   10 8a62da8899eae7a8836b74101b1c18353c6f6aec48637a31fb1669f0badab658
//   11 97139372935258e39201006dcacf7512d3f28b336be1ffd9eb5cfd57d81ab2c0
//   12 3b46ec9d81f585cbdcb73a143a889eef773f92a731dcd84418a70a1dfcf1aa3e
//   13 cda97fb735606de536ae5a70ddf9c723e64ab94b1c4637e08b3e86dd91415913
//   14 842a58ada0a5dee081ffd493bcf9b0292cfe2402dc9e5480fc29adb2e228aa4f
//   15 7c3b215e66363206a5a42cc9970ff5dad2a91c14a1a6e965252884f27a9f34dd
//   16 5c26aa398ac98f166aa01241509fa66dc2a8adcb2b35c33b239d6d185c520303
//   17 926a1190fd374eb5e8ecad3f5730adf4ffbe6b2f3949ddedca541c50cb0c825a
//   18 7096d2214b75b4361ecbb4e894e0f05813d6903b98ccb1a9810e43f1ffce9a8e
//   19 e2c40b6d99a73ac3c18048692af35956ad991f3715051eff65820aa9b1fa2ed0
//   20 04ad7fcc1cd1f055ec2937ed578cf2ec3de0a6916449c275777e7bfcee5fcae9
//   21 3a88cd65821c4121a34145a222a7805faf34f20dc25f4e2b37ce3a6abd434235
import { readFileSync } from 'node:fs';

import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

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
  'src/bch/groth16-bls12381-intratx-fs-vectors.json',
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

export const bchGroth16Bls12381IntratxFs: Implementation = {
  id: 'bch-groth16-bls12381-intratx-fs',
  name: 'BCH BLS12-381 Groth16 Fiat-Shamir PIT (22 inputs, one standard transaction)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Complete BLS12-381 Groth16 verification in one current-BCH standard transaction. ' +
    'The externally anchored coordinator commits to the 21 worker lockings, while worker ' +
    'inputs read the required siblings with OP_INPUTBYTECODE. The coordinator also pins the ' +
    'proof/public-input statement, every Miller-block payload, and one logical ' +
    '132-coefficient quotient leaf. The quotient is carried as an exact ' +
    '110-coefficient head plus 22-coefficient tail and evaluated in order. The public-input ' +
    'contribution is authenticated from a table derived only from public verification-key ' +
    'points; published synthetic VK scalar relations are limited to fixture generation. ' +
    'The terminal residue relation enforces the full four-pair Groth16 equation. B receives ' +
    'an exact G2 subgroup check. A/C are on-curve and equation-binding, while unique G1 ' +
    'subgroup encodings and the separate harness input-validation grade are not claimed. ' +
    'One locking set accepts all ten supplied equation-valid fixtures. The proof-independent ' +
    'resource certificate derives per-input ' +
    'ceilings from the exported bytecodes and covers both B branch classes.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: vectors.extraValidProofs.map(toRun),
    worstCaseProof: toRun(vectors.worstCaseProof),
    invalid: vectors.invalid.map(toRun),
  }),
};
