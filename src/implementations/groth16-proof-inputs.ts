import type { ProofInput } from '../harness/types.js';

// Reviewed locations of the Groth16 proof components A, B, C (and nothing else: no public inputs,
// pads, carried state, roots, quotients, slopes or checkpoint values). Each layout below cites the
// groth16_cashscript generator that emits it; reviewers can re-derive every index by
// decoding the shipped vector pushes. Source paths are relative to groth16_cashscript (be3dc66).

/** `count` consecutive VM-number pushes of one input. */
const numericPushes = (input: number, first: number, count: number): ProofInput[] =>
  Array.from({ length: count }, (_, index) => ({ input, push: first + index }));

/** Fixed-width fields packed in one push, `length` bytes each, starting at `first`. */
const packedFields = (input: number, push: number, first: number, length: number, count: number): ProofInput[] =>
  Array.from({ length: count }, (_, index) => ({ input, push, encoding: 'bytes' as const, offset: first + index * length, length }));

// Affine singleton ABI: reversed (Ax, Ay, Bx0, Bx1, By0, By1, Cx, Cy, in0, in1).
// gen-multiproof{,-bls12381}.mjs proofArgs/unlockingFor own this layout.
// Pushes 0/1 are public scalars; pushes 2..9 are proof coordinates.
export const affineSingletonProofInputs: ProofInput[] = numericPushes(0, 2, 8);

// Genpow singletons keep the same ten-push interface with A and C compressed to (x, parity/sign):
// pushes 0/1 are in1/in0; 2 = C sign, 3 = Cx, 4..7 = B (two sign flags + Bx1, Bx0 for BLS12-381;
// By1, By0, Bx1, Bx0 for BN254), 8 = A sign, 9 = Ax.
//   BN254: singleton/bn254/genpow-reconstructed/build.mjs:148-165 (compressG1Witness replaces the y
//   pushes 2/8 by y&1 and keeps every other push byte-for-byte).
//   BLS12-381: singleton/bls12-381/leader-recovered/README.md ("original ten-push proof/public-input
//   interface") and complete-points.mjs:4 (G2 decoder consumes [ySign, normSign, xImaginary, xReal]).
export const genpowSingletonProofInputs: ProofInput[] = numericPushes(0, 2, 8);

// BN254 min-op singleton: spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1, u[6], iAy,iVy,iCy, slopes[176],
// k10,k20,k11,k21, nb, glvSlopes), 201 args pushed in reverse (singleton/bn254/
// build_vectors_groth16_minop.mjs:51-52, 81-90). Arg i sits at push 200 - i, so Cy..Ax = pushes 193..200.
// The inverses iAy/iCy (pushes 184/182) are derived witnesses and are excluded.
export const bn254MinopProofInputs: ProofInput[] = numericPushes(0, 193, 8);

// BLS12-381 min-op singleton: spend(Ax,Ay,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1, u[6], k10,k20,k11,k21,vkxZinv),
// 21 args pushed in reverse (singleton/bls12-381/build_vectors_groth16_minop.mjs:44, 55-68;
// gen_multiproof_minop.mjs:59-69). Arg i sits at push 20 - i, so Cy..Ax = pushes 13..20.
export const bls12381MinopProofInputs: ProofInput[] = numericPushes(0, 13, 8);

// BLS12-381 Fiat-Shamir singletons (fs, fs-spec, fs-spec-shared, fs-spec-zero): the 737-byte statement
// push 22 (chunked/bls12-381/measure_fs_singleton.mjs:848-874, SKIP_GAMMA layout, 48-byte LE limbs):
//   [0,1) Bidentity, [1,193) effective B (Bxa, Bxb, Bya, Byb), [193,257) public inputs,
//   [257,545) residue root, [545,641) unit(-A) = (p0u, p0v), [641,737) unit(C) = (p3u, p3v).
// unitG1 (chunked/bls12-381/_pairingmath.mjs:70-75) maps (x, y) to (-x/(2y), -1/(2y)) and the identity
// to (0, 0); it is a bijection, so these are A and C in a normalized chart. The B-identity flag is
// part of B's encoding (an identity B ships the fixed substitute coordinates).
export const bls12381FsSingletonProofInputs: ProofInput[] = [
  { input: 0, push: 22, encoding: 'bytes', offset: 0, length: 1 },
  ...packedFields(0, 22, 1, 48, 4),
  ...packedFields(0, 22, 545, 48, 4),
];

// BN254 SI-GLS single input: unlocking [WQ, WS, redeem]; WS opens with the statement
// (Ax, Ay, Bxa, Bxb, Bya, Byb, Cx, Cy, n0, n1) as 32-byte LE words
// (chunked/bn254/sound-si-gls/transaction.mjs:7, protocol.mjs:142-144).
export const bn254SiGlsProofInputs: ProofInput[] = packedFields(0, 1, 0, 32, 8);

// BLS12-381 SI-GLS single input: same [WQ, WS, redeem] order; WS opens with the 8 proof coordinates as
// 48-byte LE words, then n0/n1 at 384/416 (chunked/bls12-381/sound-si-gls/transaction.mjs:7,
// protocol.mjs:32, 159-161).
export const bls12381SiGlsProofInputs: ProofInput[] = packedFields(0, 1, 0, 48, 8);

// BN254 sound native (3 inputs): input 2 pushes [D, STMT, S2, H2, DS2, F2, WQ, R]; STMT opens with
// the 8 proof coordinates as 32-byte LE words (chunked/bn254/bn-native-sound/transaction.mjs:26,
// protocol.mjs:150-151).
export const bn254SoundNativeProofInputs: ProofInput[] = packedFields(2, 1, 0, 32, 8);

// BLS12-381 sound native (4 inputs): input 0 pushes [ZR, G, CL, ...]; region G opens with the
// statement block, whose first 384 bytes are the 8 proof coordinates as 48-byte LE words
// (chunked/bls12-381/bls-native-sound/protocol.mjs:85-88, 210-216).
export const bls12381SoundNativeProofInputs: ProofInput[] = packedFields(0, 1, 0, 48, 8);

// BN254 intra-tx quotient-torus residue (regular and large): the Miller-genesis input's first push is
// its 25-limb inBlob (32-byte LE limbs) named by MILLER_GENESIS_NAMES (chunked/intratx/
// build_vectors_residue.mjs:245-272, build_vectors_residue_large.mjs:208-214):
//   Pu0, Pv0 (limbs 0-1)  = unit(-A), Q0xa..Q0yb (2-5) = stage B (G2.BASE when B is the identity),
//   Pu3, Pv3 (6-7) = unit(C), VkxX/Y/Z (8-10), effectivePu0/Pv0 (11-12), rawBxa..rawByb (13-16) = the
//   proof's own B, u0..u5 (17-22), Pu2/Pv2 (23-24).
// ptLimbs (chunked/pairing/_millermath.mjs:307-317) maps (x, y) to (-x/y, -1/y) and the identity to
// (0, 0). The locator takes A = (Pu0, Pv0), B = raw B, C = (Pu3, Pv3); the stage/effective copies are
// derived from these and excluded. Genesis is input 2 (two GLV inputs) here and input 1 in -large.
const intratxResidueGenesis = (input: number): ProofInput[] => [
  ...packedFields(input, 0, 0, 32, 2),
  ...packedFields(input, 0, 13 * 32, 32, 4),
  ...packedFields(input, 0, 6 * 32, 32, 2),
];
export const bn254IntratxResidueProofInputs: ProofInput[] = intratxResidueGenesis(2);
export const bn254IntratxResidueLargeProofInputs: ProofInput[] = intratxResidueGenesis(1);

// BN254 covenant residue: the GLV minting-baton genesis (step 0) takes the raw proof tuple
// PROOF_LIMBS = (-A.x, -A.y, Bxa, Bxb, Bya, Byb, Cx, Cy) as its first args, pushed in reverse before the
// redeem (chunked/pairing/gen_vkx_glv.mjs:176-180, 462-466): pushes 7..14 = Cy, Cx, Byb, Bya, Bxb,
// Bxa, -A.y, -A.x. Later steps only re-bind committed copies.
export const bn254CovenantResidueProofInputs: ProofInput[] = numericPushes(0, 7, 8);

// BLS12-381 covenant residue: the final GLV step (step 4) takes the proof tuple as witnesses:
// allArgs = [...commitLimbs, zInv, -A.x, -A.y, Bxa, Bxb, Bya, Byb, Cx, Cy], pushed in reverse after a
// leading pad push (chunked/bls12-381/build_vectors_covenant_residue.mjs:170-177, 383-395, 418-426):
// pushes 1..8 =
// Cy, Cx, Byb, Bya, Bxb, Bxa, -A.y, -A.x. The genesis carries only public inputs.
export const bls12381CovenantResidueProofInputs: ProofInput[] = numericPushes(4, 1, 8);
