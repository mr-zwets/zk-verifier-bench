// BCH-native BLS12-381 Groth16 verifier in one current-BCH-valid transaction:
//
//   shared-table GLV vk_x MSM                                5 inputs
//   c^-|x|-fused Miller + quotient-torus residue verdict    29 inputs
//                                                            ---------
//                                                            34 inputs
//
// Each input carries its incoming state as raw 48-byte limbs and uses OP_INPUTBYTECODE to require
// the next input's witness to begin with its recomputed output. Miller genesis binds vk_x and the
// canonical proof coordinates; the first and last Miller inputs fuse the curve and guarded G2
// subgroup checks, and the fixed e(alpha,beta) Miller value is precomputed.
//
// The Miller accumulator lives in Q=Fp12*/Fp6*. A six-limb canonical u represents the finite
// class [c]=[1+u*W], with [c^-1]=[1-u*W]. Q is cyclic of order p^6+1 and, for
// lambda=p+|x|, gcd(lambda,p^6+1)=r. The lambda-power image is therefore exactly the kernel of
// the final-exponent map on Q. The legacy correction w lies in Fp6 and disappears in the quotient.
// The final Miller input checks [fF]=[frob(c,1)] by projective cross-product and explicitly rejects
// [0:0], removing the separate residue-tail input. A fixed r-torsion shift makes a finite root
// available for every accepting class without changing its lambda power. Since the final-exponent
// result is r-torsion and gcd(r,p^6-1)=1, quotient acceptance is equivalent to the full pairing
// verdict, not merely equality up to a nontrivial Fp6 element.
//
// Exact whole-transaction measurements (locking + unlocking is the leaderboard script-byte field):
//   committed: 34 inputs, 195,413 script B, 196,895 score B, 195,705-B serialized spend,
//              153,091,714 op, max input 5,445,782 op; consensus-valid, non-standard by tx size
//   alternate: 34 inputs, 196,507 script B, 197,989 score B, 196,799-B serialized spend,
//              153,981,740 op, max input 5,446,214 op; consensus-valid, non-standard by tx size
//   dense:     34 inputs, 232,438 script B, 233,920 score B, 232,730-B serialized spend,
//              185,038,859 op, max input 7,527,078 op; consensus-valid, non-standard by tx size
// All three pass the BCH 2026 consensus VM. The committed vector also passes 11/11 invalid runs,
// 3/3 isolated invalid-point runs, and all 33 adjacent-seam splice checks. The dense fixture is a
// deterministic valid proof whose four GLV sub-scalars add at all 128 Straus positions; it is
// empirical stress coverage, not a formal global arithmetic maximum.
//
// Byte-exact provenance:
//   source: groth16_cashscript commit 2831928fe224d252fc90dfc26ecfdf52f29e9399
//   compiler: CashScript commit 1c707c1dbf87396b30ba5e0704b1db44475ce893
//   vector sha256: 66f65ef80de990688b0647d77caf86d8e48ce84dae8dfb6ea014ea49aff611dc
// Reproduce from the source checkout (the command pins current-BCH sizing and runs the algebra,
// complete traces, valid proofs, invalid mutations, and both consensus/standard-policy VMs):
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
//
// sha256 of locking bytecode, in input order:
//   00 96db84d0348659c4dea8ed67b9d473c26c094498bd0daeb2faadedea74bae053
//   01 6d7a7d0841796b480f4369f275d59a9a92309b310ef50c24bffd08c61e2ee4d9
//   02 55ee6ba9a9df78fc4b2dba081ad4e9899306321229c322a73598e0fd08a0c3f4
//   03 fa1d48b9e13d4a93c572549ec4b2403ce07f1c2f57c8a7c34e686854b67c70b1
//   04 1990490155fbe9c0ba6ea2bdfd26fbbaa8c9c968615ba9584861d0b4ae108928
//   05 6f7cb06169210e468d034a8efc65b9c12893fed21165e11e278a11854440e049
//   06 8e722926b6a762ac8af4d4c52f489a23094eb31ce7374053785bf62a00cd5bc3
//   07 41d877bedcd9ca486cff76d28620766f32e38f087c8ea0e08c76e04c4b0ffa78
//   08 57277b3e69f2517e57cc5fbfd9da0856b9405537af3f9724435c835024234d12
//   09 581231861b00f0fefaa76e262ab4bfa700a6d285d7e0408edaa6c6a30c73882b
//   10 8949a56d2ee52d22319f0ee562d846c92acb2880ad5b92f3bdef944c377219bd
//   11 bf96954620f804a8ca3b962efc6c7a77b9aece0e0aebff368d064b48959a1f3b
//   12 dec2c13ce89c3aa84af90e601042d0667b7396da1ec817f0ce637ea43447eabe
//   13 2f0d018b4f4091e5fd1ff7829d971aa059d21269a77bd0698b04e87e7d298edb
//   14 7df37bea01832d1801a3f6b77f7a0dc0b8c34836f5c83feed4a1727aebb9959e
//   15 ee1013ed93223ca477f9ce201f3b2d251ed11ae72a8c2079982b64c94da78956
//   16 8c449e3e73422222ff92f1a8b9bbf26d6ac993d6918f23a22bc9f609019fe7ae
//   17 ca6e468b5f2fb695a9bd0ed001744208d9799a75d743d233b38fe3589a60586a
//   18 206907bf8e7bdcebf979d1ab53b57573e107ef301e8c315b1ef4a4c110a3a49a
//   19 140c15a09e90891c77a594c5f52b0cb91c08acc0c47dae77828e1c475404e7c4
//   20 4ac13121c6cdfd00934a20ab6b55b400208b660511697f6efe35e1d818e4e796
//   21 5fac8bd96a8653c63108c3e88c22b453605b53c886074f58e131924abb45d5a6
//   22 cbde4541bcc29a63de7934d9ff51e1bf16ae4d9515af9833ae41ea359c81d60d
//   23 0efed55d0d4086434d88eb78fb9faded88272794bb1d61fc316be3f8dc00b566
//   24 120f957cd94ef7aa727538ea838570494bac55bd6d0851aaff4e507c857094d5
//   25 13c2ab764c507c613ea142d459dd1999739f2e4efa3ad47b2a711f2466ab04e9
//   26 e5d7f0f08c9dec2b603379809db3163fe7052515838601f0bcc50e731b75bf63
//   27 102f1ede895ed77ebce2972b65fd231d218b76b2f29ae91b7fdcf437a48b054e
//   28 b520898b02430fe7d3989dc0cd3bdf24458510dcd5827611c1190df06b342906
//   29 609c8d0f45472415543c38a2cc1798bbfd7fe22ae0861039e872fb86da1da0b3
//   30 154ec1a90c1e6fbf16cef7e7e6fbc5f4168011f1cee84bb0b9909f95c1a9137e
//   31 fe852321114d44263c7f65f042c590705c3cf4eb6b689d83461e03ebe324c2e0
//   32 9a64955755653b6de1d4facb7c7d0726b95a5594603023726fa630b778cec89a
//   33 874bd21498da23d4b70471c124f8fa33a2d07fd9a09432a6cd0359dee8f80dd4
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-intratx-residue-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array, so each
// step is evaluated against the same multi-input transaction (its tx.inputs[idx±1] introspection
// resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({ label: s.label, lockingBytecode: inputs[i]!.lockingBytecode, unlockingBytecode: inputs[i]!.unlockingBytecode, checkpoint: s.checkpoint, intraTx: { index: i, inputs } }));
};

export const bchGroth16Bls12381IntratxResidue: Implementation = {
  id: 'bch-groth16-bls12381-intratx-residue',
  name: 'BCH BLS12-381 Groth16 intra-tx quotient-torus residue (34-input BCH-valid verifier)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: one runtime-proof BLS12-381 verifier linked across 34 inputs of one ' +
    'transaction. Five shared-table GLV vk_x inputs feed 29 c^-|x|-fused prepared-Miller inputs; ' +
    'the first and last Miller inputs fuse canonical point, curve, and G2 subgroup validation, ' +
    'and e(alpha,beta) is precomputed. A canonical six-limb u represents [c]=[1+u*W] in ' +
    'Fp12*/Fp6*, where gcd(p+|x|,p^6+1)=r makes the lambda-power image exactly the pairing ' +
    'kernel. Constant root folds use two Fp6 products, and the final Miller input checks ' +
    '[fF]=[frob(c,1)] with a nonzero projective representative, eliminating the separate tail. ' +
    'OP_INPUTBYTECODE directly binds every state, the root, and both stage seams. One fixed ' +
    'P2SH32 script set verifies any proof for the VK at runtime. Every input fits current BCH ' +
    'script and op-cost limits; the 195,705-byte transaction is consensus-valid but non-standard ' +
    'only by total size. The dense valid fixture exercises all 128 GLV Straus add positions.',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
    invalidInputs: (v.invalidInputs ?? []).map(toRun),
  }),
};
