// BCH-native BLS12-381 Groth16 verifier — INTRA-TRANSACTION LINKED + RESIDUE, with the whole
// computation in one current-BCH-valid transaction. Each chunk is an input whose witness carries
// its incoming state as raw 48-byte limbs and directly requires the next input's witness — read
// with OP_INPUTBYTECODE — to equal its recomputed output. The fixed graph is:
//
//   GLV vk_x MSM (4-scalar ~128-bit Straus, baked table)             5 chunks
//   c^-|x|-FUSED batched Miller, e(alpha,beta) baked (cmul1); the G2  29 chunks
//     on-curve + subgroup check is FUSED in (first/last chunks reuse R_B=[|x|]B)
//   witnessed-residue final-exp tail: Fp6 witness + terminal relation 1 chunk
//                                                                    ---------
//                                                                    35 inputs
//
// For the raw Miller boundary g, lambda=p+|x| is a multiple of r. The witness satisfies
// c^lambda=g*w, expressed after the fused loop as fF*w=frob(c,1), where fF=g*c^-|x|. Only the
// six limbs of w in the embedded Fp6 are supplied; the upper Fp12 half is fixed to zero. This is
// sufficient because every nonzero Fp6 element has order dividing p^6-1, and p^6-1 divides the
// final-exponent cofactor h=(p^12-1)/r. Therefore raising c^lambda=g*w to h forces g^h=1.
// c*cInv=1 excludes the zero root and the terminal equality then excludes w=0. The residue root
// and proof context are carried through all 29 Miller inputs; vk_x is bound into Miller genesis,
// the final Miller boundary is bound into the tail, and every adjacent seam is linked directly.
//
// Exact harness measurements (locking + unlocking bytes are the leaderboard's script-byte field):
//   committed: 35 inputs, 209,216 script B, 210,741 score B, 209,516-B serialized spend,
//              157,700,169 op, max input 5,837,159 op; consensus-valid, non-standard by tx size
//   alternate: 35 inputs, 210,304 script B, 211,829 score B, 210,604-B serialized spend,
//              158,591,019 op, max input 5,837,776 op; consensus-valid, non-standard by tx size
//   dense:     35 inputs, 246,239 script B, 247,764 score B, 246,539-B serialized spend,
//              189,647,239 op, max input 7,527,090 op; consensus-valid, non-standard by tx size
// All three runs pass the real BCH 2026 consensus VM. The committed vector also passes 12/12
// invalid runs, 3/3 isolated invalid-point runs, and all 34 cross-stage splice checks. The dense
// fixture is a deterministic valid proof whose four GLV sub-scalars add at all 128 Straus
// positions; it is empirical stress coverage, not a formal global arithmetic maximum.
//
// Byte-exact provenance:
//   source: groth16_cashscript commit 4d114ce713c7cd018920a2126fe47d7aaa3d4401
//   compiler: CashScript commit 1c707c1dbf87396b30ba5e0704b1db44475ce893
//   vector sha256: beec33a546a9fa40dbc3557f291314bc92c826f21a07f148f1accbc2673a924b
// From the source checkout, with no RESCHEDULE/BCH_VM/TARGET_UNLOCK/INTRATX_BARE overrides:
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/bls12-381/gen_vkx_glv.mjs
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/bls12-381/gen_miller_residue.mjs linked
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/bls12-381/gen_finalexp_residue.mjs linked
//   VERIFIER_DIR=/path/to/zk-verifier-bench node chunked/intratx/build_vectors_residue_bls.mjs
//
// sha256 of locking bytecode, in input order:
//   00 96db84d0348659c4dea8ed67b9d473c26c094498bd0daeb2faadedea74bae053
//   01 6d7a7d0841796b480f4369f275d59a9a92309b310ef50c24bffd08c61e2ee4d9
//   02 55ee6ba9a9df78fc4b2dba081ad4e9899306321229c322a73598e0fd08a0c3f4
//   03 fa1d48b9e13d4a93c572549ec4b2403ce07f1c2f57c8a7c34e686854b67c70b1
//   04 dadf8ef9a97c732572af3239dfdbc9495a8b43a4cd8bddfae438612b3313be10
//   05 a789cdfe63a3f277c7a9bf06ac7644197b60d4af9aef998ccaf06df8ef2e9ea3
//   06 03af9375e9ce8f200b9dd6520aeb97a411e996d606bc0575f96751bffe6199c3
//   07 8b81818fe3cb77370bddeae5466584f831b52b93b12af2fac19ff9ba6c9fb8de
//   08 aa759fd996d1c91cda9550aa09aa6507d1ff0281277edf1aacc3f65a141b0aa7
//   09 71c445ab91a5d6448f0242524f687cd8903355acd9a42790a188eeb8f75ff594
//   10 44b8c8434819a1094c9f035b616032fc0e1ada1e94b16c3e578bd369dadc2455
//   11 57a632c08a27773cc2e88135b933dd672db2356ddff746677b7a34dd93eeaa3c
//   12 fba542a45a7b2fd1b28b860df0e25aadd4669f82bc18afaecbc905609fb4d7e4
//   13 a2310454f47ea4cf0b413e7715b040dfd14b752f422c69f3829a5df26e6bd60e
//   14 962074e636272f93dbc1c71515ca4b25b6267dffbddef51118ab685ed876df62
//   15 f26cd07fa46d0d098f3fa31cd1a3b848ebedb3c4543a7155897e0203e69d0303
//   16 b2500fdf20c8eac045d2d35419da3c0d5e61f0aad52fe8279b85efedfdc898aa
//   17 44506c7b556416f1a8a7751dec04fb8b2e1627a5d0429ae1c15b3d1025707acf
//   18 83a867581b8e02960ac507afe0ec8d273fc3d68c8a37768710e90c3edd31da49
//   19 df4a133ea6d3a6829c6d3990e7bf9131d887720654b59a7ad7c9f7c294f1fbf8
//   20 893d144ecd2610ce39064b8721e9779db77dc1014fd5314a3c384a58ed1fbd73
//   21 e88593a8c9df7a0cc2582992fd39f56a2020fab53970f5ee37df100b8a633490
//   22 5a95abb36c2c3710e127216a28e979f5a0cc950103bd3c041ad9e617b42f7a82
//   23 d89ee2ea741dcfe44f96491a3d656548feff1f6f6193270bc51551842f5b2e8e
//   24 844a16194f7abfbcc896f60a7d4468e28d243e6288bda25ae1a8bef2d0649fe4
//   25 c6e086b38d235385ae27591b79e9df9ee6c6f684424e339973617052772256e6
//   26 f674691a678276c65384fa0d4752bd12a20bb1450d7263c43b1d0ebc792378a3
//   27 72822188f6ce412b78253a853059f793632940a08b7078c52f565160b0181fd8
//   28 7f7be5d4c21e3dd9262b0bcdecdc1844a2b5423fe907eedd64851e5f2b836b50
//   29 c80da50838cee80552ffbdfa11ef1f82f851465fa9940ccadec4a5e97b5aa577
//   30 227a00bf4121897656ecd899766af2b87efb0414a0b20e63b45095678713dd7f
//   31 e022a4572fef28c673c2aea853aa00e2bd2c8cf92541d552e8a60e76cb4e4edc
//   32 4455f7ef3757cc60fd8fa8bf690fe905e609d043a4affa65720599a22f351eaf
//   33 c177f1a8ef7ae1fc9eee8a4da25fc40b5cd1a286615a1d5f080f90e59fe91aa3
//   34 5da34e0a031ac04be2d59c972918e4e0d68eb45f84dddff3df1d5218cafc690e
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
  name: 'BCH BLS12-381 Groth16 intra-tx linked + Fp6 residue (35-input BCH-compatible verifier)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the full BLS12-381 Groth16 verifier runs as 35 linked inputs of one ' +
    'transaction: five shared-table GLV vk_x inputs, 29 c^-|x|-fused prepared-Miller inputs, and ' +
    'one terminal residue input. The first and last Miller inputs fuse canonical point, curve, ' +
    'and G2 subgroup validation; e(alpha,beta) is precomputed. The terminal checks c*cInv=1 and ' +
    'fF*w=frob(c,1), with w supplied as six Fp6 limbs and its upper Fp12 half fixed to zero. ' +
    'This is sound because p^6-1 divides the final-exponent cofactor: c^lambda=g*w therefore ' +
    'forces g^h=1. OP_INPUTBYTECODE directly binds every adjacent state, vk_x to Miller genesis, ' +
    'and the Miller boundary to the residue verdict. One fixed P2SH32 script set verifies any ' +
    'proof for the VK at runtime. Every input fits current BCH script and op-cost limits; the ' +
    'whole transaction is consensus-valid but non-standard only because its serialized size is ' +
    '209,516 B. The dense valid fixture exercises all 128 GLV Straus add positions.',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
    invalidInputs: (v.invalidInputs ?? []).map(toRun),
  }),
};
