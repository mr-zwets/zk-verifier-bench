// BCH-native BLS12-381 Groth16 verifier in one current-BCH consensus-valid transaction:
//
//   shared-table GLV vk_x MSM                                5 inputs
//   c^-|x|-fused Miller + quotient-torus residue verdict    21 inputs
//                                                            ---------
//                                                            26 inputs
//
// The bytecode enforces the complete four-pair equation
// e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) = 1 for runtime A/B/C and
// two runtime public inputs. The precomputed e(alpha,beta) Miller value and the prepared
// fixed-G2 gamma/delta lines are ordinary verification-key preparation: all four terms remain,
// and no published setup-scalar relation is used to collapse the equation. Canonical A/C field
// encodings are checked on-curve; B is non-identity, canonical, on-curve, and checked in the exact
// G2 subgroup. A/C cofactor components pair trivially with order-r G2 partners, so this entry does
// not claim unique G1-subgroup encodings.
//
// Each input carries its incoming state as raw 48-byte limbs and uses OP_INPUTBYTECODE to require
// the next input's witness to begin with its recomputed output. Miller genesis binds vk_x and the
// proof coordinates. The Miller accumulator lives in Q=Fp12*/Fp6*. A canonical six-limb u
// represents [c]=[1+u*W], with [c^-1]=[1-u*W]. Q has order p^6+1 and, for
// lambda=p+|x|, gcd(lambda,p^6+1)=r, so the lambda-power image is exactly the final-exponent
// kernel in Q. The terminal input checks [fF]=[frob(c,1)] by projective cross-product and rejects
// [0:0]. Since the final-exponent result is r-torsion and gcd(r,p^6-1)=1, quotient acceptance is
// equivalent to the full pairing verdict, not equality modulo an unverified Fp6 factor.
//
// Exact whole-transaction measurements (score = locking + unlocking + serialized overhead):
//   committed: 26 inputs, 192,643 script B, 193,781 score B, 192,871-B serialized spend,
//              151,669,685 op, max input 7,296,644 op
//   alternate: 26 inputs, 193,729 script B, 194,867 score B, 193,957-B serialized spend,
//              152,557,679 op, max input 7,296,796 op
//   dense:     26 inputs, 229,626 script B, 230,764 score B, 229,854-B serialized spend,
//              183,586,905 op, max input 7,518,110 op
// All three are exactly funded at 1 sat/byte, pass the BCH 2026 consensus VM and standard
// per-input script policy, and are non-standard solely because each complete transaction exceeds
// the 100,000-byte standard transaction limit. This entry is therefore current-consensus-valid
// but not standard-relayable. The committed vector passes 11/11 rejection runs, 3/3 isolated
// point/range rejection runs, and all 25 adjacent-seam splice checks. The dense valid fixture
// exercises all 128 GLV Straus add positions; it is deterministic stress coverage, not a formal
// global arithmetic maximum.
//
// Against the previously published 34-input artifact, this replan reduces score by 3,114 B,
// serialized size by 2,834 B, script bytes by 2,770 B, total op-cost by 1,422,029, and inputs by 8.
// It only changes the linked one-transaction Miller boundaries; the grouped standard-relayable
// schedule and the default Fp6-tail schedule are unchanged.
//
// Byte-exact provenance:
//   source: groth16_cashscript commit 106bbb1bb09c32fdf3fc02c1aeb5f9af4721fd69
//   compiler: CashScript commit 1c707c1dbf87396b30ba5e0704b1db44475ce893
//   vector sha256: 8b27aec8874f0072fd52c609f25c77244432b74085b949d834925860c7c9e858
//   locking graph sha256: 077007aa120e08f4d1e82d95341f958e4e3a5bb344b57f1f503add113fe5be68
// Reproduce from the source checkout (the command plans the linked schedule, proves the quotient
// algebra and exact four-pair traces, and runs valid, rejection, consensus, standard-script,
// exact-fee, and transaction-size checks before writing the deterministic vector):
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
//
// sha256 of locking bytecode, in input order:
//   00 912d0d4eaee34333fa110ed93d20b02677b8f563bc8fd8a4385af6d128d77eae
//   01 8da3e636d1acab79b45230b1c3082f23be59955359f9fd83d9ccb888cb4259a8
//   02 f234cd8ffc4ef761048fe44f23ad55d4bd2b75a8bd43c9ab8e247e58e4a46c94
//   03 36a320510439156fe6c305479281772b25a600bc1ec423c827cdefa83ef07d9a
//   04 21511932e8b1f35dc011a003da5447cd38b2582dad51ea490359fc3722643d3c
//   05 e718495bad4e05fab5d1d7068f3aa80a66b7d089205a1c3110c9dec56536d6f4
//   06 21f88251aec244702ad67b5e19aac03c3ac2f7c6b80bed4ff2426f23f098dda7
//   07 eb6b2ec1ba07839b9d3e9d2fdfd178b316498870ba7f37ce5546fe0ec309441e
//   08 411ff783009d6788ec295ac756ed2a80f63cf18424d60a51080cf55ac16df816
//   09 449cd38a284ad197e94720090d092c3677b5daef6e2e517e5584f7d7d215e1d3
//   10 12b2654165143157af811b3ed45e0dbe0f3b0e4aef58f2b6fb8881a9eb664c49
//   11 613b3bc5b420ca90d8f27e7b04c7345857a2ec0a6c2db619dc08a60991946d6a
//   12 b5bdecb8ec3ae45406ed464559001c3f451b5266c0835a55f8b94bbeeacbf2bc
//   13 e67318e81ab944b5583d72094be82a7f2bf4dacc955344a9496e933681377b82
//   14 3d129d38d0e36c9c79a17349850154f9e0c7a297b9d2bf1c9ef137a679782033
//   15 236427b36b1e60cb28793404fe925bb097225637017f4d8a22360c3dfd28feef
//   16 3d8aa51fa96a00ba24f9d2bbb18bdf406d4859464dfa7e527b9bcb246f4aadb4
//   17 6aa05c7c719cb00e78c1d2824556c4f32ae60b26e50c14b6f9b2a0983580d9c8
//   18 32fdb0badfd4e4b7645f169b9ffef021ce26b8d8c8f8ac0cc79cc648419d9222
//   19 b73051a180c38395ab464b055a621bcb4f3fb38446562210243dd215930ccfe8
//   20 a5561e424bef704dea51ff4f1ebcb50ffaeccfff8c2c15ab17f8e960d9409599
//   21 958ae306881a01b402d3523acd85cab3c98fa40959468667f91ce600d1141eed
//   22 54f33e4e6b254565ccd0d53f41f15a9fec747103a57fde759c6776af1e240909
//   23 39861fa479d5db09084a04ec48167659823d22af4ef4b170a8181e8c6450720d
//   24 3ab1e08e9dd43b9e275f71e8c0231c0244cdd08beb09d5077d7dc76e2fe82c7b
//   25 e9dd0d0a60f9fa74b987920921649d4b45817ddf2660df2422af97c774979923
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
  name: 'BCH BLS12-381 Groth16 intra-tx quotient-torus residue (26-input consensus-valid verifier)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the complete four-pair BLS12-381 equation linked across 26 inputs of ' +
    'one transaction. Five shared-table GLV vk_x inputs feed 21 c^-|x|-fused prepared-Miller ' +
    'inputs. Runtime A/C are canonically encoded and on-curve; runtime B is also checked in the ' +
    'exact G2 subgroup. The fixed e(alpha,beta) value and fixed-G2 gamma/delta lines use ordinary ' +
    'verification-key preparation; no setup-scalar relation collapses the equation. A canonical ' +
    'six-limb u represents [c]=[1+u*W] in ' +
    'Fp12*/Fp6*, where gcd(p+|x|,p^6+1)=r makes the lambda-power image exactly the pairing ' +
    'kernel. Constant root folds use two Fp6 products, and the final Miller input checks ' +
    '[fF]=[frob(c,1)] with a nonzero projective representative, eliminating the separate tail. ' +
    'OP_INPUTBYTECODE directly binds every state, the root, and both stage seams. One fixed ' +
    'P2SH32 script set verifies any proof for the VK at runtime. Every input fits current BCH ' +
    'script and op-cost limits; the exactly funded 192,871-byte transaction is consensus-valid ' +
    'and passes standard per-input script policy, but it is not standard-relayable because the ' +
    'complete transaction exceeds 100,000 bytes. The dense valid fixture exercises all 128 GLV ' +
    'Straus add positions.',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
    invalidInputs: (v.invalidInputs ?? []).map(toRun),
  }),
};
