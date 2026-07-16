// BCH-native BLS12-381 Groth16 verifier in one current-BCH consensus-valid transaction:
//
//   shared-table GLV vk_x MSM                                5 inputs
//   c^-|x|-fused Miller + quotient-torus residue verdict    19 inputs
//                                                            ---------
//                                                            24 inputs
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
//   committed: 24 inputs, 192,317 script B, 193,369 score B, 192,529-B serialized spend,
//              151,427,800 op, max input 7,960,387 op
//   alternate: 24 inputs, 193,407 script B, 194,459 score B, 193,619-B serialized spend,
//              152,316,196 op, max input 7,960,567 op
//   dense:     24 inputs, 229,320 script B, 230,372 score B, 229,532-B serialized spend,
//              183,344,123 op, max input 7,960,794 op
// All three are exactly funded at 1 sat/byte, pass the BCH 2026 consensus VM and standard
// per-input script policy, and are non-standard solely because each complete transaction exceeds
// the 100,000-byte standard transaction limit. This entry is therefore current-consensus-valid
// but not standard-relayable. The committed vector passes 11/11 rejection runs, 3/3 isolated
// point/range rejection runs, and all 23 adjacent-seam splice checks. The dense valid fixture
// exercises all 128 GLV Straus add positions; it is deterministic stress coverage, not a formal
// global arithmetic maximum.
//
// Against the immediate-upstream 26-input artifact, this schedule reduces score by 412 B,
// serialized size by 342 B, script bytes by 326 B, total op-cost by 241,885, and inputs by 2.
// This one-transaction path uses its own linked Miller and shared-table GLV boundaries, isolated
// from the independently selected grouped quotient schedule and the default Fp6-tail schedule.
//
// Byte-exact provenance:
//   source: groth16_cashscript commit 2b76007bec86727ccc0018dcb4ea9b905042a52f
//   compiler: CashScript commit 1c707c1dbf87396b30ba5e0704b1db44475ce893
//   vector sha256: ce60c541019ee1053926bed9f047d477971fc69ee37bfb64779f0050caffd31d
//   locking graph sha256 (raw concatenated locking bytecode):
//     42ab7c5f075ff33b2626a772d1b3c55fb44be206265bdb3b5dd13c14eddfa0ca
// Reproduce from the source checkout (the command emits the pinned linked schedule, proves the quotient
// algebra and exact four-pair traces, and runs valid, rejection, consensus, standard-script,
// exact-fee, and transaction-size checks before writing the deterministic vector):
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus:bls
//
// sha256 of locking bytecode, in input order:
//   00 86dcee793ba2b539d2302cea1634d6846f6ee7e0e48fc13b4e8ed8921121dacf
//   01 adec6a5f8eecef34ab5d958d296286cad053d738f4b224b46e1f2748da53603a
//   02 4345dd07ff4d4a84965a9fca8868597fc5bc980e4778d88c91a3ef9cccd5b928
//   03 732dcf74fe3e2c0e7fe66e3b326f41412c88576005c819629ba3664e7524f39e
//   04 a3a4006d9674e140aee2903c10ce42b918b259919a7fef920dc07a8c764cffd0
//   05 e718495bad4e05fab5d1d7068f3aa80a66b7d089205a1c3110c9dec56536d6f4
//   06 21f88251aec244702ad67b5e19aac03c3ac2f7c6b80bed4ff2426f23f098dda7
//   07 841f82a58770708158c9017254f02e458e7f7dba1e8fe42c0e9d201092a16e12
//   08 bc5a23ecfa51a1ce739aec6fecbd440408904da89d90fa1f4280f68fc4e7c726
//   09 45fbd3cb29b8ff92d9b6a3f775a36e47a60af01baf757c090bd52988180cbb36
//   10 d691c599edf438aa3709c0cce102b6476863cb5ebfedc9296b616d5c9ce219e8
//   11 ef9828de2e627be7ce70a7501df1f8ca23e6364e4c83c304c6f934ff10d685ba
//   12 8ccf77822602b01f8a860eadfbd21f46ecc617bd69ddac33c8137690db5961ff
//   13 6248608e9b0a16481b9bcc32319d3e0abb665290c446f0d85404db7a2549c432
//   14 1bf75705e4f4340cdee600b2990e7669b6fc162dba30214ae9f756b00237cd79
//   15 3510fd3cce06c2a5076b9e53ebba430de3017121b48900e5e102d29eea2c89fa
//   16 8946e7936c40b24a903913f8140a143e32faaafeaffc04dd146ea44aa6d8dc2d
//   17 085f3b6d0c94af998d68dc8ff1c083e3d5f01427cc40c28a70d59c386c7f8c3f
//   18 619abd081b289a2537ba03e2481cb973efae2b8ca0931d9ec3cf5ed4b19be088
//   19 2c96db8d42d91f7e042f8b84f514045dbfaa84381343ca7d3cdf1e2247079eed
//   20 1f85a4d90d33e529d691fd0534a91fa54ef5e34074f13eb54b73a9e38639d4c3
//   21 2e5077492719ca442266273311e5694b114f36b76708b79a78f322c92a31a471
//   22 67a538d25fb1499258e85935f9d9fb4bc0f68e96c3aba472eaf489a54e1ee715
//   23 353a4fb1260152792dc704f107db33579ccd9e77d9306f930931976f9305a3fe
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
  name: 'BCH BLS12-381 Groth16 intra-tx quotient-torus residue (24-input consensus-valid verifier)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the complete four-pair BLS12-381 equation linked across 24 inputs of ' +
    'one transaction. Five shared-table GLV vk_x inputs feed 19 c^-|x|-fused prepared-Miller ' +
    'inputs. Runtime A/C are canonically encoded and on-curve; runtime B is also checked in the ' +
    'exact G2 subgroup. The fixed e(alpha,beta) value and fixed-G2 gamma/delta lines use ordinary ' +
    'verification-key preparation; no setup-scalar relation collapses the equation. A canonical ' +
    'six-limb u represents [c]=[1+u*W] in ' +
    'Fp12*/Fp6*, where gcd(p+|x|,p^6+1)=r makes the lambda-power image exactly the pairing ' +
    'kernel. Constant root folds use two Fp6 products, and the final Miller input checks ' +
    '[fF]=[frob(c,1)] with a nonzero projective representative, eliminating the separate tail. ' +
    'OP_INPUTBYTECODE directly binds every state, the root, and both stage seams. One fixed ' +
    'P2SH32 script set verifies any proof for the VK at runtime. Every input fits current BCH ' +
    'script and op-cost limits; the exactly funded 192,529-byte transaction is consensus-valid ' +
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
