// BCH-native BN254 Groth16 verifier in one intra-transaction-linked transaction:
//
//   GLV vk_x MSM                                            3 inputs
//   c^-(6x+2)-fused Miller + quotient residue verdict      10 inputs
//                                                          ---------
//                                                          13 inputs
//
// Every input forward-checks the next input's raw state with OP_INPUTBYTECODE. Miller genesis
// validates canonical A/B/C, checks the curves, derives the normalized G1 line coordinates, and
// binds the GLV result. Runtime B is affine; its post-loop endomorphism equation is an exact G2
// subgroup check. The fixed e(alpha,beta) Miller value is precomputed.
//
// The Miller accumulator lives in Q=Fp12*/Fp6*. A six-limb canonical u represents
// [c]=[1+u*W], where W is the Fp12/Fp6 tower basis; [c^-1]=[1-u*W]. Q has order p^6+1,
// gcd(lambda,p^6+1)=r for lambda=6x+2+p-p^2+p^3, and the lambda-power image is exactly the
// final-exponent kernel. The terminal input therefore accepts precisely when
// [f*c^(p^2)]=[c^p*c^(p^3)], with [0:0] explicitly rejected. The older residue-coset correction
// lies in Fp6 and disappears in Q. A fixed r-torsion kernel shift makes every valid root finite
// without changing its lambda power.
//
// The committed fixture is 99,993 serialized bytes / 78,422,361 op and passes both whole BCH
// 2026 consensus and standard-policy VMs. The second valid proof is 99,675 bytes and also
// standard. The deliberately dense worst-case fixture is 117,563 bytes: consensus-valid, but
// non-standard by transaction-size policy. Generated with cashc commit
// 1c707c1dbf87396b30ba5e0704b1db44475ce893; regenerate from matched source/bench checkouts with:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus
//
// sha256 of locking bytecode, in input order:
//   00 7be53af85dd402078d76af115500284b8b6b5dbe4a4ace1cbc02b03f5cd463a8
//   01 5a92c26a39b26d682bc6af1cd05227eb8e966f55fb8ffdb240cf34297b8e03ca
//   02 d29c2435a6f84f672b4ea2532abf3fdc49f3e75d87c8b80e903cce1a9135c021
//   03 b6b01b69c5ed729b3fd170831fad8a9263dbfac818fc8a89020ab165701131a5
//   04 9a7eec44dbb8eab3ea82c50573a38dcf2739c0b6f0303ca26fb193fa248dad05
//   05 13018eea4d0afcb3f8b0c5a36a55989e97c8bce543a68d5b84ed090b7c862d35
//   06 c2a96ed9742ad23c866a1abc6397e48d630ad7b50abc76fecd80c6de08e88d6b
//   07 f4c86dd86bc79c5e90d0c3a0ab3368f6e0a0dc730bee91675bb742a0b28487b1
//   08 dc2e83b36af95428ae948072b991bbcc0ddaebdd4c594444e03da132578d7bc6
//   09 9f41b794e71dccfe9fc09b66ec816bbc44c3ed4b180cb1594b4c5727206df52e
//   10 c807054b6d30c1965fa5f6f8d83ba953f6cbd302c6747aa34d5e0f84c1558c7a
//   11 eab2f927b5a555de99f480c4527749630ad6e46fa0e1edb8d9800504749d7cae
//   12 efe013193488c58e179f3cc0720c0d6d5af40cfcd8c49ddabe741366c89e4beb
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-intratx-residue-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array,
// so each step is evaluated against the same multi-input transaction (and its
// tx.inputs[idx±1] introspection resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({
    label: s.label,
    lockingBytecode: inputs[i]!.lockingBytecode,
    unlockingBytecode: inputs[i]!.unlockingBytecode,
    checkpoint: s.checkpoint,
    intraTx: { index: i, inputs },
  }));
};

export const bchGroth16IntratxResidue: Implementation = {
  id: 'bch-groth16-intratx-residue',
  name: 'BCH Groth16 intra-tx quotient-torus residue (13-input standard fixture)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: one runtime-proof BN254 verifier linked across 13 inputs of one ' +
    'transaction. Three GLV vk_x inputs feed ten affine, unit-line Miller inputs; G2 subgroup ' +
    'validation is fused into the Miller endpoint and e(alpha,beta) is precomputed. The six-limb ' +
    'root u represents [c]=[1+u*W] in Fp12*/Fp6*, reducing each residue fold from three Fp6 ' +
    'products to two. The terminal checks [f*c^(p^2)]=[c^p*c^(p^3)] with a nonzero projective ' +
    'representative. OP_INPUTBYTECODE forward-binds every dynamic state and pins the canonical ' +
    'root/proof context to Miller genesis. Each script fits current BCH limits. The committed ' +
    'and second-proof transactions pass standard policy; the dense worst-case remains consensus ' +
    'valid but exceeds standard transaction-size policy. Deployed as P2SH32.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    const invalidInputs = (v.invalidInputs ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
