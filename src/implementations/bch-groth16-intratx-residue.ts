// BCH-native BN254 Groth16 verifier in one intra-transaction-linked transaction:
//
//   grouped GLV vk_x MSM                                    2 inputs
//   c^-(6x+2)-fused Miller + quotient residue verdict       9 inputs
//                                                          ---------
//                                                          11 inputs
//
// Every input forward-checks the next input's raw state with OP_INPUTBYTECODE. The two GLV inputs
// execute a 43-position four-scalar schedule over one input-carried lookup table, then hand the
// IC1/IC2 MSM to Miller genesis as projective (X,Y,Z). The fixed e(IC0,gamma) and e(alpha,beta)
// Miller factors are precomputed. Proof A and C enter as canonical normalized (u,v) coordinates,
// with (0,0) encoding the identity. An identity B is mapped to fixed G2.BASE together with a zero
// first pairing multiplier. Genesis checks the point relations and binds the projective GLV state.
// Runtime non-identity B is affine; its post-loop endomorphism equation is an exact subgroup check.
//
// The Miller accumulator lives in Q=Fp12*/Fp6*. A six-limb canonical u represents
// [c]=[1+u*W], where W is the Fp12/Fp6 tower basis; [c^-1]=[1-u*W]. Q has order p^6+1,
// gcd(lambda,p^6+1)=r for lambda=6x+2+p-p^2+p^3, and the lambda-power image is exactly the
// final-exponent kernel. The terminal input therefore accepts precisely when
// [f*c^(p^2)]=[c^p*c^(p^3)], with [0:0] explicitly rejected. The older residue-coset correction
// lies in Fp6 and disappears in Q. A fixed r-torsion kernel shift makes every valid root finite
// without changing its lambda power.
//
// Committed fixture: 90,442 benchmark script bytes; 90,550 serialized transaction bytes;
// 90,935 verifier.cash bytes including 11 spent 35-byte P2SH32 lockings; 70,662,495 op-cost.
// Universal certificate: 99,284 serialized bytes; 79,387,771 op-cost; 716-byte relay margin.
// Compiler: mr-zwets/cashscript compiler-optimizations @
// 1c707c1dbf87396b30ba5e0704b1db44475ce893
// Vector SHA-256: 2e31e15602ac74e83b97d7d362e4e1d3685bf43eac80eb0987effe1db7bb0246
// Locking graph SHA-256: f997efcb6ae47b70aea017220d53097669dc53218715bd3343950334425a6638
// Locking-bytecode SHA-256 values, in input order:
//   00 653689340ec23eb64fbae9a83c6bbd2ea58b2dbbbf631fcd6a9c5d18b10fe47e
//   01 c8ab117bbec58018ea0f2f616c8f3674c528679417f8d9a9e1c9e5333c804614
//   02 04bd2ab3a12d640c83c43add3350c622f747cd0fdaaa342ac49ed4a9e357eea7
//   03 cd15b7761b96330f7b6b719d18a555b2ad6eee3c0622c7bed9149ffc66e9c4f1
//   04 970cfa221f6158ebc3cf43af22fa7f94a2d4fa5d75332db9174e5186fd41c46c
//   05 6b6e4cb9bb089a2086de90f667155804bb238a0a9a71f31c9f8d500ae29b920b
//   06 12580c946007866a6f9f292b0dfa17ce04c881eadf842c1fefcc5fb820aeec1b
//   07 0b4165196ddc863137067c92188ff85db4986151b523fbd358563a919c3cb6d3
//   08 eb8db42b30afeaaa1ebeb6fb2e7d332e1c0ac951ec8562578e2e1f25e9e8988d
//   09 5d3dcc87b09dc38ae95df95321fc24e64d462cd08e079fd6e7fe724896d77306
//   10 77f8f904040aebbf328dfa541484ea5e27815672e206a8b7da2d9e0c32f9a45b
//
// Regenerate from matched source/bench checkouts with:
//   VERIFIER_DIR=/path/to/zk-verifier-bench pnpm vectors:intratx:torus
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors {
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  resourceFixtureProof?: RawStep[];
  worstCaseProof?: RawStep[];
  invalid?: RawStep[][];
  invalidInputs?: RawStep[][];
}

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
  name: 'BCH Groth16 intra-tx quotient-torus residue (11-input standard fixture)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: one runtime-proof BN254 verifier linked across 11 inputs of one ' +
    'transaction. Two grouped GLV vk_x inputs feed nine affine, unit-line Miller inputs. The GLV ' +
    'stage carries the IC1/IC2 MSM projectively into Miller genesis, while e(IC0,gamma) and ' +
    'e(alpha,beta) are folded into the fixed Miller factor. G2 subgroup validation is fused into ' +
    'the Miller endpoint. Proof A and C use canonical normalized (u,v) coordinates, where (0,0) ' +
    'is the identity. An identity B is represented by fixed G2.BASE and a zero first pairing ' +
    'multiplier, preserving the neutral pairing factor without an affine-infinity encoding. The ' +
    'six-limb root u represents [c]=[1+u*W] in Fp12*/Fp6*, reducing ' +
    'each residue fold from three Fp6 products to two. The terminal checks ' +
    '[f*c^(p^2)]=[c^p*c^(p^3)] with a nonzero projective representative. OP_INPUTBYTECODE ' +
    'forward-binds every dynamic state and pins the canonical root/proof context to Miller ' +
    'genesis. Executable certificates cover the projective handoff and universal nonzero-Y ' +
    'invariant; generated fixtures cover every combination of identity A, B, and C. Each script ' +
    'and complete fixture transaction is checked against current BCH consensus and standard ' +
    'relay policy. Deployed as P2SH32.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = [
      ...(v.extraValidProofs ?? []),
      ...(v.resourceFixtureProof === undefined ? [] : [v.resourceFixtureProof]),
    ].map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    const invalidInputs = (v.invalidInputs ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
