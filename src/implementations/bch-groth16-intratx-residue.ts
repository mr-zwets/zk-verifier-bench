// BCH-native BN254 Groth16 verifier in one intra-transaction-linked transaction:
//
//   grouped GLV vk_x MSM                                    2 inputs
//   c^-(6x+2)-fused Miller + quotient residue verdict       9 inputs
//                                                          ---------
//                                                          11 inputs
//
// The designated input-0 verifier UTXO is the graph root. It requires exactly 11 inputs, and every
// nonterminal input pins its immediate successor's complete locking program at active index + 1.
// Inputs 2 through 6 use direct byte equality; the remaining edges pin the successor's SHA-256.
// The ten hops force the root to index 0 and fix every successor position; the final three inputs
// retain redundant position gates because public cashc compiles them smaller. Each handoff checks
// the successor state with OP_INPUTBYTECODE. The two GLV
// inputs execute a 43-position four-scalar schedule over one exact-length, hash-bound lookup table,
// then hand the IC1/IC2 MSM to Miller genesis as projective (X,Y,Z). The fixed e(IC0,gamma) and
// e(alpha,beta) Miller factors are precomputed. Proof A and C enter as canonical normalized (u,v)
// coordinates, with (0,0) encoding the identity. An identity B is mapped to fixed G2.BASE together
// with a zero first-pairing multiplier. Genesis checks the point relations and binds the projective
// GLV state. Runtime non-identity B is affine; its post-loop endomorphism equation is an exact
// subgroup check.
//
// The Miller accumulator lives in Q=Fp12*/Fp6*. A six-limb canonical u represents
// [c]=[1+u*W], where W is the Fp12/Fp6 tower basis; [c^-1]=[1-u*W]. Q has order p^6+1,
// gcd(lambda,p^6+1)=r for lambda=6x+2+p-p^2+p^3, and the lambda-power image is exactly the
// final-exponent kernel. The terminal input therefore accepts precisely when
// [f*c^(p^2)]=[c^p*c^(p^3)], with [0:0] explicitly rejected. The older residue-coset correction
// lies in Fp6 and disappears in Q. A fixed r-torsion kernel shift ensures every accepting
// boundary has a finite lambda-root witness without changing the witness relation.
//
// Quotient-torus chunks use separately named raw affine kernels, retaining products until the
// final coordinate or slope equation. Direct compiled-kernel probes pass on consensus and standard
// BCH VMs; the differential/range certificate covers 260 doubles and 92 additions and proves every
// intermediate remains below 8p^2. The canonical singleton-minop kernels remain unchanged.
//
// Fixture scope: verifier.cash's deterministic BN254 checkpoint key publishes its setup and IC
// scalars so the harness can mint multiple satisfying equations without a circuit prover. The
// bytecode still evaluates the complete four-pair equation and does not use those relations to
// collapse the on-chain statement. These vectors therefore establish equation execution, runtime
// witness handling, and BCH resource validity for the prescribed key; they do not establish circuit
// knowledge, secure binding of the public-input vector, or independent-setup interoperability.
//
// Committed fixture: 88,397 benchmark script bytes; 88,505 serialized transaction bytes;
// 88,890 verifier.cash bytes including 11 spent 35-byte P2SH32 lockings; 68,575,152 op-cost.
// Proof-independent relay encoding: 97,016 serialized bytes; 77,253,358 op-cost ceiling;
// 2,984-byte standard-transaction margin.
// Source: mr-zwets/groth16_cashscript @ 6819ad7908a66169897f3b9149e11278b261452b
// Compiler: mr-zwets/cashscript compiler-optimizations @
// 1c707c1dbf87396b30ba5e0704b1db44475ce893
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: 628ff17be61a1ab77f291fdc1612c7bfe0d1452871379208c1ffe639d4db25d5
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// b3650c298e64218852d3688936d84df57023154afc05a516fc4a5531f54464b1
// Synthetic zero-outpoint fixture serialization hash256:
// d15dda8774fb48cefcdf92e60078052e6a5c8e6b95037922aae122ffb1882546
// Locking-bytecode SHA-256 values, in input order:
//   00 2bacad65133c2be5d8a7e1e8164a768b9bfe404f7e80835853fbd6504637c9c3
//   01 0afda9439b2c6d6a0e886dcc67fbce67c498db49f306206494233ac2b4ff19d5
//   02 0ebc5160822ec831fbcd538eb216da655bda86c406ce3456cecf20f3c3db014d
//   03 27c90ce11b729103cb67fb183a5bc74f3bd940a949b5a6e025ad445956bfc37c
//   04 ba540858f909f1990d0e143fbfdfcd998c3808e382ef286f05356b3a9b3ebd86
//   05 b2f72b0fc6c1b06550b5da74c16cde2786f51cd50eed821106a156c8a3fcf01d
//   06 5b27feb38468c6a37d157ffc78a7e17235aeaac6191c31e4d91ff5e0a7dcb088
//   07 16981c29d9fc44933fa18e8c3f7d85189444d1c15776fdc35e8988df6915a9cc
//   08 8f8faa007f5bc7295cda7d704d6f6f7012980be3562bfb795bc954e1b6200600
//   09 cbef6a1eeb2f397bdb8b0cc5a6648a6c93df4821c34fd161e0677c4c8eeb93f8
//   10 b60c599ea00f46a68e46901ab29e97409abbb61f5e8b13a0f26f03aa116ba26c
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
    'inputs enforce exact state-push lengths so both consume the same hash-bound table. The second ' +
    'input carries the IC1/IC2 MSM projectively into Miller genesis, while e(IC0,gamma) and ' +
    'e(alpha,beta) are folded into the fixed Miller factor. G2 subgroup validation is fused into ' +
    'the Miller endpoint. Proof A and C use canonical normalized (u,v) coordinates, where (0,0) ' +
    'is the identity. An identity B is represented by fixed G2.BASE and a zero first pairing ' +
    'multiplier, preserving the neutral pairing factor without an affine-infinity encoding. The ' +
    'six-limb root u represents [c]=[1+u*W] in Fp12*/Fp6*, reducing each residue fold from three ' +
    'Fp6 products to two. The terminal checks ' +
    '[f*c^(p^2)]=[c^p*c^(p^3)] with a nonzero projective representative. OP_INPUTBYTECODE ' +
    'forward-binds every dynamic state. The root enforces the exact graph size, while each ' +
    'nonterminal input pins its immediate successor locking program at active index + 1. Inputs ' +
    '2 through 6 use direct byte equality; the remaining edges bind the successor SHA-256. Ten hops ' +
    'force the root to position 0 and fix every successor; the final three programs retain ' +
    'redundant position gates because public cashc compiles them smaller. The designated input-0 ' +
    'verifier UTXO therefore commits transitively to the complete ordered graph. ' +
    'The quotient-torus Miller chunks use scoped raw affine kernels whose compiled probes, field ' +
    'equivalence, and integer ranges are checked by the source pipeline. Executable certificates ' +
    'also cover the projective handoff, nonzero-Y invariant, subgroup endpoint, quotient relation, ' +
    'and a proof-independent 97,016-byte standard relay encoding. Generated fixtures cover every ' +
    'combination of identity A, B, and C, exact layout changes, all successor programs, table ' +
    'alignment, state seams, slopes, points, and proof binding. The companion source pipeline checks ' +
    'complete transactions against current BCH consensus and standard script/size policy, and ' +
    'constructs exact minimum-fee templates. Deployed ' +
    'as P2SH32. The prescribed checkpoint key is synthetic and publishes its setup and IC scalars. ' +
    'The bytecode evaluates the complete four-pair equation without using those relations to collapse ' +
    'the statement, but these vectors do not establish circuit knowledge, secure public-input-vector ' +
    'binding, or interoperability with an independently generated setup.',
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
