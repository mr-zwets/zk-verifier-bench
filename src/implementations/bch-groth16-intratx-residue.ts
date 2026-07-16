// BCH-native BN254 Groth16 verifier in one intra-transaction-linked transaction:
//
//   grouped GLV vk_x MSM                                    2 inputs
//   c^-(6x+2)-fused Miller + quotient residue verdict       9 inputs
//                                                          ---------
//                                                          11 inputs
//
// The designated input-0 verifier UTXO is the graph root. It requires exactly 11 inputs, and every
// nonterminal input pins its immediate successor's complete locking program at active index + 1.
// Inputs 2, 3, 5, and 6 use direct byte equality; the remaining edges pin the successor's SHA-256.
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
// collapse the on-chain statement. The verifier layout, cut selection, and universal resource
// certificate also avoid those scalar relations. These vectors therefore establish equation
// execution, runtime witness handling, and BCH resource validity for the prescribed key; they do
// not establish circuit knowledge, secure binding of the public-input vector, or independent-setup
// interoperability.
//
// Committed fixture: 88,285 benchmark script bytes; 88,393 serialized transaction bytes;
// 88,778 verifier.cash bytes including 11 spent 35-byte P2SH32 lockings; 68,471,632 op-cost.
// Proof-independent relay encoding: 98,730 serialized bytes; 78,624,129 op-cost ceiling;
// 1,270-byte standard-transaction margin.
// Source: mr-zwets/groth16_cashscript @ ca9794c341c2e187f64c13b2b2ac61398a4468b5
// Compiler: mr-zwets/cashscript compiler-optimizations @
// 1c707c1dbf87396b30ba5e0704b1db44475ce893
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: 45a46eaf9e7afc8271a670759ce2eb20436316e3cb53aadc1b1e0d4c6452d1f2
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// cf6f11ca2d10eaf8fa5a7bbb401908908513a01e3270189aa8728965e28202ad
// Synthetic zero-outpoint fixture serialization hash256:
// bf880d886a9ef46a6c771e9413f7655222439a0e276d66185ce813e2b08ff45c
// Locking-bytecode SHA-256 values, in input order:
//   00 d13cd41b5ca87e5d1923771b273d79a224511fab352aa9cd507f97e3924f293b
//   01 9fb41b0b4bc2067f88b4c70125c5483073d00825083a9c3a83b5ba0a7d6dcf95
//   02 43d70cf0741aa8181103ec578508a6248cb3c9713630999ed3ff1abba2960764
//   03 d21cd8012a44f419559ed1baf825edbefa53c39860df7fbff39e67df3e93136f
//   04 182a11dea88fe048739d370b77adebbf416ec17e4549058a8fe36ed6416b09d3
//   05 732d217b96f80ddbee7adb3e9a68731cb702aac9c612ca39ced2202f9812f840
//   06 f6abd0a99005dc963e3dd369272073263e11b499c60c4f743e15bcf953bf31f2
//   07 e800a6425c3e3ec7a5e9751ca53feb3e0ef17e4b8f487bfdeeb8cdb3c9c6ab61
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
    '2, 3, 5, and 6 use direct byte equality; the remaining edges bind the successor SHA-256. Ten hops ' +
    'force the root to position 0 and fix every successor; the final three programs retain ' +
    'redundant position gates because public cashc compiles them smaller. The designated input-0 ' +
    'verifier UTXO therefore commits transitively to the complete ordered graph. ' +
    'The quotient-torus Miller chunks use scoped raw affine kernels whose compiled probes, field ' +
    'equivalence, and integer ranges are checked by the source pipeline. Executable certificates ' +
    'also cover the projective handoff, nonzero-Y invariant, subgroup endpoint, quotient relation, ' +
    'and a proof-independent 98,730-byte standard relay encoding. Its grouped-GLV certificate ' +
    'charges the fallback at all 63 and 66 physical lookup slots without using setup or IC scalar ' +
    'relations. Generated fixtures cover every ' +
    'combination of identity A, B, and C, exact layout changes, all successor programs, table ' +
    'alignment, state seams, slopes, points, and proof binding. The companion source pipeline checks ' +
    'complete transactions against current BCH consensus and standard script/size policy, and ' +
    'constructs exact minimum-fee templates. Deployed ' +
    'as P2SH32. The prescribed checkpoint key is synthetic and publishes its setup and IC scalars ' +
    'for fixture generation. The bytecode evaluates the complete four-pair equation, and the verifier ' +
    'layout, cut selection, and resource certificate do not use those relations. These vectors do ' +
    'not establish circuit knowledge, secure public-input-vector ' +
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
