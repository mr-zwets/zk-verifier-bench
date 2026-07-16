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
// inputs execute a 64-position four-scalar schedule over one exact-length, hash-bound lookup table,
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
// Committed fixture: 86,457 benchmark script bytes; 86,565 serialized transaction bytes;
// 86,950 verifier.cash bytes including 11 spent 35-byte P2SH32 lockings; 68,489,869 op-cost.
// Proof-independent relay encoding: 99,079 serialized bytes; 79,226,279 op-cost ceiling;
// 921-byte standard-transaction margin.
// Against published main a86b230 (source 551f1b2), this advances the byte-ranked score by
// 1,828 bytes while adding 18,237 committed op-cost. The universal encoding is 349 bytes larger
// and its summed ceiling is 602,150 op-cost higher; it remains within standard relay policy.
// Source: mr-zwets/groth16_cashscript @ 7436d04f9ccda0511b943eb9ff125d0d10ec879e
// Compiler: mr-zwets/cashscript compiler-optimizations @
// 1c707c1dbf87396b30ba5e0704b1db44475ce893
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: 593111c80eab0c8c933430770e8d622eeadf6df1f4bd08b7e2ed2c69aad17367
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// aa4b7607776c5dc68234195ad060c1fd154904a5c713a0dbd6c0324e49951682
// Synthetic zero-outpoint fixture serialization hash256:
// 7793e03ecf3f0953f9ff76d7a48f8c943adf46357be67a0d2323f23ff8f7cd25
// Locking-bytecode SHA-256 values, in input order:
//   00 967609d602c1512f0e91c3953d4fd4b309085c34cc6a472c61ee079a8fef6bd9
//   01 5587abaf915c53c3c54cfd3f1a51e3f61bf6a85c311a332aa9c720f801d186ed
//   02 f876c705dc1ec416e72fa28e43b1d9de1101e98fd682b804f55bba7248ab8cbd
//   03 1af371e919599de871e28a10f4738845077a6c3af2d494dc8dff2cb408965afa
//   04 0a2c14d205bd034d431bd35e32d25ebe13ca640cf870ddf4c01b02c6739cf0c7
//   05 b9eb93313e45859d22b5eadc5e4881d4ee3dcff8a74c537900a3955a78345b80
//   06 4aa3f732daa5698417edd188ac5975cd0e66e98a6303d9d7b7ba0a0d0ad734c9
//   07 b6e0a9aa9cbc03c92f56422e12e79b0b5c5c5561b0789fa912e68e05e85e33f1
//   08 b63adac318a69f332c61cacdc6958c7f378226fa5d5bca7f10d749da0af70bc0
//   09 2b9541431004058cdb0b3495a2c2d6febe78ce0cdd52ec36b08650a0ce6138fe
//   10 0b4b839bb96e5e1518747d709c748ff22edd36c87693a60b7438a573b6f1bc8d
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
    'and a proof-independent 99,079-byte standard relay encoding. Its grouped-GLV certificate ' +
    'charges the fallback at all 58 and 70 physical lookup slots without using setup or IC scalar ' +
    'relations. Generated fixtures cover every ' +
    'combination of identity A, B, and C, exact layout changes, all successor programs, table ' +
    'alignment, state seams, slopes, points, and proof binding. The companion source pipeline checks ' +
    'complete transactions against current BCH consensus and standard script/size policy, and ' +
    'constructs deterministic templates that fund at least the default minimum relay fee. Deployed ' +
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
