// BCH-native hash-STARK verifier, INTRA-TRANSACTION LINKED: a DEEP-ALI FRI-STARK over Goldilocks
// verified by the 22 linked INPUTS of ONE transaction. No pairing, no elliptic curve, no trusted
// setup: the only cryptographic assumption is the collision resistance of SHA256, which the BCH VM
// provides natively.
//
// This is a different proof system from the Groth16 entries, so it opens its own leaderboard
// (proofSystem: 'FRI-STARK', per the Implementation.proofSystem contract in harness/types.ts). It is
// listed here because it exercises exactly the BCH-specific problems this benchmark was built to
// surface: chunking across inputs, intra-transaction state hand-off, the per-input 10,000-byte cap,
// and the op-cost density budget.
//
// WHAT IS VERIFIED
//
// The statement is a Poseidon2 hash chain over Goldilocks (t=12, x^7, R_F=8, R_P=22, the HorizenLabs
// reference of ePrint 2023/323) expressed as an AIR. Challenges live in the quadratic extension
// GF(p^2) so the 64-bit base field does not cap challenge soundness. The chain is:
//
//   AIR constraints -> batched into one composition polynomial (ALI, Fiat-Shamir alphas)
//   -> DEEP quotient at an out-of-domain point z -> FRI low-degree test (fold 8)
//
// Input 0 carries the Fiat-Shamir committed blob and runs the covenant that recomputes every
// challenge from the transcript. The other 21 inputs each execute one piece of the verification and
// read their operands from input 0 or from a sibling input via OP_INPUTBYTECODE, which is the
// intraTx mode this harness already models.
//
// SOUNDNESS WIRING
//
// Every value a cheating prover could otherwise choose freely is either recomputed on chain or
// single sourced from the committed blob and cross bound: the out-of-domain openings, the batching
// and DEEP alphas, the FRI fold challenges and per-round commitment roots, the query positions, the
// carry chain between the split composition parts, and the GF(p^2) inverse hints. On top of that,
// every input is pinned to its committed P2SH32 locking with OP_UTXOBYTECODE, so no input can be
// omitted or replaced by a filler that returns true without doing the work.
//
// That last binding exists because two adversarial audits each found a real forged-accept in it:
//
//   1. Hashing an input's UNLOCKING bytes authenticates the bytes, not the code that runs. A bare
//      output (locking OP_DROP OP_1) spent with the committed redeem as a data push passes a
//      scriptSig-byte hash while dropping that redeem unexecuted. The binding moved to the spent
//      output's LOCKING, which P2SH32 consensus ties to the redeem that actually executes.
//   2. Binding only the terminal inputs was not enough. The inputs that other inputs read are read
//      by their bytes, not by their execution, so a bare filler at a producer position (an opener,
//      a shard, the tail/final, a composition part) supplies the expected bytes while skipping its
//      own self-bind, severing the trace to composition to FRI chain. The binding now covers every
//      input, anchored on input 0.
//
// The `invalid` runs in the vectors are exactly that attack, applied at each producer role: the
// input is replaced by a bare self-funded output (locking 7551 = OP_DROP OP_1, empty witness). Each
// must be rejected. Input 0's own execution is the single irreducible external anchor, since a
// within-transaction self-bind would be circular; a deployment pins input 0's outpoint.
//
// SECURITY PARAMETERS OF THESE VECTORS (please read before comparing byte counts)
//
// These vectors are generated at the DEMONSTRATION proving configuration (blowup 8, grinding 2,
// 6 queries, fold 8), which is NOT 100-bit security. They demonstrate the structure, the soundness
// wiring and the real byte and op-cost profile of that structure on the BCH VM. Proving at the real
// parameters (blowup 8192 and up) takes hours and is run offline, and the byte reduction work that
// brings the sound build under the 100,000-byte standard transaction limit is still in progress.
// The numbers here should therefore be read as a structural datapoint, not as a finished 100-bit
// verifier. The security parameter formula used by the design is queries * (log2(blowup) - 1) +
// grinding >= 100.
//
// ARTIFACT PINNING AND PROVENANCE
//
//   sha256 over the 22 lockings concatenated in order:
//     0cb59dc1d83b2e76a527edd063a4eeaa8ee804bb704c2dff4c8fb8f1a96822b9
//   sha256 over the 22 unlockings concatenated in order:
//     92084253b1f654dd9e651c8f55c67c4f36e89cd7325841bc5cb407e9d282fffe
//
// The verifier, the prover and the builder that emits these vectors are public and reproducible:
// https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier
// The vectors come from build_sound_verifier_inputs() in apps/native_ct_verifier_tx.py, compiled to
// bytecode with libauth (P2SH32 locking, unlocking = witness ++ PUSH(redeem)), and that repository's
// own test suite runs the same 22 inputs on real libauth: 22/22 accept, and 10 forged-covenant
// attacks reject, including the bare-filler attacks reproduced in the `invalid` runs below.
//
// An earlier demonstration build of this verifier was funded and spent on BCH chipnet, so the
// construction is confirmed to execute inside a mined block:
//   fund  b8952034f1123691149a2beb5320aeaf9da2a94d4f71225ff6a3dfa6db4ea341 (height 314509)
//   spend 1f56490fb495e48a889f8327a006f9377478d9108b9bdad5c28724904c7e74b0 (height 314510, 92,191 B)
// That chipnet transaction predates the soundness wiring; the vectors here are the wired build.

import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/fri-stark-goldilocks-vectors.json', 'utf8')) as Vectors;

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

export const bchFriStarkGoldilocksIntratx: Implementation = {
  id: 'bch-fri-stark-goldilocks-intratx',
  name: 'BCH hash-STARK intra-tx linked, DEEP-ALI FRI over Goldilocks (transparent, no pairing, demo proving parameters)',
  proofSystem: 'FRI-STARK',
  field: 'Goldilocks',
  structure: 'single-tx',
  proofBinding: 'baked',
  source:
    'BCH-native hash-STARK: a DEEP-ALI FRI-STARK over Goldilocks with GF(p^2) challenges, laid out as ' +
    'the 22 linked INPUTS of ONE transaction. The statement is a Poseidon2 hash chain expressed as an ' +
    'AIR; the AIR residuals are batched into one composition polynomial, opened at an out-of-domain ' +
    'point (DEEP), and the resulting quotient is checked by FRI (fold 8). Input 0 carries the ' +
    'Fiat-Shamir committed blob and recomputes every challenge from the transcript; the other inputs ' +
    'run the openers, the DEEP shards, the composition parts and the aggregated FRI, reading their ' +
    'operands from input 0 or from a sibling via OP_INPUTBYTECODE (intra-tx linked, no NFT hand-off). ' +
    'Transparent: no trusted setup and no elliptic curve, the only assumption is SHA256 collision ' +
    'resistance, which the BCH VM hashes natively. Soundness wiring: every prover-chosen value is ' +
    'recomputed on chain or single sourced from the committed blob and cross bound (out-of-domain ' +
    'openings, batching and DEEP alphas, FRI betas and per-round roots, query positions, the carry ' +
    'chain, the GF(p^2) inverse hints), and every input is pinned to its committed P2SH32 locking with ' +
    'OP_UTXOBYTECODE so no input can be dropped or replaced by a bare filler that skips its self-bind. ' +
    'Two adversarial audits each found and fixed a real forged-accept in that binding layer; the ' +
    'invalid runs reproduce the bare-filler attack at each producer role. Deployed as P2SH32, so each ' +
    'input\'s redeem rides in the scriptSig and counts toward the op-cost budget; every input is within ' +
    'the 10,000-byte cap (largest unlocking 9,813 B, largest redeem 7,569 B). IMPORTANT: these vectors ' +
    'are at the DEMONSTRATION proving configuration (blowup 8, grinding 2, 6 queries), which is not ' +
    '100-bit security; proving at the real parameters takes hours offline and the byte reduction that ' +
    'brings the sound build under 100,000 B is still in progress, so this is a structural datapoint ' +
    'rather than a finished 100-bit verifier. Verifier, prover and vector builder are public: ' +
    'https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier (lockConcatSha256 ' +
    '0cb59dc1d83b2e76a527edd063a4eeaa8ee804bb704c2dff4c8fb8f1a96822b9).',
  load: async () => {
    const valid = toRun(v.steps);
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, invalid };
  },
};
