// BCH-native BN254 Groth16 verifier targeting the PROPOSED bch-spec 100 kB-script VM:
//
//   GLV vk_x MSM             1 input    (one 128-position four-scalar schedule)
//   fused Miller + verdict   1 input    (the complete 348-operation quotient-torus trace)
//                            --------
//                            2 inputs   (one standard-relayable bch-spec transaction)
//
// The root fixes the exact input count and SHA-256-pins the terminal program; the terminal fixes
// its position. OP_INPUTBYTECODE binds the projective vk_x handoff. The Miller input validates
// canonical A/B/C encodings, curve relations, identity semantics, and the exact runtime-B subgroup
// endpoint, then evaluates the complete prescribed four-pair equation. It folds only the ordinary
// fixed-key e(alpha,beta) and e(IC0,gamma) factors; it does not use the fixture's published scalar
// relations to collapse the statement.
//
// Committed fixture: 72,163 script B; 72,201 serialized B; 72,271 verifier.cash score;
// 68,808,715 op. The dense worst-case fixture is 83,804 serialized B / 82,867,490 op.
// All 13 accepting fixture families use the same locking graph and pass the bch-spec consensus
// and standard-policy VMs with exact minimum-fee templates. This requires the proposed VM because
// the terminal unlocking is 69,886 B; current BCH limits unlocking bytecode to 10,000 B.
//
// The prescribed checkpoint key is synthetic and publishes setup and IC scalars. These vectors
// establish complete-equation execution and proposed-VM resource validity for that key; circuit
// knowledge, production public-input binding, arbitrary-key verification, and independently
// generated setup interoperability are outside this artifact's scope.
//
// Source: mr-zwets/groth16_cashscript @ 6819ad7908a66169897f3b9149e11278b261452b
// Compiler: mr-zwets/cashscript compiler-optimizations @
// 1c707c1dbf87396b30ba5e0704b1db44475ce893
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: 5f05de4e05c1d61df4ce72b601bf00da7ca239042e4b0921dbbf8b4e92ab8f1d
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// ddbe6f7996fc20598c7469a277a29981c76e073da0f274602e988d482fffafa8
// Locking-bytecode SHA-256 values, in input order:
//   00 1ab4def616d8df48e27c9f7aef537fea2bfc90233a06b41217d4b127711ea768
//   01 a9e8dd8ed9e14ad4d3d4f04883197db39ad65d87318dff386abdae5024590d0b
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-intratx-residue-large-vectors.json', 'utf8')) as Vectors;

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

export const bchGroth16IntratxResidueLarge: Implementation = {
  id: 'bch-groth16-intratx-residue-large',
  name: 'BCH Groth16 intra-tx quotient-torus residue, LARGE 100 kB scripts (whole verifier in 2 inputs of one transaction, PROPOSED bch-spec)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  vm: 'bch-spec',
  source:
    'BCH-native CashScript: one runtime-proof BN254 verifier in two linked inputs of one ' +
    'transaction, targeting the proposed bch-spec 100,000-byte-script VM. A 128-position ' +
    'four-scalar GLV schedule computes the IC1/IC2 MSM projectively. One unrolled input then ' +
    'validates canonical A/B/C encodings, curve relations, identity semantics, and the exact ' +
    'runtime-B subgroup endpoint while executing the complete 348-operation quotient-torus ' +
    'Miller trace and terminal relation. The fixed e(alpha,beta) and e(IC0,gamma) factors are ' +
    'precomputed without using the fixture\'s published scalar relations to collapse the ' +
    'four-pair equation. The root enforces the exact input count and pins the terminal locking ' +
    'program; the terminal enforces its position; OP_INPUTBYTECODE binds the projective handoff; ' +
    'both input blobs have exact widths. All accepting fixtures pass the bch-spec consensus and ' +
    'standard-policy VMs with fee-funded deterministic templates. The 69,886-byte terminal ' +
    'unlocking requires the proposed VM and exceeds current BCH\'s 10,000-byte limit. Deployed ' +
    'as P2SH32. The prescribed checkpoint key is synthetic and publishes setup and IC scalars, ' +
    'so this artifact establishes complete-equation execution and proposed-VM resource validity ' +
    'for that key; it does not establish circuit knowledge, production public-input binding, ' +
    'arbitrary-key verification, or independent-setup interoperability.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    const invalidInputs = (v.invalidInputs ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
