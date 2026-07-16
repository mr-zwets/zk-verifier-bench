// BCH-native BN254 Groth16 verifier targeting the PROPOSED bch-spec 100 kB-script VM:
//
//   GLV vk_x MSM             1 input    (one 128-position four-scalar schedule)
//   fused Miller + verdict   3 inputs   (the complete 348-operation quotient-torus trace)
//                            --------
//                            4 inputs   (one transaction passing the bch-spec standard-policy model)
//
// The root fixes the exact input count and SHA-256-pins the terminal program; the terminal fixes
// its position. OP_INPUTBYTECODE binds the projective vk_x and complete Miller-state handoffs. The
// Miller inputs validate canonical A/B/C encodings, curve relations, identity semantics, and the
// exact runtime-B subgroup endpoint, then evaluate the complete prescribed four-pair equation. They
// fold only the ordinary fixed-key e(alpha,beta) and e(IC0,gamma) factors; they do not use the
// fixture's published scalar relations to collapse the statement.
//
// Committed fixture: 58,631 script B; 58,683 serialized B; 58,823 verifier.cash score;
// 68,317,512 op. The dense worst-case fixture is 70,144 serialized B / 82,375,653 op.
// All 14 accepting fixture families use the same locking graph and pass the bch-spec consensus
// and standard-policy VMs with default-minimum-fee-funded deterministic templates. This requires
// the proposed VM because
// the largest unlocking is 21,393 B; current BCH limits unlocking bytecode to 10,000 B.
//
// The prescribed checkpoint key is synthetic and publishes setup and IC scalars. These vectors
// establish complete-equation execution and proposed-VM resource validity for that key; circuit
// knowledge, production public-input binding, arbitrary-key verification, and independently
// generated setup interoperability are outside this artifact's scope.
//
// Source: mr-zwets/groth16_cashscript @ b4d9780275d5f1545465c2dec9702e70ea621006
// Compiler: mr-zwets/cashscript compiler-optimizations @
// 1c707c1dbf87396b30ba5e0704b1db44475ce893
// Input fixture SHA-256:
//   multiproof d513f1fe45d7aba20f289cbc38439d5ebdb05a9975950a5e32d2bf21239d4abc
//   pairing checkpoint e393e8b6af6f528c93f97f37656802bf44daefa5819640a557fbff95e236739e
// Vector SHA-256: 860d7fa449fd1fd666cd8158d3bc3bdf9d5a5ad50947dbb89311a8cb081f7caa
// Locking graph SHA-256 (UTF-8 concatenated locking-hex text):
// 661ada6d936a22991dba578fc84590c13628c429cc499c6d008efd81cb1abb48
// Locking-bytecode SHA-256 values, in input order:
//   00 176f4d3adcde71b894768c383511903da9fbd01db0d85a748ccd2534e3e33b25
//   01 981413eb2acfc42deb9cab59ec4dddd56543da1dc6593e5f8f16312d5cab1f23
//   02 eec55ea1c7a89b5c123ec0cdb331dd09d470d74c17628070749316b2f1ac83cf
//   03 cc99d54729c273c4103fe481f9c042deca4340ff976b16f5afacf8244936c647
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
  name: 'BCH Groth16 intra-tx quotient-torus residue, LARGE 100 kB scripts (whole verifier in 4 inputs of one transaction, PROPOSED bch-spec)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  vm: 'bch-spec',
  source:
    'BCH-native CashScript: one runtime-proof BN254 verifier in four linked inputs of one ' +
    'transaction, targeting the proposed bch-spec 100,000-byte-script VM. A 128-position ' +
    'four-scalar GLV schedule computes the IC1/IC2 MSM projectively. Three linked inputs then ' +
    'validate canonical A/B/C encodings, curve relations, identity semantics, and the exact ' +
    'runtime-B subgroup endpoint while executing the complete 348-operation quotient-torus ' +
    'Miller trace and terminal relation. The fixed e(alpha,beta) and e(IC0,gamma) factors are ' +
    'precomputed without using the fixture\'s published scalar relations to collapse the ' +
    'four-pair equation. The root enforces the exact input count and pins the terminal locking ' +
    'program; the terminal enforces its position; OP_INPUTBYTECODE binds every state handoff; ' +
    'all input blobs have exact widths. All accepting fixtures pass the bch-spec consensus and ' +
    'standard-policy VMs with fee-funded deterministic templates. The 21,393-byte maximum ' +
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
