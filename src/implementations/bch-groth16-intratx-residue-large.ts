// BCH-native Groth16 verifier — INTRA-TRANSACTION LINKED + QUOTIENT-TORUS RESIDUE with LARGE
// (100 kB) input scripts, targeting the PROPOSED bch-spec upgrade. Identical mechanism and
// quotient-torus chunk graph to bch-groth16-intratx-residue (OP_INPUTBYTECODE forward-checking,
// GLV vk_x MSM, c^-(6x+2)-fused Miller in Fp12*/Fp6* with e(alpha,beta) precomputed, endpoint-
// fused exact G2 subgroup check, terminal [f*c^(p^2)]=[c^p*c^(p^3)] with [0:0] rejection), but
// re-planned at the 100 kB budget:
//
//   GLV vk_x MSM             1 input    (one 128-iter loop window; 5.2M op in a 2.3 kB unlock)
//   fused Miller + verdict   1 input    (the whole unrolled torus walk, ~71.8M op)
//                            --------
//                            2 inputs   (one standard-relayable-on-spec transaction)
//
// 82,183 B / 77.0M op over 2 inputs (worst case 91.0M op) — below the current-BCH 13-input
// frontier on every axis. Every input fits its own bch-spec budget ((10000 + unlockingLen) * 800
// up to 88,000,000 op, scripts <= 100,000 B); deployed as P2SH32 so each chunk redeem rides in
// the scriptSig where it counts toward the op-cost budget. Graded against the real bch-spec VM
// (createVirtualMachineBchSpec).
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_residue_large.mjs ->
// src/bch/groth16-intratx-residue-large-vectors.json.
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
    'BCH-native CashScript: the quotient-torus BN254 Groth16 verifier laid out as the INPUTS of ' +
    'ONE transaction, sized for the PROPOSED bch-spec upgrade (100,000-byte scripts, op-cost ' +
    'budget (10000 + unlockingLen) * 800 = up to 88,000,000 per input). Same forward-checking as ' +
    'bch-groth16-intratx-residue (each input carries its incoming state as a raw byte blob and ' +
    'binds the chain via tx.inputs[idx+1].unlockingBytecode introspection) and the same ' +
    'quotient-torus graph (GLV vk_x MSM, c^-(6x+2)-fused Miller in Fp12*/Fp6* with e(alpha,beta) ' +
    'precomputed, endpoint-fused exact G2 subgroup check, terminal cross-multiplied ' +
    '[f*c^(p^2)]=[c^p*c^(p^3)] with projective-zero rejection), re-planned at the 100 kB budget ' +
    'into 2 inputs (GLV vk_x 1, unrolled fused Miller + verdict 1): 82,183 B / 77.0M op, below ' +
    'the current-BCH 13-input frontier on every axis. Each input fits its own bch-spec budget; ' +
    'NOT valid on current BCH (BCH_2026 caps scripts at 10,000 B) — it requires the bch-spec ' +
    'upgrade. Deployed as P2SH32 so each chunk redeem rides in the scriptSig where it counts ' +
    'toward the op-cost budget.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    const invalidInputs = (v.invalidInputs ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
