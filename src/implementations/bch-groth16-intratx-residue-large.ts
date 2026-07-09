// BCH-native Groth16 verifier — INTRA-TRANSACTION LINKED + RESIDUE with LARGE (100 kB) input
// scripts, targeting the PROPOSED bch-spec upgrade. Identical mechanism and residue chunk graph
// to bch-groth16-intratx-residue (OP_INPUTBYTECODE forward-checking, no NFT commitment, no
// hashing; fast-G2 endo subgroup check + GLV vk_x MSM + c^-(6x+2)-FUSED Miller with e(alpha,beta)
// skipped + witnessed-residue final-exp tail), but each chunk is sized to a 100 kB unlocking
// instead of 10 kB.
//
// Why it needs bch-spec: current BCH (BCH_2026) caps every script at 10,000 B and grants an
// input (41 + unlockingLen) * 800 op-cost, so ~202M op forces ~33 inputs. The proposed bch-spec
// upgrade raises the per-script cap to 100,000 B and the density-control base to 10,000, so an
// input gets (10000 + unlockingLen) * 800 = up to 88,000,000 op — ~11x. The SAME residue verifier
// therefore collapses to ~one fat input per stage floor:
//
//   fast-G2 subgroup check   1 input
//   GLV vk_x MSM             2 inputs   (the tiny zinv/assert final chunk stays separate)
//   c^-(6x+2)-fused Miller   3 inputs   (161M op / ~80M byte-bound per input)
//   residue final-exp tail   1 input
//                            --------
//                            7 inputs   (one non-standard <1 MB transaction)
//
// ~196 kB / ~178M op over 7 inputs (vs ~263 kB / ~202M over 33 for the current-BCH residue build).
// Op-cost and bytes are conserved — this is a STRUCTURAL simplification (fewer, fatter UTXOs in
// one tx), not a resource reduction. Every input fits its own bch-spec budget (op-cost <=
// 88,000,000, scripts <= 100,000 B); deployed as P2SH32 so each chunk redeem rides in the scriptSig
// where it counts toward the op-cost budget. Graded against the real bch-spec VM (createVirtualMachineBchSpec).
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_residue_large.mjs ->
// src/bch/groth16-intratx-residue-large-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

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
  name: 'BCH Groth16 intra-tx linked + residue, LARGE 100 kB scripts (whole verifier in ~7 inputs of one transaction, PROPOSED bch-spec)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  vm: 'bch-spec',
  source:
    'BCH-native CashScript: the residue-optimized full BN254 Groth16 verifier laid out as the ' +
    'INPUTS of ONE transaction, sized for the PROPOSED bch-spec upgrade (100,000-byte scripts, ' +
    'op-cost budget (10000 + unlockingLen) * 800 = up to 88,000,000 per input). Same ' +
    'forward-checking as bch-groth16-intratx-residue (each input carries its incoming state as a ' +
    'raw byte blob and binds the chain via tx.inputs[idx+1].unlockingBytecode introspection — no ' +
    'NFT-commitment hand-off, no hashing, no 128-byte state limit) and the same residue chunk ' +
    'graph (fast-G2 endo subgroup check, GLV vk_x MSM, c^-(6x+2)-FUSED batched Miller with ' +
    'e(alpha,beta) precomputed/skipped, witnessed-residue final-exp TAIL), but each chunk fills a ' +
    '100 kB input instead of 10 kB, collapsing the verifier from 33 inputs to ~7 (g2check 1, GLV ' +
    'vk_x 2, fused Miller 3, residue tail 1), ~196 kB / ~178M op. Op-cost and bytes are conserved; ' +
    'this is a structural simplification (fewer, fatter UTXOs) rather than a resource reduction. ' +
    'The residue witness (c, cInv) threads through every fused-Miller chunk and is re-checked in ' +
    'the tail (c*cInv==ONE, c canonical, w in {1,w27,w27^2}); the verdict is fF*w*c^q2 == c^q*c^q3. ' +
    'Every input fits one bch-spec input budget (op-cost <= 88,000,000, scripts <= 100,000 B); the ' +
    'whole verifier is one non-standard (<1 MB) transaction. NOT valid on current BCH (BCH_2026, ' +
    'which caps scripts at 10,000 B) — it requires the bch-spec upgrade. Deployed as P2SH32 so each ' +
    'chunk redeem rides in the scriptSig where it counts toward the op-cost budget.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
