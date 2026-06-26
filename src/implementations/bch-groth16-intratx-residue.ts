// BCH-native Groth16 verifier — INTRA-TRANSACTION LINKED + RESIDUE, the whole computation
// in ONE transaction. This is the residue-optimized counterpart of bch-groth16-intratx:
// same single-tx forward-checking mechanism (each chunk is an INPUT whose witness carries
// its incoming state as a raw byte blob, and it require()s the next input's blob — read via
// tx.inputs[idx+1].unlockingBytecode, OP_INPUTBYTECODE — equals its recomputed output), but
// it runs the residue-optimized chunk graph instead of the plain one:
//
//   fast-G2 endo subgroup check (ePrint 2022/348)            4 chunks   (== plain build)
//   GLV vk_x MSM (4-scalar ~128-bit Straus)                  5 chunks   (was 9, plain)
//   c^-(6x+2)-FUSED Miller, e(alpha,beta) precomputed        23 chunks  (skips pair 1)
//   witnessed-residue final-exp TAIL (verdict in ONE chunk)  1 chunk    (was 12, plain)
//                                                            ---------
//                                                            33 inputs  (plain intratx: 54)
//
// The residue witness (c, cInv) threads through every fused-Miller chunk and is re-checked
// in the tail (c*cInv==ONE, c canonical, w in {1,w27,w27^2}); the verdict is the residue
// equation fF*w*c^q2 == c^q*c^q3. Cross-stage soundness links are bound where layouts allow
// (vk_x into the fused-Miller genesis input; the fused-Miller boundary [fF,c,cInv] into the
// residue tail). Same chunk math as bch-groth16-grouped-residue, but laid out as the inputs
// of one non-standard (<1 MB) transaction rather than token-threaded standard transactions.
//
// Result: ~263 KB / ~202M op over 33 inputs (vs ~523 KB / 411M over 54 for plain intratx),
// each input fitting one BCH input budget (op-cost <=8,032,800, scripts <=10,000 B).
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_residue.mjs ->
// src/bch/groth16-intratx-residue-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

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
  name: 'BCH Groth16 intra-tx linked + residue (whole residue-optimized verifier in one transaction, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the residue-optimized full BN254 Groth16 verifier laid out as ' +
    'the INPUTS of ONE transaction. Same forward-checking as bch-groth16-intratx (each input ' +
    'carries its incoming state as a raw byte blob and binds the chain via ' +
    'tx.inputs[idx+1].unlockingBytecode introspection — no NFT-commitment hand-off, no ' +
    'hashing, no 128-byte state limit), but it runs the residue chunk graph: fast-G2 endo ' +
    'subgroup check (ePrint 2022/348, 4 chunks), GLV vk_x MSM (5 chunks), c^-(6x+2)-FUSED ' +
    'batched Miller with e(alpha,beta) precomputed/skipped (23 chunks), and a witnessed-' +
    'residue final-exponentiation TAIL collapsing the hard exponentiation to ONE chunk — 33 ' +
    'inputs total (vs 54 for the plain intra-tx build), ~263 KB / ~202M op. The residue ' +
    'witness (c, cInv) threads through every fused-Miller chunk and is re-checked in the tail ' +
    '(c*cInv==ONE, c canonical, w in {1,w27,w27^2}); the verdict is fF*w*c^q2 == c^q*c^q3. ' +
    'Every input fits one BCH input budget (op-cost <=8,032,800, scripts <=10,000 B); the ' +
    'whole verifier is one non-standard (<1 MB) transaction. Same chunk math as ' +
    'bch-groth16-grouped-residue; one fixed set of input scripts verifies any proof for the VK ' +
    '(proof in the witness). Deployed as P2SH32 so each chunk\'s redeem rides in the scriptSig, ' +
    'where it counts toward the op-cost budget and offsets the pad.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
