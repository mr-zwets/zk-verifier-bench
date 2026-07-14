// BCH-native Groth16 verifier — INTRA-TRANSACTION LINKED + RESIDUE, the whole computation
// in ONE transaction. This is the residue-optimized counterpart of bch-groth16-intratx:
// same single-tx forward-checking mechanism (each chunk is an INPUT whose witness carries
// its incoming state as a raw byte blob, and it require()s the next input's blob — read via
// tx.inputs[idx+1].unlockingBytecode, OP_INPUTBYTECODE — equals its recomputed output), but
// it runs the residue-optimized chunk graph instead of the plain one:
//
//   fast-G2 endo subgroup check (ePrint 2022/348)            3 chunks
//   GLV vk_x MSM (4-scalar ~128-bit Straus)                  3 chunks
//   c^-(6x+2)-FUSED Miller + terminal residue verdict        20 chunks  (skips pair 1)
//                                                            ---------
//                                                            26 inputs  (plain intratx: 42)
//
// The residue witness (c, cInv) threads through every fused-Miller chunk. Its terminal chunk
// checks c*cInv==ONE, c canonical, exact w membership in {1,w27,w27^2}, and the residue
// equation fF*(w*c^q2) == (c*c^q2)^q. It uses the same chunk math as
// bch-groth16-grouped-residue, laid out as the inputs of one non-standard (<1 MB)
// transaction rather than token-threaded standard transactions. The three GLV chunks read one
// hash-bound fixed lookup table carried by the final GLV input rather than embedding three copies.
//
// Result: ~225 KB / ~180M op over 26 inputs (vs ~329 KB / ~262M over 42 for plain intratx),
// each input fitting one BCH input budget (op-cost <=8,032,800, scripts <=10,000 B).
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_residue.mjs ->
// src/bch/groth16-intratx-residue-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

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
    'hashing, no 128-byte state limit), but it runs the residue chunk graph: canonical-coordinate fast-G2 endo ' +
    'subgroup check (ePrint 2022/348, 3 chunks), GLV vk_x MSM (3 chunks), c^-(6x+2)-FUSED ' +
    'batched Miller with e(alpha,beta) precomputed/skipped (20 chunks). Its terminal chunk ' +
    'also checks the witnessed-residue verdict, for 26 inputs total (vs 42 for the plain ' +
    'intra-tx build), ~225 KB / ~180M op. The three GLV chunks share one hash-bound fixed ' +
    'lookup table carried by the final GLV input. The residue witness (c, cInv) threads through ' +
    'every Miller chunk; the terminal checks c*cInv==ONE, c canonical, exact w membership ' +
    'in {1,w27,w27^2}, and fF*(w*c^q2) == (c*c^q2)^q. ' +
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
    const invalidInputs = (v.invalidInputs ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid, invalidInputs };
  },
};
