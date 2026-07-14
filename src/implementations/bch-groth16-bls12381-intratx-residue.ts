// BCH-native BLS12-381 Groth16 verifier — INTRA-TRANSACTION LINKED + RESIDUE, the whole
// computation in ONE transaction. The residue-optimized counterpart of
// bch-groth16-bls12381-intratx and the intra-tx cousin of bch-groth16-bls12381-grouped-residue:
// same single-tx forward-checking mechanism (each chunk is an INPUT whose witness carries its
// incoming state as a raw 48-byte-limb blob, and it require()s the next input's blob — read via
// tx.inputs[idx+1].unlockingBytecode, OP_INPUTBYTECODE — equals its recomputed output), but it
// runs the residue-optimized chunk graph instead of the plain one:
//
//   GLV vk_x MSM (4-scalar ~128-bit Straus, baked table)             5 chunks
//   c^-|x|-FUSED batched Miller, e(alpha,beta) baked (cmul1); the G2  29 chunks
//     on-curve + subgroup check is FUSED in (first/last chunks reuse R_B=[|x|]B)
//   witnessed-residue final-exp TAIL: mu_27A ((w^|x|)*w)^9 walk       5 chunks (4 walk + finalize)
//                                                                    ---------
//                                                                    39 inputs
//
// The residue witness (c, cInv) threads through every fused-Miller chunk and is re-checked in
// the tail; w enters the tail as an uncommitted witness. Cross-stage soundness links are bound
// where layouts allow (vk_x into the fused-Miller genesis input; the fused-Miller boundary
// [fF,c,cInv] into the residue tail). Same chunk math as bch-groth16-bls12381-grouped-residue,
// but laid out as the inputs of one non-standard (<1 MB) transaction rather than token-threaded
// standard transactions.
//
// The worst-case field contains a deterministic valid proof whose four GLV sub-scalars execute
// an add at all 128 Straus positions. It maximized total op-cost among 32 full proofs and increased
// the heaviest step versus the prior fixture. This is empirical stress coverage, not a claim of a
// formal global arithmetic maximum.
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_residue_bls.mjs ->
// src/bch/groth16-bls12381-intratx-residue-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-intratx-residue-vectors.json', 'utf8')) as Vectors;

// Turn one run (an ordered list of chunk inputs) into Step[] sharing ONE inputs array, so each
// step is evaluated against the same multi-input transaction (its tx.inputs[idx±1] introspection
// resolves to the real siblings).
const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({ label: s.label, lockingBytecode: inputs[i]!.lockingBytecode, unlockingBytecode: inputs[i]!.unlockingBytecode, checkpoint: s.checkpoint, intraTx: { index: i, inputs } }));
};

export const bchGroth16Bls12381IntratxResidue: Implementation = {
  id: 'bch-groth16-bls12381-intratx-residue',
  name: 'BCH BLS12-381 Groth16 intra-tx linked + residue (whole residue-optimized verifier in one transaction, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the residue-optimized full BLS12-381 Groth16 verifier laid out as ' +
    'the INPUTS of ONE transaction. Same forward-checking as bch-groth16-bls12381-intratx (each ' +
    'input carries its incoming state as a raw 48-byte-limb blob and binds the chain via ' +
    'tx.inputs[idx+1].unlockingBytecode introspection — no NFT-commitment hand-off, no hashing, ' +
    'arbitrary intermediate size), but it runs the residue chunk graph: GLV vk_x MSM (5 chunks), ' +
    'c^-|x|-FUSED batched Miller with e(alpha,beta) baked and only e(-A,B) running on-chain G2 ' +
    'arithmetic (29 chunks; the G2 on-curve + prime-order-subgroup validation is FUSED into the ' +
    'first/last Miller chunks, reusing the running R_B=[|x|]B the loop already walks), and a ' +
    'witnessed-residue final-exponentiation TAIL collapsing the Hayashida-Scott hard part to a ' +
    'mu_27A ((w^|x|)*w)^9 walk + fF*w==frob(c,1) verdict (5 chunks) — 39 inputs total (vs 83 for ' +
    'the plain intra-tx build). The residue witness (c, cInv) threads through every fused-Miller ' +
    'chunk and is re-checked in the tail; w enters the tail as an uncommitted witness. Every ' +
    'input fits one BCH input budget (op-cost <=8,032,800, scripts <=10,000 B); the whole ' +
    'verifier is one non-standard (<1 MB) transaction. Same chunk math as ' +
    'bch-groth16-bls12381-grouped-residue; one fixed set of input scripts verifies any proof for ' +
    'the VK (proof in the witness). Deployed as P2SH32 so each chunk\'s redeem rides in the ' +
    'scriptSig, where it counts toward the op-cost budget and offsets the pad. The supplied ' +
    'worst-case run is a deterministic valid all-position GLV stress proof selected from 32 full ' +
    'proofs; this is empirical stress coverage rather than a formal global arithmetic maximum.',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
    invalidInputs: (v.invalidInputs ?? []).map(toRun),
  }),
};
