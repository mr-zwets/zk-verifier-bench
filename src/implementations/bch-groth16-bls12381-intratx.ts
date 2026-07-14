// BCH-native BLS12-381 Groth16 verifier — INTRA-TRANSACTION LINKED, the whole
// computation in ONE transaction (the BLS counterpart of bch-groth16-intratx). The
// chunked verifier (vk_x -> input-validated prepared-VK Miller product -> final exponentiation ->
// assert product==1) is laid out as 56 INPUTS of a single transaction: 475,579 bytes,
// 377,687,307 op-cost. Each chunk carries its incoming state as a raw 48-byte-limb
// blob and forward-checks its successor via
// tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE) — no NFT-commitment hand-off,
// no hashing, arbitrary intermediate size. The easy-part inverse rides as an
// uncommitted witness. Same chunk math as the multi-tx bch-groth16-bls12381-chunked.
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_bls.mjs ->
// src/bch/groth16-bls12381-intratx-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][]; invalidInputs?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-bls12381-intratx-vectors.json', 'utf8')) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({ label: s.label, lockingBytecode: inputs[i]!.lockingBytecode, unlockingBytecode: inputs[i]!.unlockingBytecode, checkpoint: s.checkpoint, intraTx: { index: i, inputs } }));
};

export const bchGroth16Bls12381Intratx: Implementation = {
  id: 'bch-groth16-bls12381-intratx',
  name: 'BCH BLS12-381 Groth16 intra-tx linked (whole verifier in one transaction, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the full BLS12-381 Groth16 verifier uses 5 shared-table GLV vk_x + 29 ' +
    'input-validated prepared Miller + 22 final-exp inputs. Only proof-derived B walks G2 ' +
    'on-chain; the five GLV siblings read one hash-bound VK table, and fixed gamma/delta lines ' +
    'and e(alpha,beta) are manifest-bound VK constants. ' +
    'The first Miller input checks A/C and B on-curve; the last reuses R_B=[|x|]B for the ' +
    'guarded psi(B)==[-x]B subgroup check. The 56 inputs total 475,579 bytes and ' +
    '377,687,307 op-cost in ONE transaction. vk_x emits exactly (-A,B,C,vk_x); Miller ' +
    'derives f=1 and R_B=B, and every adjacent ' +
    'stage checks the entire successor blob. Each input carries state as a raw 48-byte-' +
    'limb blob and binds the chain by forward-checking its successor via ' +
    'tx.inputs[idx+1].unlockingBytecode introspection (OP_INPUTBYTECODE) — no NFT-' +
    'commitment hand-off, no hashing, arbitrary intermediate size. The easy-part inverse ' +
    'rides as an uncommitted witness. Every input fits one BCH budget (op-cost ' +
    '<=8,032,800, scripts <=10,000 B); the whole verifier is one non-standard (<1 MB) ' +
    'transaction. Same chunk math as bch-groth16-bls12381-chunked; one fixed set of ' +
    'input scripts verifies any proof for the VK (proof in the witness). Deployed as ' +
    'P2SH32 so each chunk\'s redeem rides in the scriptSig, where it counts toward the ' +
    'op-cost budget and offsets the pad (~27% fewer on-chain bytes than bare-script).',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
    invalidInputs: (v.invalidInputs ?? []).map(toRun),
  }),
};
