// BCH-native BLS12-381 Groth16 pairing (batched Miller + final exponentiation ->
// verdict) — INTRA-TRANSACTION LINKED, in ONE transaction. The BLS counterpart of
// bch-pairing-intratx: the pairing chunks are the INPUTS of a single transaction;
// each chunk carries its incoming state as a raw 48-byte-limb blob and forward-checks
// its successor via tx.inputs[idx+1].unlockingBytecode (OP_INPUTBYTECODE) — no NFT-
// commitment hand-off, no hashing. The easy-part inverse rides as an uncommitted
// witness. Same chunk math as the multi-tx bch-pairing-bls12381-chunked.
//
// Vectors: groth16_contract/chunked/intratx/build_vectors_bls.mjs ->
// src/bch/pairing-bls12381-intratx-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/pairing-bls12381-intratx-vectors.json', 'utf8')) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((s) => ({ lockingBytecode: hexToBin(s.locking), unlockingBytecode: hexToBin(s.unlocking) }));
  return raw.map((s, i) => ({ label: s.label, lockingBytecode: inputs[i]!.lockingBytecode, unlockingBytecode: inputs[i]!.unlockingBytecode, checkpoint: s.checkpoint, intraTx: { index: i, inputs } }));
};

export const bchPairingBls12381Intratx: Implementation = {
  id: 'bch-pairing-bls12381-intratx',
  name: 'BCH BLS12-381 Groth16 pairing intra-tx linked (one transaction, BCH-compatible)',
  proofSystem: 'Groth16 pairing (BCH-native)',
  field: 'BLS12-381',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the BLS12-381 Groth16 pairing (batched 4-pair optimal-ate ' +
    'Miller -> final exponentiation -> verdict == Fp12 ONE) computed as the INPUTS of ONE ' +
    'transaction. Each chunk carries its incoming state as a raw 48-byte-limb blob and ' +
    'binds the chain by forward-checking its successor via tx.inputs[idx+1].' +
    'unlockingBytecode introspection (OP_INPUTBYTECODE) — no NFT commitment, no hashing. ' +
    'The easy-part inverse rides as an uncommitted witness. Every input fits one BCH ' +
    'budget; the whole pairing is one non-standard (<1 MB) transaction. Same chunk math ' +
    'as bch-pairing-bls12381-chunked. Deployed as P2SH so each chunk\'s redeem rides ' +
    'in the scriptSig, where it counts toward the op-cost budget and offsets the pad ' +
    '(~27% fewer on-chain bytes than bare-script).',
  load: async () => ({
    valid: toRun(v.steps),
    extraValidProofs: (v.extraValidProofs ?? []).map(toRun),
    worstCaseProof: v.worstCaseProof ? toRun(v.worstCaseProof) : undefined,
    invalid: (v.invalid ?? []).map(toRun),
  }),
};
