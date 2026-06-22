// BCH-native Groth16 PAIRING (Miller boundary) — INTRA-TRANSACTION LINKED. The
// batched 4-pair optimal-ate Miller loop to the pre-final-exponentiation boundary
//   e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta)   (an Fp12)
// computed as the INPUTS of ONE transaction. Each Miller chunk takes its incoming
// (f in Fp12 + the 4 running G2 points + the pair points) as a raw byte blob, and
// forward-checks its successor by reading tx.inputs[idx+1].unlockingBytecode
// (OP_INPUTBYTECODE) and require()-ing it equals the recomputed outgoing blob — no
// NFT-commitment hand-off, no hashing. Single-transaction counterpart of the multi-tx
// bch-pairing-chunked (same chunk math) and the non-deployable bch-pairing-singleton.
//
// Vectors: groth16_contract/chunked/intratx/build_vectors.mjs ->
// src/bch/pairing-intratx-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/pairing-intratx-vectors.json', 'utf8')) as Vectors;

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

export const bchPairingIntratx: Implementation = {
  id: 'bch-pairing-intratx',
  name: 'BCH Groth16 pairing intra-tx linked (Miller boundary in one transaction, BCH-compatible)',
  proofSystem: 'Groth16 pairing (BCH-native)',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the BN254 Groth16 Miller boundary computed as the INPUTS of ' +
    'ONE transaction. Each batched-Miller chunk carries its incoming state (f in Fp12 + ' +
    '4 running G2 points + pair points) as a raw byte blob and binds the chain by ' +
    'forward-checking its successor via tx.inputs[idx+1].unlockingBytecode introspection ' +
    '(OP_INPUTBYTECODE) — no NFT commitment, no hashing, no 128-byte state limit. Every ' +
    'input fits one BCH budget (op-cost <=8,032,800, <=10,000 B); the whole boundary is ' +
    'one non-standard (<1 MB) transaction. Same chunk math as bch-pairing-chunked. ' +
    'Deployed as P2SH so each chunk\'s redeem rides in the scriptSig, where it counts ' +
    'toward the op-cost budget and offsets the pad (~30% fewer on-chain bytes than ' +
    'bare-script). Reaches the miller-boundary checkpoint (full verdict: bch-groth16-intratx).',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
