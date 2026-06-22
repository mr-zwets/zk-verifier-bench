// BCH-native Groth16 verifier — INTRA-TRANSACTION LINKED, the whole computation in
// ONE transaction. Instead of the multi-tx covenant (bch-groth16-chunked), which
// chains ~60 transactions and hands state forward through an NFT commitment
// (hash256 of the state, re-provided and re-hashed every step, capped at 128 bytes),
// this lays the SAME chunked computation out as the INPUTS of a single transaction.
//
// Each chunk takes its incoming state as a raw byte blob in its own witness, recomputes
// the outgoing state, and FORWARD-checks its successor: it require()s that the next
// input's incoming blob — read directly via tx.inputs[idx+1].unlockingBytecode
// (OP_INPUTBYTECODE) — equals its recomputed output. That is exactly the "verify
// arg01 == arg10" idea: sibling inputs read each other's arguments. No hashing, no
// token commitment, and intermediate values are arbitrary size. Cross-stage soundness
// links are bound where layouts allow (vk_x into the Miller genesis input; the Miller
// boundary into the final-exponentiation genesis input).
//
// Result: ~60 inputs, each independently fitting one BCH input's op-cost budget
// (<=8,032,800) and 10,000-byte script cap, packed into one non-standard transaction
// (<1 MB). The reused chunk math is identical to bch-groth16-chunked.
//
// Vectors: groth16_contract/chunked/intratx/build_vectors.mjs ->
// src/bch/groth16-intratx-vectors.json.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-intratx-vectors.json', 'utf8')) as Vectors;

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

export const bchGroth16Intratx: Implementation = {
  id: 'bch-groth16-intratx',
  name: 'BCH Groth16 intra-tx linked (whole verifier in one transaction, BCH-compatible)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: the full BN254 Groth16 verifier (validate G2 inputs -> vk_x ' +
    '-> batched 4-pair optimal-ate Miller -> final exponentiation -> assert product==1) ' +
    'laid out as the INPUTS of ONE transaction. Each input carries its incoming state as ' +
    'a raw byte blob and binds the chain by forward-checking its successor via ' +
    'tx.inputs[idx+1].unlockingBytecode introspection (OP_INPUTBYTECODE) — no NFT-' +
    'commitment hand-off, no hashing, no 128-byte state limit, arbitrary intermediate ' +
    'size. Every input fits one BCH input budget (op-cost <=8,032,800, scripts ' +
    '<=10,000 B); the whole verifier is one non-standard (<1 MB) transaction. Same ' +
    'chunk math as bch-groth16-chunked; one fixed set of input scripts verifies any ' +
    'proof for the VK (proof in the witness). Single-transaction counterpart of the ' +
    'multi-tx bch-groth16-chunked and the non-deployable bch-groth16-singleton. ' +
    'Deployed as P2SH so each chunk\'s redeem rides in the scriptSig, where it counts ' +
    'toward the op-cost budget and offsets the pad (~30% fewer on-chain bytes than a ' +
    'bare-script deployment; the same lever applies to the multi-tx covenant chunks).',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
