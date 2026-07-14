// BCH-native Groth16 verifier — intra-transaction, authenticated P2S dispatcher.
//
// Same 46-input BN254 Groth16 intra-tx verifier as bch-groth16-intratx (byte-identical
// unlocking bytecodes, same successor links), but each stage's 35-byte P2SH32 locking
// is replaced by a 44-byte bare (P2S — pay-to-script, NOT P2SH) dispatcher:
//
//   OP_DUP OP_HASH256 <hash256(stage body)> OP_EQUALVERIFY
//   <999> OP_DEFINE <999> OP_INVOKE
//
// The stage body stays as the final push of the unlocking — ordinary authenticated
// data instead of a P2SH redeem script. The dispatcher hash-checks the exact body
// before defining and invoking it, so modified bodies and valid bodies from other
// stages are rejected. Identifier 999 is reserved for the dispatcher; bodies define
// 0..24, and OP_DEFINE errors on redefinition. Bare lockings ≤201 bytes are
// relay-standard on BCH, so the 44-byte dispatcher is standard.
//
// Standalone this only emulates P2SH32 semantics at +9 bytes per input — NOT a size
// improvement. Its value is that the pattern is ordinary bytecode, so it can be
// embedded inside larger scripts (P2SH authentication only exists as the whole
// top-level locking pattern).
//
// Vectors: tools/derive-groth16-intratx-authenticated-p2s.mts ->
// src/bch/groth16-intratx-authenticated-p2s-vectors.json
// (derived from src/bch/groth16-intratx-vectors.json).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep { label: string; locking: string; unlocking: string; checkpoint?: string }
interface Vectors { steps: RawStep[]; extraValidProofs?: RawStep[][]; worstCaseProof?: RawStep[]; invalid?: RawStep[][] }

const v = JSON.parse(readFileSync('src/bch/groth16-intratx-authenticated-p2s-vectors.json', 'utf8')) as Vectors;

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

export const bchGroth16IntratxAuthenticatedP2s: Implementation = {
  id: 'bch-groth16-intratx-authenticated-p2s',
  name: 'BCH Groth16 intra-tx, authenticated P2S dispatcher (embeddable-pattern prototype)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'Authenticated P2S (bare/pay-to-script, not P2SH) dispatcher variant of the 46-input ' +
    'BN254 Groth16 intra-transaction verifier. Each original 35-byte P2SH32 locking is ' +
    'replaced by a 44-byte bare dispatcher — OP_DUP OP_HASH256 <hash256(body)> ' +
    'OP_EQUALVERIFY <999> OP_DEFINE <999> OP_INVOKE — that authenticates the stage body ' +
    '(still the final push of the byte-identical unlocking, now ordinary data rather ' +
    'than a P2SH redeem script) before invoking it. Modified bodies and valid bodies ' +
    'from other stages are rejected at the hash check. Bare lockings <=201 bytes are ' +
    'relay-standard. Standalone this only emulates P2SH32 semantics at +9 bytes per ' +
    'input — not a size improvement; the point is that the pattern is ordinary bytecode ' +
    'and therefore embeddable inside larger scripts, where P2SH authentication cannot go.',
  load: async () => {
    const valid = toRun(v.steps);
    const extraValidProofs = (v.extraValidProofs ?? []).map(toRun);
    const worstCaseProof = v.worstCaseProof ? toRun(v.worstCaseProof) : undefined;
    const invalid = (v.invalid ?? []).map(toRun);
    return { valid, extraValidProofs, worstCaseProof, invalid };
  },
};
