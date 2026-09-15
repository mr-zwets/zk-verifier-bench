// BCH-native BN254 Groth16 verifier — crown8 raw-chain submission vectors.
//
// Bytecode provenance (sha256):
//   exec[0..5] bc890390772483cfc243f36096d877b7a57c91756c95b12f787f2a07cc563c45
//   genesis     ed9f2d96efea8ed93f145cefe542effd4b763ce475a8cb26a5d37535b13924b1
//   terminal    b32a0dfb3d819177d813a8829e5b4f44a1851dee5d577f6b6e665c285d2636e6
//
// Construction: eight P2SH32 inputs in one transaction. Inputs 0..5 consume
// and bind successive raw Miller-chain records through sibling unlocking-bytecode
// introspection; genesis and terminal bind the proof-root and final pairing state.
// The published vectors contain three distinct accepted proofs against the exact
// same lock vector, a separately selected highest-op corpus proof, and nine targeted
// bit-flip plans spanning each raw-chain executor plus the genesis/terminal roots.
// Corpus provenance is pinned in the JSON artifact; the benchmark's stock 1000-sat,
// sequence-0 intra-tx envelope is the deployment context used by these scripts.
//
// Size roadmap (mutation #1 — Miller rebalance): padBytes is already 0; the next
// lever is moving ~1.13M op-cost from wall-bound exec0/1/4 into under-full exec2,
// then shrinking donor unlocks. Expected mid-case savings ~1.2–1.4 KB. Plan +
// checker: tools/crown8-rebalance-plan.mts (requires regenerating the six exec
// programs from the private crown8 builder — not a pure JSON patch).
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  name: string;
  lock: string;
  unlock: string;
}

interface Mutation {
  kind: 'executor-rawchain-bit' | 'terminal-root-prefix-bit' | 'terminal-bq-bit' | 'genesis-cblob-bit';
  input: number;
}

interface Vectors {
  valid: RawStep[];
  extraValidProofs: RawStep[][];
  worstCaseProof: RawStep[];
  invalidMutations: Mutation[];
}

interface Input {
  lockingBytecode: Uint8Array;
  unlockingBytecode: Uint8Array;
}

const vectors = JSON.parse(
  readFileSync('src/bch/groth16-intratx-crown8-rawchain-vectors.json', 'utf8'),
) as Vectors;

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index]);

const inputsOf = (raw: RawStep[]): Input[] => {
  if (raw.length !== 8) throw new Error('crown8 vectors must contain exactly eight inputs');
  return raw.map((step) => ({
    lockingBytecode: hexToBin(step.lock),
    unlockingBytecode: hexToBin(step.unlock),
  }));
};

/**
 * Dense stage labels for the crown8 pipeline so the harness reports a full
 * cumulative op-cost + byte profile (not just the four sparse milestones).
 *
 *   0 exec0     miller-start         first raw Miller-chain executor
 *   1 exec1     miller-iter-group-1  intermediate Miller iteration group
 *   2 exec2     miller-iter-group-2
 *   3 exec3     miller-iter-group-3
 *   4 exec4     miller-iter-group-4
 *   5 exec5     miller-boundary      last Miller executor (pre-finalExp product)
 *   6 genesis   proof-root           proof-root / cBlob binding
 *   7 terminal  terminal-close       final pairing / residue close
 */
const checkpointOf = (index: number): string => {
  switch (index) {
    case 0: return 'miller-start';
    case 1: return 'miller-iter-group-1';
    case 2: return 'miller-iter-group-2';
    case 3: return 'miller-iter-group-3';
    case 4: return 'miller-iter-group-4';
    case 5: return 'miller-boundary';
    case 6: return 'proof-root';
    case 7: return 'terminal-close';
    default: throw new Error(`crown8 checkpoint index out of range: ${index}`);
  }
};

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = inputsOf(raw);
  return inputs.map((input, index) => ({
    label: raw[index]!.name,
    lockingBytecode: input.lockingBytecode,
    unlockingBytecode: input.unlockingBytecode,
    checkpoint: checkpointOf(index),
    intraTx: { index, inputs },
  }));
};

const dataPushes = (script: Uint8Array): Array<{ start: number; length: number }> => {
  const pushes: Array<{ start: number; length: number }> = [];
  for (let at = 0; at < script.length;) {
    const opcode = script[at++]!;
    if (opcode === 0 || (opcode >= 0x4f && opcode <= 0x60)) continue;
    let length: number;
    if (opcode <= 75) length = opcode;
    else if (opcode === 0x4c) length = script[at++]!;
    else if (opcode === 0x4d) { length = script[at]! | (script[at + 1]! << 8); at += 2; }
    else if (opcode === 0x4e) {
      length = (script[at]! | (script[at + 1]! << 8) | (script[at + 2]! << 16) | (script[at + 3]! << 24)) >>> 0;
      at += 4;
    } else {
      throw new Error('non-push opcode in crown8 unlocking');
    }
    if (at + length > script.length) throw new Error('truncated crown8 unlocking push');
    pushes.push({ start: at, length });
    at += length;
  }
  return pushes;
};

const copyInputs = (raw: RawStep[]): Input[] =>
  inputsOf(raw).map(({ lockingBytecode, unlockingBytecode }) => ({
    lockingBytecode,
    unlockingBytecode: Uint8Array.from(unlockingBytecode),
  }));

const runFromInputs = (inputs: Input[]): Step[] => inputs.map((input, index) => ({
  label: vectors.valid[index]!.name,
  lockingBytecode: input.lockingBytecode,
  unlockingBytecode: input.unlockingBytecode,
  checkpoint: checkpointOf(index),
  intraTx: { index, inputs },
}));

const mutate = (mutation: Mutation): Step[] => {
  const inputs = copyInputs(vectors.valid);
  if (mutation.kind === 'executor-rawchain-bit') {
    if (mutation.input < 0 || mutation.input > 5) throw new Error('raw-chain mutation must target executor 0..5');
    const record = dataPushes(inputs[mutation.input]!.unlockingBytecode)[2];
    if (record === undefined || ![576, 768].includes(record.length)) throw new Error('raw-chain record ABI drift');
    inputs[mutation.input]!.unlockingBytecode[record.start + record.length - 384]! ^= 1;
  } else if (mutation.kind === 'terminal-root-prefix-bit') {
    const prefix = dataPushes(inputs[7]!.unlockingBytecode)[2];
    if (mutation.input !== 7 || prefix === undefined || prefix.length !== 80) throw new Error('terminal root-prefix ABI drift');
    inputs[7]!.unlockingBytecode[prefix.start]! ^= 1;
  } else if (mutation.kind === 'terminal-bq-bit') {
    const bq = dataPushes(inputs[7]!.unlockingBytecode)[1];
    if (mutation.input !== 7 || bq === undefined || bq.length !== 103 * 32) throw new Error('terminal bq ABI drift');
    inputs[7]!.unlockingBytecode[bq.start + Math.floor(bq.length / 2)]! ^= 1;
  } else {
    const cBlob = dataPushes(inputs[6]!.unlockingBytecode)[0];
    if (mutation.input !== 6 || cBlob === undefined || cBlob.length !== 24 * 32) throw new Error('genesis cBlob ABI drift');
    inputs[6]!.unlockingBytecode[cBlob.start + Math.floor(cBlob.length / 2)]! ^= 1;
  }
  return runFromInputs(inputs);
};

const assertLockInvariant = (): void => {
  const base = inputsOf(vectors.valid);
  for (const run of [...vectors.extraValidProofs, vectors.worstCaseProof]) {
    const candidate = inputsOf(run);
    if (candidate.some((input, index) => !sameBytes(input.lockingBytecode, base[index]!.lockingBytecode))) {
      throw new Error('runtime proof vector changed a crown8 locking bytecode');
    }
  }
};

export const bchGroth16IntratxCrown8Rawchain: Implementation = {
  id: 'bch-groth16-intratx-crown8-rawchain',
  name: 'BCH BN254 Groth16 crown8 raw-chain',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source: 'Eight-input P2SH32 BN254 Groth16 verifier with sibling-bytecode-bound raw Miller-chain records; corpus-pinned runtime vectors and targeted witness tamper plans.',
  load: async () => {
    assertLockInvariant();
    return {
      valid: toRun(vectors.valid),
      extraValidProofs: vectors.extraValidProofs.map(toRun),
      worstCaseProof: toRun(vectors.worstCaseProof),
      invalid: vectors.invalidMutations.map(mutate),
    };
  },
};
