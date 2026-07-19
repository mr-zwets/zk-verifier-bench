// BCH-native BN254 Groth16 verifier — crown8 raw-chain submission vectors.
//
// Bytecode provenance (sha256):
//   exec[0..5] ddc0ffe8267dd847032d4d7d72962fb0c5ed6e96f6d9b1365233615c91d3462a
//   genesis     b746bd7ad5067ca597bc01d0641123cb5f7b07bebbb1247c08297f9219b52d57
//   terminal    41954608e9a737bdac049b3c4f64ac230f59de7e6f6a567f23cbf561af20b3c8
//
// Construction: eight P2SH32 inputs in one transaction. Inputs 0..5 consume
// and bind successive raw Miller-chain records through sibling unlocking-bytecode
// introspection; genesis and terminal bind the proof-root and final pairing state.
// The published vectors contain three distinct accepted proofs against the exact
// same lock vector, a separately selected highest-op corpus proof, and nine targeted
// bit-flip plans spanning each raw-chain executor plus the genesis/terminal roots.
// Corpus provenance is pinned in the JSON artifact; the benchmark's stock 1000-sat,
// sequence-0 intra-tx envelope is the deployment context used by these scripts.
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

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = inputsOf(raw);
  return inputs.map((input, index) => ({
    label: raw[index]!.name,
    lockingBytecode: input.lockingBytecode,
    unlockingBytecode: input.unlockingBytecode,
    checkpoint: index === 0 ? 'miller-start' : index === 5 ? 'miller-boundary' : index === 6 ? 'proof-root' : index === 7 ? 'terminal-close' : undefined,
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
  checkpoint: index === 0 ? 'miller-start' : index === 5 ? 'miller-boundary' : index === 6 ? 'proof-root' : index === 7 ? 'terminal-close' : undefined,
  intraTx: { index, inputs },
}));

const mutate = (mutation: Mutation): Step[] => {
  const inputs = copyInputs(vectors.valid);
  if (mutation.kind === 'executor-rawchain-bit') {
    if (mutation.input < 0 || mutation.input > 5) throw new Error('raw-chain mutation must target executor 0..5');
    const record = dataPushes(inputs[mutation.input]!.unlockingBytecode)[2];
    if (record === undefined || ![576, 768, 602, 826].includes(record.length)) throw new Error('raw-chain record ABI drift');
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
