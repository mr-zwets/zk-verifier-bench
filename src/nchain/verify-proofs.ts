// Run the real nChain BSV Groth16 verifier as a verification program: feed it a
// valid proof (the genuine mainnet witness) and tampered/invalid proofs, and show
// it accepts the first and rejects the rest. Uses the BCH 2026 VM with limits
// loosened. No tx-context opcodes are used by the verifier (no CHECKSIG/hashing),
// so a synthetic locking/unlocking pair evaluates identically to the real spend.
import { readFileSync } from 'node:fs';
import {
  ConsensusBch2025,
  createInstructionSetBch2026,
  createTestAuthenticationProgramBch,
  createVirtualMachine,
  decodeTransactionBch,
  hexToBin,
  ripemd160,
  secp256k1,
  sha1,
  sha256,
} from '@bitauth/libauth';

const decode = (path: string) => {
  const tx = decodeTransactionBch(hexToBin(readFileSync(path, 'utf8').trim()));
  if (typeof tx === 'string') throw new Error(`decode ${path}: ${tx}`);
  return tx;
};

const verifier = decode('data/nchain/parent-tx.hex').outputs[0]!.lockingBytecode;
const realProof = decode('data/nchain/spending-tx.hex').inputs[0]!.unlockingBytecode;

// Walk a push-only script and return the [start,end) byte ranges of each data
// push payload (opcodes 0x01..0x4e). Lets us corrupt a real field element.
const dataPushRanges = (script: Uint8Array): Array<[number, number]> => {
  const ranges: Array<[number, number]> = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i]!;
    i += 1;
    let len = 0;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === 0x4c) { len = script[i]!; i += 1; }
    else if (op === 0x4d) { len = script[i]! | (script[i + 1]! << 8); i += 2; }
    else if (op === 0x4e) { len = script[i]! | (script[i + 1]! << 8) | (script[i + 2]! << 16) | (script[i + 3]! << 24); i += 4; }
    else continue; // OP_0 / OP_1..OP_16 / OP_1NEGATE: no payload
    if (len > 0) ranges.push([i, i + len]);
    i += len;
  }
  return ranges;
};

// Flip one byte inside the nth-largest data push.
const tamper = (script: Uint8Array, pick: number): Uint8Array => {
  const ranges = dataPushRanges(script).sort((a, b) => b[1] - b[0] - (a[1] - a[0]));
  const [start, end] = ranges[pick]!;
  const copy = script.slice();
  const at = start + Math.floor((end - start) / 2);
  copy[at]! ^= 0x01; // flip the low bit of a middle byte
  return copy;
};

const HUGE = Number.MAX_SAFE_INTEGER;
const vm = createVirtualMachine(
  createInstructionSetBch2026(false, {
    consensus: {
      ...ConsensusBch2025,
      baseInstructionCost: 100,
      maximumFunctionIdentifierLength: 7,
      maximumMemorySlots: HUGE,
      maximumStandardLockingBytecodeLength: -1,
      maximumStandardUnlockingBytecodeLength: HUGE,
      maximumTokenCommitmentLength: 128,
      operationCostBudgetPerByte: HUGE,
      maximumStackItemLength: HUGE,
      maximumVmNumberByteLength: HUGE,
      maximumStackDepth: HUGE,
      maximumControlStackDepth: HUGE,
      maximumBytecodeLength: HUGE,
      maximumOperationCount: HUGE,
    },
    ripemd160,
    secp256k1,
    sha1,
    sha256,
  }),
);

const check = (label: string, unlockingBytecode: Uint8Array) => {
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: verifier,
    unlockingBytecode,
    valueSatoshis: 668842n,
  });
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  console.log(`${accepted ? 'ACCEPT' : 'REJECT'}  ${label}`);
  if (!accepted) {
    console.log(`        reason: ${state.error ?? `final stack depth ${state.stack.length}, top = ${top === undefined ? '(empty)' : [...top].join(',')}`}`);
  }
  return accepted;
};

console.log('Groth16 verifier (BLS12-381), real mainnet proof vs tampered proofs:\n');
check('genuine mainnet proof', realProof);
check('proof with 1 bit flipped in largest field element', tamper(realProof, 0));
check('proof with 1 bit flipped in 2nd-largest field element', tamper(realProof, 1));
check('proof with 1 bit flipped in 5th-largest field element', tamper(realProof, 4));
