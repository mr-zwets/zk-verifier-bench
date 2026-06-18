// Execute the real nChain BSV Groth16 verifier in libauth's BCH 2026 VM, with
// the resource limits loosened ("BCH VM without the limits"). Replays the actual
// mainnet spend: spending tx e4cd...514c, input 0, against parent output 79a5...4940:0.
import { readFileSync } from 'node:fs';
import {
  ConsensusBch2025,
  createInstructionSetBch2026,
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

const parent = decode('data/nchain/parent-tx.hex');
const spending = decode('data/nchain/spending-tx.hex');
const sourceOutput = parent.outputs[0]!;

const HUGE = Number.MAX_SAFE_INTEGER;
const loosenedConsensus = {
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
};

const vm = createVirtualMachine(
  createInstructionSetBch2026(false, {
    consensus: loosenedConsensus,
    ripemd160,
    secp256k1,
    sha1,
    sha256,
  }),
);

const program = { inputIndex: 0, sourceOutputs: [sourceOutput], transaction: spending };

console.log('verifier locking bytecode bytes:', sourceOutput.lockingBytecode.length.toLocaleString());
console.log('proof unlocking bytecode bytes :', spending.inputs[0]!.unlockingBytecode.length.toLocaleString());
console.log('evaluating real mainnet spend under loosened BCH 2026 limits...\n');

const t0 = process.hrtime.bigint();
const state = vm.evaluate(program);
const verifyResult = vm.verify(program);
const ms = Number(process.hrtime.bigint() - t0) / 1e6;

const top = state.stack[state.stack.length - 1];
console.log('evaluate() error:', state.error ?? '(none)');
console.log('final stack depth:', state.stack.length);
console.log('top of stack:', top === undefined ? '(empty)' : `len ${top.length} = ${top.length <= 4 ? [...top].join(',') : '...'}`);
console.log('verify() result :', verifyResult === true ? 'TRUE (valid spend)' : verifyResult);
console.log(`wall time: ${ms.toFixed(0)} ms`);
console.log('\nmetrics:', state.metrics);
