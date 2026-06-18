// Run a real BN254 field multiplication (x * y) mod p on libauth's BCH 2026 VM.
// Demonstrates that the BCH VM does native big-integer field arithmetic, and
// reports the operation-cost metrics for the step, under both the real BCH 2026
// consensus limits and a loosened ("limits removed") configuration.
import {
  bigIntToVmNumber,
  binToHex,
  ConsensusBch2025,
  createInstructionSetBch2026,
  createTestAuthenticationProgramBch,
  createVirtualMachine,
  createVirtualMachineBch2026,
  OpcodesBch,
  ripemd160,
  secp256k1,
  sha1,
  sha256,
} from '@bitauth/libauth';

// BN254 / alt_bn128 base field prime (same constant as BN256.cash).
const p =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const x = 11111111111111111111111111111111111111111111111111111111111111111111111n;
const y = 22222222222222222222222222222222222222222222222222222222222222222222222n;
const expected = (x * y) % p;

// Minimal data push for a VM number value (handles our <=75 byte operands).
const pushNum = (value: bigint): number[] => {
  const data = bigIntToVmNumber(value);
  return [data.length, ...data];
};
const op = (code: number): number[] => [code];

// Script: <x> <y> OP_MUL <p> OP_MOD <expected> OP_EQUAL
const lockingBytecode = Uint8Array.from([
  ...pushNum(x),
  ...pushNum(y),
  ...op(OpcodesBch.OP_MUL),
  ...pushNum(p),
  ...op(OpcodesBch.OP_MOD),
  ...pushNum(expected),
  ...op(OpcodesBch.OP_EQUAL),
]);

// Reconstruct ConsensusBch2026 (= ConsensusBch2025 + the 2026 overrides), since
// the package does not re-export it by name, then inflate every resource ceiling
// to model "the BCH VM without the limits".
const consensusBch2026 = {
  ...ConsensusBch2025,
  baseInstructionCost: 100,
  maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: 1000,
  maximumStandardLockingBytecodeLength: 201,
  maximumStandardUnlockingBytecodeLength: 10000,
  maximumTokenCommitmentLength: 128,
};

const HUGE = Number.MAX_SAFE_INTEGER;
const loosenedConsensus = {
  ...consensusBch2026,
  operationCostBudgetPerByte: HUGE,
  maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE,
  maximumControlStackDepth: HUGE,
  maximumMemorySlots: HUGE,
  maximumBytecodeLength: HUGE,
};

type Vm = ReturnType<typeof createVirtualMachineBch2026>;

const run = (label: string, vm: Vm): void => {
  const program = createTestAuthenticationProgramBch({
    lockingBytecode,
    unlockingBytecode: Uint8Array.of(),
    valueSatoshis: 10000n,
  });
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const isTrue = top !== undefined && top.length === 1 && top[0] === 1;
  console.log(`\n=== ${label} ===`);
  console.log('error:        ', state.error ?? '(none)');
  console.log('stack depth:  ', state.stack.length);
  console.log('top of stack: ', top === undefined ? '(empty)' : binToHex(top));
  console.log('OP_EQUAL true:', isTrue);
  console.log('metrics:      ', state.metrics);
};

console.log('p        =', p.toString());
console.log('expected =', expected.toString());
console.log('locking bytecode bytes:', lockingBytecode.length);

run('default BCH 2026 consensus', createVirtualMachineBch2026(false));
run(
  'loosened consensus (limits removed)',
  createVirtualMachine(
    createInstructionSetBch2026(false, {
      consensus: loosenedConsensus,
      ripemd160,
      secp256k1,
      sha1,
      sha256,
    }),
  ),
);
