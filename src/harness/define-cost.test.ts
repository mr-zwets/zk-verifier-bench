// Guard for patches/@bitauth__libauth@3.1.0-next.8.patch: OP_DEFINE must charge its function body
// as stack-pushed bytes (CHIP-2025-05 Functions, OP_DEFINE clarification 4; BCHN interpreter.cpp
// `metrics.TallyPushOp`). libauth 3.1.0-next.8 does not (bitauth/libauth#166). This fails if the patch
// is missing, and also if a fixed libauth plus the patch charges the body twice: then drop the patch.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createTestAuthenticationProgramBch,
  createVirtualMachineBch2026,
  createVirtualMachineBchSpec,
  encodeDataPush,
  flattenBinArray,
} from '@bitauth/libauth';

const OP_1 = 0x51;
const OP_DEFINE = 0x89;

// <body of k bytes> <0x01> OP_DEFINE OP_1
type Vm = {
  evaluate: (program: ReturnType<typeof createTestAuthenticationProgramBch>) => {
    error?: string;
    metrics: { operationCost: number };
  };
};
const opCost = (vm: Vm, k: number) => {
  const lockingBytecode = flattenBinArray([
    encodeDataPush(new Uint8Array(k).fill(0x61)), // OP_NOP bytes: a valid body
    Uint8Array.of(OP_1, OP_DEFINE, OP_1),
  ]);
  const program = createTestAuthenticationProgramBch({
    lockingBytecode,
    unlockingBytecode: Uint8Array.of(),
    valueSatoshis: 1000n,
  });
  const state = vm.evaluate(program);
  assert.equal(state.error, undefined, `k=${k}: ${state.error}`);
  return state.metrics.operationCost;
};

for (const [name, make] of [
  ['BCH 2026', (): Vm => createVirtualMachineBch2026(false)],
  ['BCH 2026 standard', (): Vm => createVirtualMachineBch2026(true)],
  ['bch-spec', (): Vm => createVirtualMachineBchSpec(false)],
] as const) {
  test(`${name}: OP_DEFINE charges its body once`, () => {
    const vm = make();
    // 100 more body bytes: +100 for the push, +100 for OP_DEFINE's body charge.
    assert.equal(opCost(vm, 200) - opCost(vm, 100), 200);
  });
}
