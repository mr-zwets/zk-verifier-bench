// Shared BCH 2026 VM with resource limits loosened ("the BCH VM without the
// limits"), plus helpers to evaluate a locking/unlocking pair and to reason
// about the real BCH op-cost budget. Used by the benchmark harness and the
// per-implementation scripts.
import {
  ConsensusBch2025,
  createInstructionSetBch2026,
  createTestAuthenticationProgramBch,
  createVirtualMachine,
  createVirtualMachineBch2026,
  ripemd160,
  secp256k1,
  sha1,
  sha256,
} from '@bitauth/libauth';

const HUGE = Number.MAX_SAFE_INTEGER;

/** ConsensusBch2026 (= 2025 + 2026 overrides) with every resource ceiling lifted. */
export const loosenedConsensusBch2026 = {
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

export const createLoosenedVm = () =>
  createVirtualMachine(
    createInstructionSetBch2026(false, {
      consensus: loosenedConsensusBch2026,
      ripemd160,
      secp256k1,
      sha1,
      sha256,
    }),
  );

/** Real BCH 2026 VM with normal consensus limits (non-standard mode). A script
 * that exceeds the op-cost budget, stack depth, etc. will NOT validate here. */
export const createRealVm = () => createVirtualMachineBch2026(false);

export type Bch2026Vm = ReturnType<typeof createLoosenedVm>;

export interface EvalOutcome {
  /** strict BCH acceptance: clean exit, single truthy item, no error */
  accepted: boolean;
  /**
   * BSV-semantics acceptance: exactly one non-zero stack item, reached either by
   * clean exit OR by halting at an OP_RETURN. Post-Genesis BSV (active since Feb
   * 2020) treats OP_RETURN as a terminator that succeeds iff the stack holds a
   * single non-zero item; BCH treats an executed OP_RETURN as failure. Lets us
   * judge a BSV verifier's correctness while keeping `accepted` as the strict BCH
   * verdict.
   */
  bsvAccepted: boolean;
  error: string | undefined;
  operationCost: number;
  instructionCount: number;
  arithmeticCost: number;
  stackPushedBytes: number;
}

const OP_RETURN_ERR = 'Program called an OP_RETURN operation.';
/** Bitcoin truthiness: non-empty, not all-zero (trailing 0x80 = negative zero is false). */
const isTruthy = (v: Uint8Array | undefined): boolean =>
  v !== undefined && v.length > 0 && !v.every((b, i) => b === 0 || (i === v.length - 1 && b === 0x80));

/** Evaluate unlocking + locking as a synthetic spend and report acceptance + metrics. */
export const evaluatePair = (
  vm: Bch2026Vm,
  lockingBytecode: Uint8Array,
  unlockingBytecode: Uint8Array,
): EvalOutcome => {
  const program = createTestAuthenticationProgramBch({
    lockingBytecode,
    unlockingBytecode,
    valueSatoshis: 1000n,
  });
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted =
    state.error === undefined &&
    state.stack.length === 1 &&
    top !== undefined &&
    top.length === 1 &&
    top[0] === 1;
  const bsvAccepted =
    state.stack.length === 1 && isTruthy(top) && (state.error === undefined || state.error === OP_RETURN_ERR);
  const m = state.metrics;
  return {
    accepted,
    bsvAccepted,
    error: state.error,
    operationCost: m.operationCost,
    instructionCount: m.evaluatedInstructionCount,
    arithmeticCost: m.arithmeticCost,
    stackPushedBytes: m.stackPushedBytes,
  };
};

// --- real BCH 2026 op-cost budget reasoning ---
const OP_COST_BUDGET_PER_BYTE = 800;
const DENSITY_CONTROL_BASE = 41;
/** Max standard P2SH unlocking bytecode length (the practical per-input wall). */
export const STANDARD_UNLOCKING_CAP = 10_000;

/** Op-cost budget a single BCH input grants for the given unlocking length. */
export const realOpCostBudget = (unlockingLen: number): number =>
  (DENSITY_CONTROL_BASE + unlockingLen) * OP_COST_BUDGET_PER_BYTE;

/** Budget of one input at the standard unlocking cap. */
export const standardInputBudget = (): number => realOpCostBudget(STANDARD_UNLOCKING_CAP);
