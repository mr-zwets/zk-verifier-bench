// A benchmarkable verifier implementation. The unit of execution is a Step (one
// locking + unlocking pair = one transaction's script evaluation). A single-tx
// verifier is one Step; a multi-tx verifier (BCH's split-across-transactions
// approach, or any covenant that carries state forward) is an ordered list of
// Steps. Implementations are grouped into separate leaderboards by
// (proofSystem, structure).
export type Structure = 'single-tx' | 'multi-tx';

export interface Step {
  label: string;
  /** the verifier program for this step (its opcode list, as bytecode) */
  lockingBytecode: Uint8Array;
  /** the witness for this step (proof data / carried state), push-only */
  unlockingBytecode: Uint8Array;
}

/** A valid run (all steps must be accepted) plus optional invalid runs (each must fail). */
export interface Scenario {
  valid: Step[];
  /** explicit invalid runs; each is a full step list that must fail at some step */
  invalid?: Step[][];
  /** if true, the harness derives invalid runs by bit-flipping each step's witness */
  tamperable?: boolean;
  /**
   * Size-only: do not execute. For verifiers we cannot run in a synthetic context
   * (e.g. transaction-introspection covenants), report sizes and size-based BCH
   * compatibility (each step's scripts <= the 10,000-byte cap) without execution.
   */
  profileOnly?: boolean;
  /**
   * The verifier was built for BSV's post-Genesis OP_RETURN terminator (success =
   * single non-zero stack item at an executed OP_RETURN). Judge its correctness by
   * that rule on the loosened VM. The real-VM `bchCompatible` check stays strict
   * (an executed OP_RETURN fails on BCH), so this only affects the correctness
   * column, not the BCH verdict.
   */
  bsvOpReturnTerminator?: boolean;
}

export interface Implementation {
  id: string;
  name: string;
  /** "Groth16" | "Circle-STARK" | ... (defines the leaderboard) */
  proofSystem: string;
  /** curve or field, e.g. "BLS12-381", "BN254", "M31", or "-" */
  field: string;
  structure: Structure;
  source: string;
  load: () => Promise<Scenario>;
}

export interface StepMetrics {
  label: string;
  lockingBytes: number;
  unlockingBytes: number;
  operationCost: number;
  instructionCount: number;
  accepted: boolean;
  error: string | undefined;
}

export interface BenchmarkResult {
  impl: Implementation;
  /** size-only entry: not executed (sizes + size-based BCH compat only) */
  profileOnly: boolean;
  /** invalid runs were available, so rejection was actually tested */
  checked: boolean;
  validPassed: boolean;
  invalidRejected: number;
  invalidTotal: number;
  pass: boolean;
  /** correctness was judged under the BSV post-Genesis OP_RETURN-terminator rule
   * (the valid run halts at a reachable OP_RETURN, which fails on strict BCH) */
  bsvOpReturn: boolean;
  steps: StepMetrics[];
  stepCount: number;
  totalBytes: number;
  totalOperationCost: number;
  maxStepOperationCost: number;
  /** every step's op-cost fits one standard BCH input's budget */
  fitsStandardBudget: boolean;
  /** ceil(maxStepOpCost / standard budget): inputs the heaviest step needs */
  inputsForHeaviestStep: number;
  /** every step of the valid run validates on the REAL BCH 2026 VM (consensus limits) */
  bchCompatible: boolean;
  /** short reason the first incompatible step failed on the real VM */
  bchIncompatibleReason?: string;
  error?: string;
}
