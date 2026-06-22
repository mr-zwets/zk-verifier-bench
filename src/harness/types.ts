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
  /**
   * If set, this step reaches a named milestone (e.g. "vk_x", "miller-boundary").
   * The benchmark records the cumulative op-cost and on-chain bytes to reach it,
   * so implementations can compete on the in-between metrics, not just the total.
   */
  checkpoint?: string;
  /**
   * Token-threading covenant context. When set, this step's program carries NO
   * baked state: the running state lives in the spent/created NFT commitment and
   * the locking enforces it by introspection, so one fixed program verifies ANY
   * proof. The harness drives the step through a synthetic token-carrying tx
   * (spent UTXO = inCommitment, output[0] = outCommitment under outLockingBytecode,
   * same category). All hex; the runner builds the transaction (see vm.evaluatePair).
   */
  covenant?: {
    category: Uint8Array;
    capability: 'none' | 'mutable' | 'minting';
    inCommitment: Uint8Array;
    outCommitment: Uint8Array;
    outLockingBytecode: Uint8Array;
  };
}

export interface CheckpointStat {
  label: string;
  /** 1-based step index at which the checkpoint is reached */
  atStep: number;
  /** cumulative op-cost of steps 1..atStep */
  cumulativeOpCost: number;
  /** cumulative locking+unlocking bytes of steps 1..atStep */
  cumulativeBytes: number;
}

/** A valid run (all steps must be accepted) plus optional invalid runs (each must fail). */
export interface Scenario {
  valid: Step[];
  /**
   * Additional INDEPENDENT valid runs, each a DISTINCT proof verified against the
   * SAME locking program(s) as `valid` (same step lockingBytecode, different
   * unlocking witness). A runtime-general verifier accepts all of them; a verifier
   * with the proof baked into its program accepts only the one it was built for.
   * The harness runs these to empirically grade proof-generality (see
   * Implementation.proofBinding). Each entry must be the same length as `valid`.
   */
  extraValidProofs?: Step[][];
  /**
   * A WORST-CASE proof run: the same fixed locking(s) as `valid`, but with dense,
   * near-r public inputs so a chunk-sized covenant pays for (nearly) every scalar
   * position. Op-cost is proof-size dependent for these verifiers — the chunk windows
   * are worst-case SIZED (so the step graph matches `valid`), but the measured op-cost
   * only reaches the worst case when a dense proof is actually RUN. The harness records
   * this run's op-cost separately (benchmarks.worstCase). Must be a valid, accepted run
   * (same length as `valid`); omit for proof-size-independent verifiers.
   */
  worstCaseProof?: Step[];
  /** explicit invalid runs; each is a full step list that must fail at some step */
  invalid?: Step[][];
  /**
   * Adversarial INPUT runs: well-formed witnesses that supply a structurally-invalid
   * curve point — a G1/G2 point off the curve, or a G2 point on-curve but OUTSIDE the
   * order-r subgroup. A verifier with EIP-197-style input validation (on-curve +
   * subgroup checks, like ecPairing) REJECTS all of these; one that feeds raw points
   * into the pairing may accept them. The harness runs them to empirically grade
   * input validation (BenchmarkResult.inputValidation). Each must be REJECTED.
   */
  invalidInputs?: Step[][];
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
  /**
   * Where the proof lives, which decides whether one deployed program verifies many
   * proofs or just one:
   *   'runtime' - the proof (A,B,C / public inputs) is supplied in the unlocking
   *               witness at spend time; one fixed locking verifies ANY valid proof
   *               for its VK. Runtime-general (nchain, scrypt, our singletons).
   *   'baked'   - the specific proof is compiled into the locking program (e.g. the
   *               chunked verifier bakes each step's state-commitments); a different
   *               proof needs the program regenerated. Instance-specific.
   * The harness reports this and, where `extraValidProofs` are provided, confirms it
   * empirically. Defaults to 'runtime' when omitted.
   */
  proofBinding?: 'runtime' | 'baked';
  /**
   * For a token-threading covenant entry (its steps carry `Step.covenant`): does the
   * covenant actually enforce TOKEN SAFETY, i.e. that the carried state token cannot
   * be swapped or forged across the thread? A safe deployment must either pin the
   * category and require a perpetuated MUTABLE (non-minting) commitment, or mint a
   * fresh IMMUTABLE token each step with the new commitment bound by the covenant.
   * That means introspecting and require()-ing, at minimum:
   *   - output[0].tokenCategory == input.tokenCategory   (category continuity)
   *   - the carried NFT capability stays mutable (never minting)
   *   - exactly one such token flows in -> out[0] (no injected sibling tokens)
   * The current PoC covenant enforces only the commitment transition, not the above,
   * so this defaults to FALSE for any token-threading entry. Set true only once the
   * covenant genuinely enforces it (and the harness exercises a category-swap /
   * capability-escalation rejection). Meaningless (null in results) for non-covenant
   * entries.
   */
  tokenSafetyEnforced?: boolean;
  /** the current reference implementation; others are compared against it */
  reference?: boolean;
  /** a toy demo, not a real verifier; kept in its own leaderboard but excluded
   * from the vs-reference comparison (its ratios would be meaningless) */
  demo?: boolean;
  /** a same-milestone comparison against a reference verifier (see Milestone) */
  milestone?: Milestone;
  load: () => Promise<Scenario>;
}

/**
 * A same-milestone comparison: this implementation reaches a named verifier
 * milestone, and the benchmark shows its op-cost next to a reference cost measured
 * in the same VM (where the monolithic reference reaches the same milestone). Raw
 * numbers only — no ratio unless `normalized`, since op-cost depends on scalar
 * width/popcount.
 */
export interface Milestone {
  name: string;
  /** this implementation's op-cost at the comparison scalar */
  thisOpCost: number;
  referenceOpCost: number;
  referenceSource: string;
  /** the scalar both sides are measured at (for a normalized comparison) */
  scalar?: string;
  /** confound to surface when NOT normalized */
  caveat?: string;
  /** true only if both sides ran identical work (same scalar) */
  normalized?: boolean;
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
  /** how the proof is bound to the program (see Implementation.proofBinding) */
  proofBinding: 'runtime' | 'baked';
  /** distinct proofs run against the SAME locking (1 = the main valid run, + extras) */
  proofsTested: number;
  /** how many of those distinct proofs the program fully accepted */
  proofsPassed: number;
  /** verifies >= 2 distinct proofs under one locking (empirically runtime-general) */
  runtimeGeneral: boolean;
  /** any step threads state through an NFT-commitment covenant (Step.covenant set) */
  tokenThreaded: boolean;
  /** token-threading entries only: does the covenant enforce token safety (category
   * continuity + capability constraint)? null when not token-threaded. */
  tokenSafetyEnforced: boolean | null;
  /** EIP-197 input validation: how many adversarial-point runs (off-curve /
   * off-subgroup, from Scenario.invalidInputs) were run, and how many the verifier
   * rejected. `enforced` = at least one tested and ALL rejected. */
  inputValidation: { tested: number; rejected: number; enforced: boolean };
  /** correctness was judged under the BSV post-Genesis OP_RETURN-terminator rule
   * (the valid run halts at a reachable OP_RETURN, which fails on strict BCH) */
  bsvOpReturn: boolean;
  steps: StepMetrics[];
  /** cumulative op-cost + bytes to reach each named checkpoint (multi-step) */
  checkpointStats: CheckpointStat[];
  stepCount: number;
  totalBytes: number;
  totalOperationCost: number;
  maxStepOperationCost: number;
  /** every step's op-cost fits one standard BCH input's budget */
  fitsStandardBudget: boolean;
  /** ceil(maxStepOpCost / standard budget): inputs the heaviest step needs */
  inputsForHeaviestStep: number;
  /**
   * Op-cost of the WORST-CASE proof run (dense near-r public inputs), when the scenario
   * supplies one. Same step graph as the valid run (worst-case-sized windows), but the
   * op-cost reflects a dense proof — proof-size dependent for chunked covenants (~5-6×
   * the vk_x stage), ~unchanged for proof-size-independent verifiers. undefined when no
   * worst-case run was provided or it did not fully accept. */
  worstCase?: {
    stepCount: number;
    totalOperationCost: number;
    maxStepOperationCost: number;
    inputsForHeaviestStep: number;
  };
  /** every step of the valid run validates on the REAL BCH 2026 VM (consensus limits) */
  bchCompatible: boolean;
  /** short reason the first incompatible step failed on the real VM */
  bchIncompatibleReason?: string;
  error?: string;
}
