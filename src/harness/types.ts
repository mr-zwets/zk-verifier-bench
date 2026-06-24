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
    /** capability of tx.outputs[0] (the perpetuated / minted / terminating token) */
    capability: 'none' | 'mutable' | 'minting';
    inCommitment: Uint8Array;
    outCommitment: Uint8Array;
    outLockingBytecode: Uint8Array;
    /**
     * Covenant-thread extensions (optional; default => the legacy 1-in/1-out mutable shape).
     * A baton-genesis chunk SPENDS a minting baton (inputCapability='minting') and emits a
     * second output recreating the baton (secondOutputBaton=true); a terminal chunk spends
     * the mutable thread token (inputCapability='mutable') and strips to an immutable
     * (capability='none') verdict output. See harness/vm.ts evaluatePair.
     */
    inputCapability?: 'none' | 'mutable' | 'minting';
    secondOutputBaton?: boolean;
  };
  /**
   * Intra-transaction linked-input context. Set when this step is ONE INPUT of a
   * SINGLE transaction whose inputs carry the chunked computation forward by reading
   * each other's witnesses (OP_INPUTBYTECODE) instead of an NFT-commitment hand-off.
   * `index` is this step's input index; `inputs` is the full ordered list of every
   * input's (locking, unlocking) in the shared tx (the SAME array object across all
   * steps of the run). The harness evaluates this input against a transaction built
   * from `inputs`, so a chunk's `tx.inputs[idx±1].unlockingBytecode` introspection
   * resolves to its real sibling. State is passed as raw, arbitrary-size byte blobs
   * (no 128-byte token-commitment limit, no hashing), bound by direct byte equality.
   */
  intraTx?: {
    index: number;
    inputs: { lockingBytecode: Uint8Array; unlockingBytecode: Uint8Array }[];
  };
  /**
   * Grouped (multi-tx, multi-input) context. Set when this step is ONE INPUT of one of a
   * HANDFUL of standard (<100,000 B) transactions that together run the chunked computation.
   * It is the hybrid of `intraTx` and `covenant`: WITHIN a group transaction the inputs bind
   * each other by OP_INPUTBYTECODE forward-checks (intra-tx), and ACROSS group transactions the
   * running state rides a CashToken NFT commitment (covenant) — a group's last chunk commits
   * hash256(outBlob) to output[0], the next group's first chunk binds its inBlob via
   * tx.inputs[0].nftCommitment. The token thread chains all groups in order.
   *
   * `group` is this input's transaction index; `index` its position within that group's tx;
   * `inputs` the full ordered input list of THIS group's tx (the SAME array across the group's
   * steps), so a chunk's tx.inputs[idx±1] introspection resolves to its real sibling. The
   * token fields drive the cross-group hand-off: `inToken` is spent by input[0] of the group
   * (undefined => no spent token), `outToken` is created at output[0] (undefined => terminal
   * group, the thread token is burned), `outLockingBytecode` is output[0]'s locking when a
   * token is created. The harness builds one synthetic token-carrying tx per group and
   * evaluates input `index` against it.
   */
  grouped?: {
    group: number;
    index: number;
    inputs: { lockingBytecode: Uint8Array; unlockingBytecode: Uint8Array }[];
    category: Uint8Array;
    inToken?: { capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array };
    outToken?: { capability: 'none' | 'mutable'; commitment: Uint8Array };
    outLockingBytecode?: Uint8Array;
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
   * be swapped or substituted across the thread? A safe deployment must either pin the
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
  /** dead-weight zero-padding bytes in the unlocking: every all-zero push that buys op-cost
   * budget, wherever it sits (bare scripts pad LAST; P2SH deployments push the redeem script
   * last so the pad is second-to-last). 0 for unpadded steps (e.g. singletons). */
  padBytes: number;
  /** serialized transaction overhead this step adds that the script-byte score does NOT
   * count: tx envelope (version/locktime/counts), the spent outpoint + sequence, script-
   * length varints, and — for a covenant step — the CashToken output prefix that carries
   * the threaded state. Excludes the perpetuated output locking (counted as the NEXT
   * step's locking). For an intra-tx bundle the shared envelope+output land on input 0. */
  txOverheadBytes: number;
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
  /** EIP-197 input validation: how many ISOLATED adversarial-point runs (off-curve /
   * off-subgroup, from Scenario.invalidInputs — a chunked g2check stage that rejects the bad
   * point at the check, before the pairing) were run, and how many the verifier rejected.
   * `enforced` = at least one tested and ALL rejected. `tested === 0` on a full Groth16
   * verifier means input validation is NOT DEMONSTRATED — note a naive point-swap in a
   * single-tx verifier is caught by the verification equation, so it can't demonstrate
   * validation (see harness/adversarial.ts). */
  inputValidation: { tested: number; rejected: number; enforced: boolean };
  /** correctness was judged under the BSV post-Genesis OP_RETURN-terminator rule
   * (the valid run halts at a reachable OP_RETURN, which fails on strict BCH) */
  bsvOpReturn: boolean;
  steps: StepMetrics[];
  /** cumulative op-cost + bytes to reach each named checkpoint (multi-step) */
  checkpointStats: CheckpointStat[];
  stepCount: number;
  totalBytes: number;
  /** total dead-weight zero-padding bytes across all steps (subset of totalBytes) */
  totalPadBytes: number;
  /** total serialized transaction overhead across all steps, ON TOP of totalBytes (envelope
   * + outpoints + token prefixes + varints). The recurring per-tx cost of a covenant chain;
   * ~one tx's worth for a single-tx verifier. true on-chain size ≈ totalBytes + this. */
  totalTxOverheadBytes: number;
  /** number of transactions the run spans: one per step for a covenant chain, 1 for an
   * intra-tx bundle or a single-tx verifier. */
  txCount: number;
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
   * the vk_x stage), ~unchanged for proof-size-independent verifiers. undefined only when
   * no worst-case run was provided. `accepted` reports whether every worst-case step was
   * accepted by the verifier under test — a valid worst-case proof that rejects is a
   * completeness bug, and folds into the overall `pass`. */
  worstCase?: {
    accepted: boolean;
    stepCount: number;
    totalOperationCost: number;
    maxStepOperationCost: number;
    inputsForHeaviestStep: number;
  };
  /** every step of the valid run validates on the REAL BCH 2026 VM (consensus limits) */
  bchCompatible: boolean;
  /** short reason the first incompatible step failed on the real VM */
  bchIncompatibleReason?: string;
  /**
   * The valid run is relayable under BCH 2026 STANDARD (mempool) policy — strictly
   * stronger than `bchCompatible` (consensus). Requires ALL of: every step validates
   * under the libauth standard instruction set (createVirtualMachineBch2026(true) —
   * push-only scriptSig, standard encodings, clean stack); every locking <= 201 B and
   * every unlocking <= 10,000 B (standard script caps); and every transaction <=
   * 100,000 B (standard max tx size). A consensus-valid verifier can still be
   * non-standard: e.g. the intra-tx bundle is one ~626 KB transaction — fine per input,
   * but over the standard size, so it must be mined directly rather than relayed. */
  fitsBchStandardness: boolean;
  /** short reason standardness fails (e.g. the size cap that is exceeded); undefined when it fits */
  bchStandardnessReason?: string;
  /**
   * No step hides its contract behind an insecure P2SH20 envelope (OP_HASH160 <20B>
   * OP_EQUAL). P2SH20's 160-bit hash is collision-vulnerable at ~2^80 work, so it is
   * DISALLOWED for entries (use P2SH32, or deploy bare / P2S). false => the entry is
   * disqualified (folded into `pass`); orthogonal to consensus/standardness, since
   * P2SH20 is itself valid and relayable on BCH — this is a competition security rule. */
  securePackaging: boolean;
  /** short reason the packaging is disallowed (how many steps use P2SH20); undefined when secure */
  insecurePackagingReason?: string;
  error?: string;
}
