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

/** Real BCH 2026 VM in STANDARD (mempool-relay) mode — libauth's `standard=true`
 * toggle. Enforces the stricter standard per-input script rules (push-only scriptSig,
 * standard pubkey/signature encodings, clean stack) on top of consensus. NOTE: this
 * toggle is per-INPUT only; transaction-level relay policy (the 100,000-byte standard
 * max tx size, the 201/10,000-byte standard script caps) is NOT applied by evaluate()
 * — those are checked explicitly against the constants below. */
export const createStandardVm = () => createVirtualMachineBch2026(true);

// --- BCH 2026 standard (relay-policy) limits, from ConsensusBch2026Overrides ---
/** Max standard locking bytecode (scriptPubKey) length; a longer output is non-standard. */
export const MAX_STANDARD_LOCKING_BYTECODE = 201;
/** Max standard unlocking bytecode (scriptSig) length. */
export const MAX_STANDARD_UNLOCKING_BYTECODE = 10_000;
/** Max standard serialized transaction size; a larger tx is not relayed (must be mined directly). */
export const MAX_STANDARD_TRANSACTION_SIZE = 100_000;

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

/**
 * Token-threading covenant context. When present, the running state lives in the
 * spent/created NFT commitment (an introspection covenant), so the locking carries
 * NO baked state and one fixed program verifies any proof. The harness builds a
 * synthetic 1-in/1-out tx: the spent UTXO holds `inCommitment`, output[0] holds
 * `outCommitment` under `outLockingBytecode` (the next chunk), same token category.
 */
export interface CovenantContext {
  category: Uint8Array; // 32-byte token category (the thread id)
  capability: 'none' | 'mutable' | 'minting'; // capability of tx.outputs[0] (the perpetuated/terminating token)
  inCommitment: Uint8Array; // NFT commitment of the spent UTXO  = hash256(incoming state)
  outCommitment: Uint8Array; // NFT commitment of tx.outputs[0]   = hash256(outgoing state)
  outLockingBytecode: Uint8Array; // tx.outputs[0] locking (next chunk; the perpetuation target)
  // --- OPTIONAL, covenant-thread extensions (default => the legacy 1-in/1-out shape) ---
  // A minting-baton-genesis chunk spends a MINTING baton (not the thread token) and
  // emits TWO outputs: [0] the freshly-minted thread token, [1] the recreated baton relocked
  // to the chunk itself. Set when the chunk's input capability differs from output[0]'s.
  inputCapability?: 'none' | 'mutable' | 'minting'; // capability of the SPENT input token (default = `capability`)
  // The second output (a baton recreation), present only on a genesis chunk. The baton has
  // no commitment and is relocked to `lockingBytecode` (custody pinned to the validating chunk).
  secondOutputBaton?: boolean;
}

/** Intra-transaction linked-input context. The whole chunked computation is the
 * inputs of ONE transaction; chunk `index` reads its siblings' witnesses via
 * introspection (OP_INPUTBYTECODE) to carry state forward. The runner builds a
 * transaction from every input's (locking, unlocking) and evaluates input `index`
 * against it, so `tx.inputs[i].unlockingBytecode` resolves to the real sibling. */
export interface IntraTxContext {
  index: number;
  inputs: { lockingBytecode: Uint8Array; unlockingBytecode: Uint8Array }[];
}

/** Grouped (multi-tx, multi-input) context — the hybrid of intra-tx and covenant. The
 * computation is a handful of standard transactions; within one group tx the inputs bind by
 * OP_INPUTBYTECODE forward-checks, across groups the state rides a CashToken NFT commitment.
 * The runner builds ONE token-carrying tx for the group (input[0] optionally spends `inToken`,
 * output[0] optionally creates `outToken`) and evaluates input `index` against it. */
export interface GroupedContext {
  group: number;
  index: number;
  inputs: { lockingBytecode: Uint8Array; unlockingBytecode: Uint8Array }[];
  category: Uint8Array;
  inToken?: { capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array };
  outToken?: { capability: 'none' | 'mutable'; commitment: Uint8Array };
  outLockingBytecode?: Uint8Array;
}

/** Evaluate unlocking + locking as a synthetic spend and report acceptance + metrics.
 * With a covenant context the spend is driven through a token-carrying tx so the
 * contract's NFT-commitment / output introspection resolves. */
export const evaluatePair = (
  vm: Bch2026Vm,
  lockingBytecode: Uint8Array,
  unlockingBytecode: Uint8Array,
  covenant?: CovenantContext,
  intraTx?: IntraTxContext,
  grouped?: GroupedContext,
): EvalOutcome => {
  const mkToken = (
    capability: 'none' | 'mutable' | 'minting',
    commitment: Uint8Array,
  ) => ({
    amount: 0n,
    category: covenant!.category,
    nft: { capability, commitment },
  });
  const intraTxProgram = intraTx && {
    inputIndex: intraTx.index,
    sourceOutputs: intraTx.inputs.map((i) => ({ lockingBytecode: i.lockingBytecode, valueSatoshis: 1000n })),
    transaction: {
      version: 2,
      inputs: intraTx.inputs.map((i, n) => ({
        outpointTransactionHash: new Uint8Array(32),
        outpointIndex: n,
        sequenceNumber: 0,
        unlockingBytecode: i.unlockingBytecode,
      })),
      // a single OP_RETURN output keeps the synthetic tx well-formed (no value carried)
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
  };
  // Grouped: a multi-input token-carrying tx. input[0] optionally spends the incoming-state
  // token (covInHash binds it); output[0] optionally carries the outgoing-state token (covout
  // commits it). All other inputs are plain; the OP_INPUTBYTECODE forward-checks resolve to the
  // real siblings within this group's tx.
  const gTok = (t?: { capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array }) =>
    t ? { amount: 0n, category: grouped!.category, nft: { capability: t.capability, commitment: t.commitment } } : undefined;
  const groupedProgram = grouped && {
    inputIndex: grouped.index,
    sourceOutputs: grouped.inputs.map((i, n) => ({
      lockingBytecode: i.lockingBytecode,
      valueSatoshis: 1000n,
      token: n === 0 ? gTok(grouped.inToken) : undefined,
    })),
    transaction: {
      version: 2,
      inputs: grouped.inputs.map((i, n) => ({
        outpointTransactionHash: new Uint8Array(32),
        outpointIndex: n,
        sequenceNumber: 0,
        unlockingBytecode: i.unlockingBytecode,
      })),
      outputs: grouped.outToken
        ? [{ lockingBytecode: grouped.outLockingBytecode ?? Uint8Array.from([0x6a]), valueSatoshis: 1000n, token: gTok(grouped.outToken) }]
        : [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
  };
  // Covenant-thread extensions: a genesis chunk spends a MINTING baton (inputCapability) and
  // emits [thread token, recreated baton]; a terminal chunk strips capability (output 'none').
  // When neither is set this is exactly the legacy 1-in/1-out mutable->mutable shape.
  const inCap = covenant?.inputCapability ?? covenant?.capability ?? 'mutable';
  const inValue = covenant?.secondOutputBaton ? 3000n : 1000n;
  const covOutputs = covenant
    ? covenant.secondOutputBaton
      ? [
          { lockingBytecode: covenant.outLockingBytecode, valueSatoshis: 1000n, token: mkToken(covenant.capability, covenant.outCommitment) },
          { lockingBytecode, valueSatoshis: 1000n, token: mkToken('minting', new Uint8Array(0)) },
        ]
      : [{ lockingBytecode: covenant.outLockingBytecode, valueSatoshis: 1000n, token: mkToken(covenant.capability, covenant.outCommitment) }]
    : [];
  const program = groupedProgram
    ? groupedProgram
    : intraTxProgram
    ? intraTxProgram
    : covenant
    ? {
        inputIndex: 0,
        sourceOutputs: [{ lockingBytecode, valueSatoshis: inValue, token: mkToken(inCap, covenant.inCommitment) }],
        transaction: {
          version: 2,
          inputs: [
            { outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode },
          ],
          outputs: covOutputs,
          locktime: 0,
        },
      }
    : createTestAuthenticationProgramBch({
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

/**
 * True iff `locking` is a P2SH20 redeem-hash envelope: OP_HASH160 <20-byte hash>
 * OP_EQUAL (0xa9 0x14 …20… 0x87, 23 bytes total). P2SH20 hides the contract behind a
 * 160-bit hash, which is collision-vulnerable at only ~2^80 work — cheap enough to
 * incentivise forging a second redeem script for a contract holding real value (the
 * reason CashScript defaults to p2sh32 and warns p2sh20 is "cryptographically insecure
 * for a large subset of smart contracts"). Entries must wrap in P2SH32 (OP_HASH256
 * <32-byte> OP_EQUAL) or deploy bare/P2S, so the harness flags any P2SH20 locking and
 * disallows the entry. */
export const isP2sh20Locking = (locking: Uint8Array): boolean =>
  locking.length === 23 && locking[0] === 0xa9 && locking[1] === 0x14 && locking[22] === 0x87;

/** Budget of one input at the standard unlocking cap. */
export const standardInputBudget = (): number => realOpCostBudget(STANDARD_UNLOCKING_CAP);
