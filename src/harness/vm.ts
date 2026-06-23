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
  capability: 'none' | 'mutable' | 'minting';
  inCommitment: Uint8Array; // NFT commitment of the spent UTXO  = hash256(incoming state)
  outCommitment: Uint8Array; // NFT commitment of tx.outputs[0]   = hash256(outgoing state)
  outLockingBytecode: Uint8Array; // tx.outputs[0] locking (next chunk; the perpetuation target)
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

/** Evaluate unlocking + locking as a synthetic spend and report acceptance + metrics.
 * With a covenant context the spend is driven through a token-carrying tx so the
 * contract's NFT-commitment / output introspection resolves. */
export const evaluatePair = (
  vm: Bch2026Vm,
  lockingBytecode: Uint8Array,
  unlockingBytecode: Uint8Array,
  covenant?: CovenantContext,
  intraTx?: IntraTxContext,
): EvalOutcome => {
  const mkToken = (commitment: Uint8Array) => ({
    amount: 0n,
    category: covenant!.category,
    nft: { capability: covenant!.capability, commitment },
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
  const program = intraTxProgram
    ? intraTxProgram
    : covenant
    ? {
        inputIndex: 0,
        sourceOutputs: [{ lockingBytecode, valueSatoshis: 1000n, token: mkToken(covenant.inCommitment) }],
        transaction: {
          version: 2,
          inputs: [
            { outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode },
          ],
          outputs: [
            { lockingBytecode: covenant.outLockingBytecode, valueSatoshis: 1000n, token: mkToken(covenant.outCommitment) },
          ],
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

/** Budget of one input at the standard unlocking cap. */
export const standardInputBudget = (): number => realOpCostBudget(STANDARD_UNLOCKING_CAP);
