// Op-cost profiler for BCH 2026 scripts with OP_DEFINE / OP_INVOKE (libauth 3.1.0-next.8).
// Method: wrap every operation of the loosened BCH-2026 instruction set. Before each operation the
// current call stack (function ids, from OP_INVOKE frames) is captured; after `every` (which
// recomputes metrics.operationCost) the op-cost delta of that one instruction is attributed
// exclusively to the innermost frame and inclusively to every distinct frame on the stack.
// OP_INVOKE itself is charged to the caller. Phase = which stateEvaluate call (unlocking /
// locking / redeem) the instruction ran in. Totals are checked against vm.evaluate().
import {
  encodeAuthenticationInstruction,
  ConsensusBch2025, createInstructionSetBch2026, createVirtualMachine, createTestAuthenticationProgramBch,
  ripemd160, secp256k1, sha1, sha256, binToHex, vmNumberToBigInt,
} from '@bitauth/libauth';

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const OP_DEFINE = 0x89, OP_INVOKE = 0x8a;

export const idName = (idHex) => {
  try { return 'f' + vmNumberToBigInt(Uint8Array.from(Buffer.from(idHex, 'hex')), { requireMinimalEncoding: false }).toString(); }
  catch { return 'x' + idHex; }
};

export function profile({ locking, unlocking, names = {}, intraTx, keyOf, onInvoke, onReturn, segOf, base: baseSet }) {
  const base = baseSet ?? createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 });
  const frameOf = new WeakMap(); // instructions array -> function key
  let phase = -1;
  let ctx = null; // stack snapshot for the current instruction
  let ctxOp = 0;
  const fnName = (k) => (k.startsWith('#') ? k : names[k] ?? idName(k));
  const excl = new Map(), incl = new Map(), calls = new Map(), edges = new Map();
  const defines = []; // executed OP_DEFINE: { key, bodyLen }
  const top = []; // depth-1 call instances in order { name, cost }
  const opExcl = new Map(); // per-opcode exclusive cost (for helper characterization)
  let curTop = null;
  const add = (m, k, v) => m.set(k, (m.get(k) ?? 0) + v);
  const stackOf = (state) => {
    const s = [];
    for (const f of state.controlStack) if (typeof f === 'object' && f !== null && f.instructions) s.push(f.instructions);
    s.push(state.instructions);
    return s.map((ins) => frameOf.get(ins) ?? `#phase${phase}`);
  };
  const offs = new WeakMap();
  const offsetOf = (ins, ip) => {
    let o = offs.get(ins);
    if (!o) { o = []; let acc = 0; for (const i of ins) { o.push(acc); acc += encodeAuthenticationInstruction(i).length; } offs.set(ins, o); }
    return o[ip];
  };
  let ctxIp = 0, ctxPhase = 0, ctxLen = 0, ctxSeg = null;
  const topOff = new Map(); // `${phase}:${offset}` -> { len, tl }
  const timeline = []; // depth-1 timeline: calls from the top frame and top-frame gaps
  let gap = null;
  const ops = {};
  for (const [code, op] of Object.entries(base.operations)) {
    const c = Number(code);
    ops[code] = (state) => {
      ctx = stackOf(state); ctxOp = c;
      if (segOf) {
        const frames = []; for (const f of state.controlStack) if (typeof f === 'object' && f !== null && f.instructions) frames.push([f.instructions, f.ip - 1]);
        frames.push([state.instructions, state.ip]);
        ctxSeg = segOf(ctx.map(fnName), frames.map(([ins, ip]) => offsetOf(ins, ip)), phase);
      }
      if (ctx.length === 1) { ctxIp = offsetOf(state.instructions, state.ip); ctxPhase = phase; ctxLen = encodeAuthenticationInstruction(state.instructions[state.ip]).length; }
      let pendingKey = null, pendingBody = null;
      if (c === OP_INVOKE || c === OP_DEFINE) {
        const it = state.stack[state.stack.length - 1];
        pendingKey = it ? binToHex(it) : null;
        if (c === OP_DEFINE) pendingBody = state.stack[state.stack.length - 2];
      }
      const prevIns = state.instructions, prevFc = state.functionCount;
      const next = op(state);
      if (c === OP_INVOKE && next.error === undefined && pendingKey !== null && next.instructions !== prevIns) {
        frameOf.set(next.instructions, pendingKey);
        const nm = fnName(pendingKey);
        if (onInvoke) onInvoke(ctx.map(fnName), nm);
        add(calls, nm, 1);
        add(edges, `${fnName(ctx[ctx.length - 1])} -> ${nm}`, 1);
        if (ctx.length === 1) { curTop = { name: nm, cost: 0, at: ctxIp, phase: ctxPhase }; top.push(curTop); timeline.push(curTop); gap = null; }
      }
      if (c === OP_DEFINE && pendingKey !== null && pendingBody && next.functionCount !== prevFc) defines.push({ key: pendingKey, name: fnName(pendingKey), bodyLen: pendingBody.length });
      return next;
    };
  }
  const instructionSet = {
    ...base,
    operations: ops,
    every: (state) => {
      const before = state.metrics.operationCost;
      const next = base.every(state);
      const d = next.metrics.operationCost - before;
      if (ctx) {
        const names_ = ctx.map(fnName);
        add(excl, names_[names_.length - 1], d);
        for (const n of new Set(names_)) add(incl, n, d);
        // depth-1 attribution: instructions inside a call made from the top frame
        if (ctx.length >= 2 && curTop) curTop.cost += d;
        if (ctx.length === 1) {
          if (!gap || gap.phase !== ctxPhase) { gap = { name: '(top)', cost: 0, at: ctxIp, end: ctxIp, phase: ctxPhase, n: 0 }; timeline.push(gap); }
          gap.cost += d; gap.end = ctxIp; gap.n += 1;
        }
        if (ctx.length === 1) { const k = `${ctxPhase}:${ctxIp}`; if (!topOff.has(k)) topOff.set(k, { len: ctxLen, tl: timeline.length - 1 }); }
        { const seen = new Set(); for (let i = 0; i < names_.length; i++) { const k = `${names_[i]} > ${names_[i + 1] ?? '(self)'}`; if (!seen.has(k)) { seen.add(k); add(edgeIncl, k, d); } } }
        add(opTot, ctxOp, d); add(opCnt, ctxOp, 1);
        add(opExcl, `${names_[names_.length - 1]}|${ctxOp.toString(16)}`, d);
        if (keyOf) for (const k of keyOf(names_, ctxOp)) add(custom, k, d);
        if (segOf) { add(custom, ctxSeg, d); }
      }
      return next;
    },
    evaluate: (program, opts) => base.evaluate(program, {
      ...opts,
      stateEvaluate: (st) => { phase += 1; return opts.stateEvaluate(st); },
    }),
  };
  const edgeIncl = new Map(); const opTot = new Map(), opCnt = new Map();
  const custom = new Map();
  const vm = createVirtualMachine(instructionSet);
  const program = intraTx ? intraTxProgram(intraTx) : createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const st = vm.evaluate(program);
  const topItem = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && topItem?.length === 1 && topItem[0] === 1;
  const sum = [...excl.values()].reduce((a, b) => a + b, 0);
  return {
    accepted, error: st.error, operationCost: st.metrics.operationCost, attributed: sum,
    instructions: st.metrics.evaluatedInstructionCount,
    excl: Object.fromEntries([...excl].sort((a, b) => b[1] - a[1])),
    incl: Object.fromEntries([...incl].sort((a, b) => b[1] - a[1])),
    calls: Object.fromEntries(calls), edges: Object.fromEntries(edges),
    opTot: Object.fromEntries([...opTot].map(([k, x]) => [k.toString(16), [x, opCnt.get(k)]])), top, timeline, topOff: Object.fromEntries(topOff), defines, edgeIncl: Object.fromEntries([...edgeIncl].sort((a, b) => b[1] - a[1])), custom: Object.fromEntries(custom),
    opExcl,
  };
}

function intraTxProgram({ index, inputs }) {
  return {
    inputIndex: index,
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.lockingBytecode, valueSatoshis: 1000n })),
    transaction: {
      version: 2,
      inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlockingBytecode })),
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
  };
}

export const fmt = (n) => Math.round(n).toLocaleString('en-US');
