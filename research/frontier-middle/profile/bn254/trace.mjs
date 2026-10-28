// Generic op-cost attribution tracer for libauth BCH VMs (2026 / spec) with OP_DEFINE/OP_INVOKE.
// Wraps every operation of an instruction set (no debug trace, so 800M-op-cost runs fit in memory).
// Per executed instruction it attributes: 100 (base) + delta(arithmeticCost + stackPushedBytes + hashIter*H + sig*S)
// to (a) the innermost frame's function id (exclusive), (b) every distinct function id on the call stack
// (inclusive), (c) the full call path, and (d) the ip of the outermost (top-level) frame.
import {
  binToHex, createInstructionSetBch2026, createInstructionSetBchSpec, createVirtualMachine,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} from '@bitauth/libauth';

const OP_INVOKE = 0x8a;
const HUGE = Number.MAX_SAFE_INTEGER;
export const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};

export function makeTracedVm(kind, standard = false) {
  let set, consensus;
  if (kind === 'loose') { consensus = loosened; set = createInstructionSetBch2026(false, {consensus, ripemd160, secp256k1, sha1, sha256}); }
  else if (kind === 'bch2026') { set = createInstructionSetBch2026(standard); consensus = {...ConsensusBch2025, baseInstructionCost: 100}; }
  else if (kind === 'spec') { set = createInstructionSetBchSpec(standard); consensus = {...ConsensusBch2025, baseInstructionCost: 100}; }
  const H = standard ? consensus.hashDigestIterationCostStandard : consensus.hashDigestIterationCostConsensus;
  const S = consensus.signatureCheckCost;
  const rest = (m) => m.arithmeticCost + m.stackPushedBytes + m.hashDigestIterations * H + m.signatureCheckCount * S;
  const P = {reset() {
    this.excl = new Map(); this.incl = new Map(); this.path = new Map(); this.topIp = new Map(); this.calls = new Map();
    this.total = 0; this.instr = 0; this.byOpcode = new Map(); this.frameIp = new Map(); this.frameLen = new Map(); this.arith = 0; this.pushed = 0; this.hash = 0;
  }};
  P.reset();
  let cur = null;
  const fidOf = (ins) => ins.__fid ?? ('top' + ins.length);
  const ops = {};
  for (const [code, fn] of Object.entries(set.operations)) {
    const c = Number(code);
    ops[c] = (state) => {
      const frames = [];
      for (const e of state.controlStack) if (typeof e === 'object' && e !== null && e.instructions) frames.push(e);
      const outer = frames.length ? frames[0] : {instructions: state.instructions, ip: state.ip};
      const stackFids = frames.map((f) => fidOf(f.instructions)); stackFids.push(fidOf(state.instructions));
      const m = state.metrics;
      cur = {pre: rest(m), arith: m.arithmeticCost, pushed: m.stackPushedBytes, hash: m.hashDigestIterations, fids: stackFids,
        topKey: fidOf(outer.instructions) + '@' + outer.ip, op: c, fk: frames.map((f) => fidOf(f.instructions) + '@' + f.ip).concat(fidOf(state.instructions) + '@' + state.ip)};
      let fid;
      if (c === OP_INVOKE) fid = binToHex(state.stack[state.stack.length - 1] ?? new Uint8Array());
      const before = state.instructions;
      const out = fn(state);
      if (c === OP_INVOKE && out.instructions !== before && out.error === undefined) {
        out.instructions.__fid = 'f' + fid; P.calls.set('f' + fid, (P.calls.get('f' + fid) ?? 0) + 1);
        P.frameLen.set('f' + fid, out.instructions.length);
      }
      return out;
    };
  }
  const origEvery = set.every;
  const every = (state) => {
    const out = origEvery(state);
    if (cur) {
      const m = out.metrics; const d = rest(m) - cur.pre + 100;
      P.total += d; P.instr += 1;
      P.arith += m.arithmeticCost - cur.arith; P.pushed += m.stackPushedBytes - cur.pushed; P.hash += m.hashDigestIterations - cur.hash;
      const inner = cur.fids[cur.fids.length - 1];
      P.excl.set(inner, (P.excl.get(inner) ?? 0) + d);
      for (const f of new Set(cur.fids)) P.incl.set(f, (P.incl.get(f) ?? 0) + d);
      const pk = cur.fids.join('>'); P.path.set(pk, (P.path.get(pk) ?? 0) + d);
      P.topIp.set(cur.topKey, (P.topIp.get(cur.topKey) ?? 0) + d);
      for (const k of new Set(cur.fk)) P.frameIp.set(k, (P.frameIp.get(k) ?? 0) + d);
      P.byOpcode.set(cur.op, (P.byOpcode.get(cur.op) ?? 0) + d);
      cur = null;
    }
    return out;
  };
  const vm = createVirtualMachine({...set, operations: ops, every});
  return {vm, P};
}

// parse "a b c" -> Map
export const top = (map, n = 30) => [...map].sort((a, b) => b[1] - a[1]).slice(0, n);
export const M = (x) => (x / 1e6).toFixed(3) + 'M';
