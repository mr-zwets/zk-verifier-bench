// Kernel measurement on libauth 3.1.0-next.8, BCH_2026 instruction set (the bench's VM).
//
// A kernel case is { inputs, defs, body, outputs, siblings? }:
//   inputs   : stack items the kernel starts with (bottom first), pushed by the unlocking bytecode;
//   defs     : [{id, body}] functions defined in a prologue (OP_DEFINE), outside the measured region;
//   body     : the measured bytecode (inline code, or `<id> OP_INVOKE` for a function kernel);
//   outputs  : the items the kernel must leave (bottom first): {bin: Uint8Array} compared with OP_EQUALVERIFY,
//              {num: bigint} compared with OP_NUMEQUALVERIFY. The expected values come from a reference
//              implementation in JS, so an accepted run is a correctness check.
//
// Script:  <prologue: defs> OP_NOP <body> OP_NOP <checks> OP_1
// The two OP_NOPs are markers: the instruction set is wrapped so that each OP_NOP snapshots the raw metrics
// (instruction count, arithmetic cost, pushed bytes, hash digest iterations) before it executes. The kernel's
// op-cost is the difference of the two snapshots, minus the first marker's own instruction (100). A calibration
// with an empty body gives exactly 0 (asserted in run.mjs).
//
// Op-cost = 100 * instructions + arithmetic cost + pushed bytes + iterations * {192 standard, 64 consensus}.
// BCHN-adjusted: libauth charges OP_DEFINE 100 (plus the body's push); BCHN (consensus) also charges the body's
// byte length per executed OP_DEFINE (research/opcost-timing/KERNELS.md). Only the prologue executes OP_DEFINE.
//
// Each case is run on (1) the loosened BCH 2026 VM (all ceilings lifted; measures any size) in standard and in
// consensus mode, and (2) the real BCH 2026 VM, standard and consensus, as a P2SH32 spend whose unlocking is
// zero-padded so that its budget covers the whole script (with BCHN's define charge): this checks that the kernel
// is valid under the real limits (stack item size, number size, standard rules). A case whose padded unlocking
// would exceed 10,000 B is reported as `real: "over one standard input"`.
import {
  createInstructionSetBch2026, createVirtualMachine, encodeDataPush, hash256, ripemd160, secp256k1, sha1, sha256,
  ConsensusBch2025,
} from '@bitauth/libauth';
import {asm} from './asm.mjs';

const HUGE = Number.MAX_SAFE_INTEGER;
const loose = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: HUGE,
  maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE,
  maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const crypto = {ripemd160, secp256k1, sha1, sha256};

let snaps = [];
function markedVm(standard, consensus) {
  const base = consensus ? createInstructionSetBch2026(standard, {consensus, ...crypto}) : createInstructionSetBch2026(standard);
  const nop = base.operations[0x61];
  const operations = {...base.operations, [0x61]: (s) => {
    const m = s.metrics;
    snaps.push({instr: m.evaluatedInstructionCount, arith: m.arithmeticCost, pushed: m.stackPushedBytes, iters: m.hashDigestIterations, sig: m.signatureCheckCount});
    return nop(s);
  }};
  return createVirtualMachine({...base, operations});
}
const VM = {
  looseStd: markedVm(true, loose), looseCons: markedVm(false, loose),
  realStd: markedVm(true), realCons: markedVm(false),
};

export const p2sh32 = (redeem) => Uint8Array.from([0xaa, 0x20, ...hash256(redeem), 0x87]);
const pushes = (items) => Uint8Array.from(items.flatMap((b) => [...encodeDataPush(Uint8Array.from(b))]));

function programOf(locking, unlocking, siblings = []) {
  const ins = [unlocking, ...siblings.map((s) => s.unlocking)];
  const locks = [locking, ...siblings.map((s) => s.locking ?? Uint8Array.of(0x51))];
  return {
    inputIndex: 0,
    sourceOutputs: locks.map((l) => ({lockingBytecode: Uint8Array.from(l), valueSatoshis: 10000n})),
    transaction: {version: 2, locktime: 0,
      inputs: ins.map((u, n) => ({outpointIndex: n, outpointTransactionHash: new Uint8Array(32), sequenceNumber: 0, unlockingBytecode: Uint8Array.from(u)})),
      outputs: [{lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 1000n}]},
  };
}
const ok = (st) => st.error === undefined && st.stack.length === 1 && st.stack[0].length === 1 && st.stack[0][0] === 1;

export function prologueOf(defs) { return asm(defs.map((d) => [d.body, d.id, 'DEFINE'])); }
export function checksOf(outputs) {
  const parts = [];
  for (const o of [...outputs].reverse()) parts.push(o.bin !== undefined ? [o.bin, 'EQUALVERIFY'] : [o.num, 'NUMEQUALVERIFY']);
  return asm(parts);
}
const cost = (d, iterCost) => 100 * d.instr + d.arith + d.pushed + d.iters * iterCost;
const diff = (a, b) => ({instr: b.instr - a.instr - 1, arith: b.arith - a.arith, pushed: b.pushed - a.pushed, iters: b.iters - a.iters});

export function runCase(c) {
  const defs = c.defs ?? [];
  const prologue = prologueOf(defs);
  const script = asm({raw: [0x61]}, {raw: prologue}, {raw: [0x61]}, {raw: c.body}, {raw: [0x61]}, {raw: checksOf(c.outputs)}, 1);
  const unlocking = pushes(c.inputs);
  const res = {};
  for (const mode of ['looseStd', 'looseCons']) {
    snaps = [];
    const st = VM[mode].evaluate(programOf(script, unlocking, c.siblings));
    if (!ok(st)) throw new Error(`${c.name ?? 'case'} rejected (${mode}): ${st.error ?? 'stack ' + st.stack.length}`);
    if (snaps.length !== 3) throw new Error('expected 3 markers, got ' + snaps.length);
    res[mode] = {kernel: diff(snaps[1], snaps[2]), prologue: diff(snaps[0], snaps[1]), total: st.metrics.operationCost, iters: st.metrics.hashDigestIterations};
  }
  const k = res.looseStd.kernel, kc = res.looseCons.kernel;
  if (JSON.stringify(k) !== JSON.stringify(kc)) throw new Error('standard/consensus metric mismatch');
  const pr = res.looseStd.prologue;
  const defBytes = defs.reduce((a, d) => a + d.body.length, 0);
  const out = {
    opStd: cost(k, 192), opCons: cost(k, 64), instr: k.instr, arith: k.arith, pushed: k.pushed, iters: k.iters,
    bodyBytes: c.body.length, defBytes, prologueBytes: prologue.length,
    defineLibauth: cost(pr, 192), defineBchn: cost(pr, 192) + defBytes,
  };
  // real BCH 2026 VM, P2SH32 with zero pad (pad pushed last, dropped first by the redeem)
  const redeem = asm('DROP', {raw: script});
  const needOp = res.looseStd.total + 2 * 100 + defBytes + 400; // + DROP and pad push, BCHN define charge, margin
  const baseU = pushes([...c.inputs, new Uint8Array(0), redeem]).length;
  const U = Math.max(baseU, Math.ceil(needOp / 800) - 41, 2 * (res.looseStd.iters + 2) - 41);
  let pad = U - baseU, unl;
  for (let t = 0; t < 4; t++) { unl = pushes([...c.inputs, new Uint8Array(Math.max(0, pad)), redeem]); if (unl.length >= U) break; pad += U - unl.length; }
  if (unl.length > 10_000 || redeem.length > 10_000) out.real = 'over one standard input';
  else {
    const lock = p2sh32(redeem);
    const r = ['realStd', 'realCons'].map((m) => { snaps = []; const st = VM[m].evaluate(programOf(lock, unl, c.siblings)); return ok(st) ? 'ok' : (st.error ?? 'stack'); });
    out.real = r[0] === 'ok' && r[1] === 'ok' ? 'ok' : `std: ${r[0]}; cons: ${r[1]}`;
    out.realUnlocking = unl.length;
  }
  return out;
}
// run `trials` random cases from build(rng, i) and aggregate
export function measure(name, build, {trials = 16, seed = 1} = {}) {
  const rng = makeRng(name + ':' + seed);
  const rows = [];
  for (let i = 0; i < trials; i++) { const c = build(rng, i); c.name = name; rows.push(runCase(c)); }
  const agg = (f) => { const v = rows.map(f); return {min: Math.min(...v), max: Math.max(...v), mean: v.reduce((a, b) => a + b, 0) / v.length}; };
  const real = [...new Set(rows.map((r) => r.real))];
  return {
    name, trials, opStd: agg((r) => r.opStd), opCons: agg((r) => r.opCons), instr: agg((r) => r.instr), arith: agg((r) => r.arith),
    pushed: agg((r) => r.pushed), iters: agg((r) => r.iters), bodyBytes: agg((r) => r.bodyBytes), defBytes: rows[0].defBytes,
    prologueBytes: rows[0].prologueBytes, defineLibauth: rows[0].defineLibauth, defineBchn: rows[0].defineBchn, real,
  };
}

// deterministic RNG (xorshift128+ over BigInt) seeded from a string
export function makeRng(seedStr) {
  let h = 0xcbf29ce484222325n; const M = (1n << 64n) - 1n;
  for (const ch of Buffer.from(seedStr)) { h ^= BigInt(ch); h = (h * 0x100000001b3n) & M; }
  let s0 = h | 1n, s1 = (h * 0x9e3779b97f4a7c15n) & M | 1n;
  const next64 = () => { let x = s0; const y = s1; s0 = y; x ^= (x << 23n) & M; s1 = x ^ y ^ (x >> 17n) ^ (y >> 26n); return (s1 + y) & M; };
  const big = (bits) => { let v = 0n; for (let b = 0; b < bits; b += 64) v = (v << 64n) | next64(); return v & ((1n << BigInt(bits)) - 1n); };
  return {
    next64, big,
    below: (n) => { const bits = n.toString(2).length + 64; return big(bits) % n; },
    int: (n) => Number(next64() % BigInt(n)),
    bytes: (k) => Uint8Array.from({length: k}, () => Number(next64() & 255n)),
  };
}
