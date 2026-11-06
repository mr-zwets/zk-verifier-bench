// Symbolic-stack assembler (bch-2026 / bch-spec VM), with a scheduling arithmetic-kernel compiler.
// Copied from chunked/bn254/sound-si-gls/asm.mjs (reviewed) with three extensions for the multi-input build:
//   (1) BOUND functions are matched on a WINDOW: the top W items, W = depth of the deepest item the body
//       touches at its first call site. Later call sites must present every touched item at the same
//       symbolic AND physical depth (asserted) with the same altstack/piles context; items below the
//       window may differ (each role keeps its own items there). The body must leave the items below
//       the window untouched (asserted). Any item an instruction pops or a kernel reads counts as touched.
//   (2) function ids above 16 are allowed (pushed as 2-byte numbers);
//   (3) kernels may read items below a pile whose physical size is known (not only above every pile).
//
// Every stack item has a name; PICK/ROLL depths are computed from names, so code is position-exact
// by construction. Structured control flow keeps the symbolic stack consistent:
//   - ifElse(): both branches must end with the same named layout (asserted);
//   - loop(): OP_BEGIN body OP_UNTIL, the body must restore the entry layout (asserted);
//   - functions (OP_DEFINE / OP_INVOKE) are either LOCAL (they see only their declared inputs, so
//     they are position independent) or BOUND (compiled against the full named layout of their first
//     call site; every later call site must present exactly the same layout, asserted).
// Kernels: a DAG over named stack items (read-only "env" items are PICKed, "input" items are
// consumed at their last use) is scheduled by local search on the exact bch-spec op-cost model
// (100/instruction + pushed bytes + lenA*lenB for MUL/MOD/DIV + 2*len(result) for arithmetic).
import assert from 'node:assert/strict';
import {bigIntToVmNumber, encodeDataPush} from '@bitauth/libauth';

export const OP = {
  0: 0x00, PUSHDATA1: 0x4c, NEG1: 0x4f, TRUE: 0x51, NOP: 0x61, IF: 0x63, NOTIF: 0x64, BEGIN: 0x65, UNTIL: 0x66, ELSE: 0x67, ENDIF: 0x68,
  VERIFY: 0x69, TOALT: 0x6b, FROMALT: 0x6c, TWODROP: 0x6d, TWODUP: 0x6e, IFDUP: 0x73, DEPTH: 0x74, DROP: 0x75, DUP: 0x76, NIP: 0x77,
  OVER: 0x78, PICK: 0x79, ROLL: 0x7a, ROT: 0x7b, SWAP: 0x7c, TUCK: 0x7d, CAT: 0x7e, SPLIT: 0x7f, NUM2BIN: 0x80, BIN2NUM: 0x81,
  SIZE: 0x82, INVERT: 0x83, AND: 0x84, OR: 0x85, XOR: 0x86, EQUAL: 0x87, EQUALVERIFY: 0x88, DEFINE: 0x89, INVOKE: 0x8a,
  ADD1: 0x8b, SUB1: 0x8c, LSHIFTNUM: 0x8d, RSHIFTNUM: 0x8e, NEGATE: 0x8f, ABS: 0x90, NOT: 0x91, ZERONOTEQUAL: 0x92, ADD: 0x93,
  SUB: 0x94, MUL: 0x95, DIV: 0x96, MOD: 0x97, BOOLAND: 0x9a, BOOLOR: 0x9b, NUMEQUAL: 0x9c, NUMEQUALVERIFY: 0x9d, NUMNOTEQUAL: 0x9e,
  LESSTHAN: 0x9f, GREATERTHAN: 0xa0, LESSTHANOREQUAL: 0xa1, GREATERTHANOREQUAL: 0xa2, MIN: 0xa3, MAX: 0xa4, WITHIN: 0xa5,
  SHA256: 0xa8, HASH256: 0xaa, EQUAL_: 0x87,
};
export const numBytes = (n) => bigIntToVmNumber(BigInt(n));
export const pushNum = (n) => [...encodeDataPush(numBytes(n))];
export const pushData = (b) => [...encodeDataPush(Uint8Array.from(b))];
export const numLen = (n) => numBytes(n).length;
// Keep allocator identities canonical while selecting compact raw wire keys.
// OP_0 emits the empty raw key; OP_1NEGATE emits raw key 81.
// BDBL and HDEC exchange their raw wire keys; allocator identities and
// definition order remain canonical (f.id / ctx.nextId).
export const pushFunctionId = (id) => pushNum(id === 18 ? 0 : id === 20 ? -1 : id === 15 ? 21 : id === 21 ? 15 : id);

let uid = 0;
const LAZY = process.env.LAZY === '1'; // off by default: the static cost model is not accurate enough for it
export class Asm {
  constructor(stack = [], ctx = undefined) {
    this.st = [...stack];
    this.code = [];
    this.ctx = ctx ?? {funcs: new Map(), nextId: 1, defs: []};
    this.localFloor = -1; // index below which a LOCAL function may not reach
    this.marks = [];
    this.alt = [];          // symbolic altstack
    this.piles = new Map(); // pile item name -> physical item count (null: varies, items below are unreachable)
  }
  mark(name) { this.marks.push({name, off: this.code.length}); return this; }
  absorb(sub, base) { for (const m of sub.marks) this.marks.push({name: m.name, off: base + m.off}); }
  fresh(b = 't') { return `${b}#${uid++}`; }
  emit(...b) { for (const x of b) { assert.ok(Number.isInteger(x) && x >= 0 && x < 256, 'byte ' + x); this.code.push(x); } return this; }
  idx(name) { if (this.touched) this.touched.add(name); const i = this.st.lastIndexOf(name); if (i < 0) throw new Error(`no item '${name}' (top: ${this.st.slice(-14).join(', ')})`); if (i <= this.localFloor) throw new Error(`local function reaches below its inputs: ${name}`); return i; }
  has(name) { return this.st.lastIndexOf(name) > this.localFloor; }
  depth(name) {
    const i = this.idx(name); let d = this.st.length - 1 - i;
    for (let j = i + 1; j < this.st.length; j++) if (this.piles.has(this.st[j])) { const c = this.piles.get(this.st[j]); if (c === null) throw new Error(`'${name}' is below pile ${this.st[j]} of varying size`); d += c - 1; }
    return d;
  }
  // ---- piles (a run of physical items represented by one symbolic item; the top one is taken first) ----
  pushPile(name, pieces) { for (const b of pieces) this.emit(...pushData(b)); this.st.push(name); this.piles.set(name, pieces.length); return this; }
  pileTake(name, as) {
    const d = this.depth(name); if (d === 1) this.emit(OP.SWAP); else if (d === 2) this.emit(OP.ROT); else if (d > 2) this.emit(...pushNum(d), OP.ROLL); else this.emit(OP.DUP, OP.DROP);
    const c = this.piles.get(name); if (c !== null) { this.piles.set(name, c - 1); }
    this.st.push(as); return this;
  }
  pileDone(name) { const i = this.st.lastIndexOf(name); if (i >= 0) this.st.splice(i, 1); else this.alt.splice(this.alt.lastIndexOf(name), 1); this.piles.delete(name); return this; }
  // ---- altstack ----
  toAlt(name) { if (name !== undefined) this.roll(name); this.emit(OP.TOALT); this.alt.push(this.mk(this.st.pop())); return this; }
  fromAlt(as) { assert.ok(this.alt.length, 'altstack empty'); this.emit(OP.FROMALT); const n = this.alt.pop(); this.st.push(as ?? n); return this; }
  peekAlt(as) { assert.ok(this.alt.length); this.emit(OP.FROMALT, OP.DUP, OP.TOALT); this.st.push(as); return this; }
  pushAltPile(name, count) { this.alt.push(name); this.piles.set(name, count); return this; } // pieces were moved there with TOALT
  altPileTake(as) { const n = this.alt.at(-1); assert.ok(this.piles.has(n), 'alt top is not a pile'); this.emit(OP.FROMALT); const c = this.piles.get(n); if (c !== null) this.piles.set(n, c - 1); this.st.push(as); return this; }
  // a bound function compiled with a pile of varying size (null) may be called where its size is known
  compatCtx(o, what) { assert.deepEqual(this.alt, o.alt, what + ': altstack differs'); assert.deepEqual([...this.piles.keys()].sort(), [...o.piles.keys()].sort(), what + ': piles differ');
    for (const [n, c] of o.piles) assert.ok(c === null || this.piles.get(n) === c, what + ': pile size of ' + n); }
  sameCtx(o, what) { assert.deepEqual(this.alt, o.alt, what + ': altstack differs'); assert.deepEqual([...this.piles], [...o.piles], what + ': piles differ'); }
  top(k = 0) { return this.st[this.st.length - 1 - k]; }
  // ---- stack moves ----
  pick(name, as) { const d = this.depth(name); if (d === 0) this.emit(OP.DUP); else if (d === 1) this.emit(OP.OVER); else this.emit(...pushNum(d), OP.PICK); this.st.push(as ?? name); return this; }
  roll(name) { const d = this.depth(name); if (d === 1) this.emit(OP.SWAP); else if (d === 2) this.emit(OP.ROT); else if (d > 2) this.emit(...pushNum(d), OP.ROLL); this.st.splice(this.idx(name), 1); this.st.push(name); return this; } // (symbolic index: d is physical)
  drop(name) { if (name !== undefined) { const d = this.depth(name); if (d === 1) { this.emit(OP.NIP); this.st.splice(this.st.length - 2, 1); return this; } if (d > 0) this.roll(name); } this.emit(OP.DROP); this.mk(this.st.pop()); return this; }
  rename(name, as) { if (as === undefined) { this.mk(this.st[this.st.length - 1]); this.st[this.st.length - 1] = name; return this; } this.st[this.idx(name)] = as; return this; }
  push(v, name) { this.emit(...pushNum(v)); this.st.push(name ?? this.fresh('c')); return this; }
  pushBytes(b, name) { this.emit(...pushData(b)); this.st.push(name ?? this.fresh('b')); return this; }
  // generic opcode: pops k items, pushes the named outputs
  op(code, pops, ...outs) { this.emit(code); assert.ok(this.st.length - pops > this.localFloor, 'op pops below local floor'); for (let i = 0; i < pops; i++) this.mk(this.st.pop()); this.st.push(...outs); return this; }
  mk(name) { if (this.touched) this.touched.add(name); return name; }
  bin(code, out) { return this.op(code, 2, out ?? this.fresh()); }
  verify(code = OP.VERIFY, pops = 1) { return this.op(code, pops); }
  // bring named items to the top in the given order (moving them); minimal: skips a prefix already in place
  arrange(names) {
    const n = names.length; const cur = this.st.slice(-n);
    if (cur.length === n && cur.every((x, i) => x === names[i])) return this;
    // find largest k such that names[0..k) are, in order, directly below nothing that must move:
    let k = 0; // greedy: keep names[0..k) if they already occupy the bottom of the top-n window in order
    const win = this.st.slice(-n); while (k < n && win[k] === names[k]) k++;
    // (fix vs the SI-GLS copy) the kept prefix must have only items that get rolled above it
    while (k > 0 && !win.slice(k).every((x) => names.slice(k).includes(x))) k--;
    for (let i = k; i < n; i++) this.roll(names[i]);
    return this;
  }
  // make the whole stack equal to `layout` (same multiset of names), with minimal rolls
  arrangeAll(layout) {
    assert.equal(this.st.length, layout.length, `layout size ${this.st.length} vs ${layout.length}: ${this.diff(layout)}`);
    assert.deepEqual([...this.st].sort(), [...layout].sort(), 'arrangeAll: different items ' + this.diff(layout));
    // shortest suffix of the target to roll: the rest must already be in order
    let j = layout.length;
    for (; j >= 0; j--) { const mv = new Set(layout.slice(j)); const keep = this.st.filter((x) => !mv.has(x)); if (keep.every((x, i) => x === layout[i])) break; }
    for (let i = j; i < layout.length; i++) this.roll(layout[i]);
    assert.deepEqual(this.st, layout, 'arrangeAll');
    return this;
  }
  // make the items above `base` equal to `list` (rolling up any listed item from below base), with minimal rolls
  arrangeAbove(base, list) {
    const seg = this.st.slice(this.st.lastIndexOf(base) + 1); assert.ok(this.st.includes(base), 'arrangeAbove: no ' + base);
    const extra = seg.filter((x) => !list.includes(x)); assert.equal(extra.length, 0, 'arrangeAbove: unexpected items above ' + base + ': ' + extra.join(','));
    assert.equal(new Set(list).size, list.length);
    let j = list.length;
    for (; j >= 0; j--) { const mv = new Set(list.slice(j)); const keep = seg.filter((x) => !mv.has(x)); if (list.slice(0, j).every((x) => seg.includes(x)) && keep.length === j && keep.every((x, i) => x === list[i])) break; }
    for (let i = j; i < list.length; i++) this.roll(list[i]);
    assert.deepEqual(this.st.slice(-list.length), list, 'arrangeAbove'); assert.equal(this.st[this.st.length - list.length - 1], base);
    return this;
  }
  diff(layout) { const a = new Set(this.st), b = new Set(layout); return `missing [${[...b].filter((x) => !a.has(x)).join(',')}] extra [${[...a].filter((x) => !b.has(x)).join(',')}]`; }
  // ---- control flow ----
  sub(stack = this.st) { const s = new Asm(stack, this.ctx); s.localFloor = this.localFloor; s.alt = [...this.alt]; s.piles = new Map(this.piles); s.touched = this.touched; return s; }
  ifElse(thenFn, elseFn, {layout} = {}) {
    this.mk(this.st.pop()); // condition
    const entry = this.st.slice();
    const a = this.sub(), b = this.sub();
    thenFn(a); if (elseFn) elseFn(b);
    const target = layout ?? (elseFn ? a.st.slice() : entry);
    a.arrangeAll(target); b.arrangeAll(target); a.sameCtx(b, 'if/else');
    const base = this.code.length + 1;
    if (b.code.length === 0) { this.absorb(a, base); this.emit(OP.IF, ...a.code, OP.ENDIF); }
    else if (a.code.length === 0) { this.absorb(b, base); this.emit(OP.NOTIF, ...b.code, OP.ENDIF); }
    else { this.absorb(a, base); this.absorb(b, base + a.code.length + 1); this.emit(OP.IF, ...a.code, OP.ELSE, ...b.code, OP.ENDIF); }
    this.st = a.st; this.alt = a.alt; this.piles = a.piles; return this;
  }
  // OP_BEGIN body OP_UNTIL: body(sub) must leave [entry layout..., cond]; loops while cond is false
  loop(body, {onExit} = {}) {
    const entry = this.st.slice(); const s = this.sub();
    body(s); const cond = s.top(); if (onExit) onExit(s.st.slice(0, -1)); s.arrangeAll([...entry, cond]); s.st.pop(); s.sameCtx(this, 'loop');
    this.absorb(s, this.code.length + 1); this.emit(OP.BEGIN, ...s.code, OP.UNTIL); return this;
  }
  // ---- functions ----
  // local function: body sees only its `ins` (top items, in order); returns names of outputs
  defLocal(name, nIn, nOut, body) { assert.ok(!this.ctx.funcs.has(name)); this.ctx.funcs.set(name, {kind: 'local', nIn, nOut, body, id: null}); return this; }
  defBound(name, body) { assert.ok(!this.ctx.funcs.has(name)); this.ctx.funcs.set(name, {kind: 'bound', body, id: null}); return this; }
  compileLocal(f) {
    const ins = Array.from({length: f.nIn}, (_, i) => `in${i}`);
    const s = new Asm(['__floor', ...ins], this.ctx); s.localFloor = 0;
    f.body(s, ins); assert.equal(s.st.length - 1, f.nOut, 'local function output count'); assert.equal(s.st[0], '__floor');
    return s.code;
  }
  invoke(name, outs) {
    const f = this.ctx.funcs.get(name); assert.ok(f, 'no function ' + name);
    if (f.id === null) {
      f.id = this.ctx.nextId++;
      if (f.kind === 'local') f.code = this.compileLocal(f);
      else {
        const s = this.sub(); s.touched = new Set(); f.entry = this.st.slice(); f.entryCtx = this.sub(); f.body(s); f.exit = s.st.slice(); f.exitCtx = s; f.code = s.code; f.touched = s.touched;
        // the window: the top W entry items, W = depth of the deepest entry item the body touches
        const E = f.entry.length; f.window = 0; f.touchedPos = new Map();
        for (const t of f.touched) { const i = f.entry.lastIndexOf(t); if (i < 0) continue; f.window = Math.max(f.window, E - i); f.touchedPos.set(t, {rel: E - i, phys: this.depth(t)}); }
        assert.deepEqual(f.exit.slice(0, E - f.window), f.entry.slice(0, E - f.window), `bound function ${name}: body disturbed items below its window`);
        for (const t of f.touched) if (this.touched) this.touched.add(t);
      }
      this.ctx.defs.push(f);
    }
    this.emit(...pushFunctionId(f.id), OP.INVOKE);
    if (f.kind === 'local') {
      assert.ok(this.st.length - f.nIn > this.localFloor);
      this.st.splice(this.st.length - f.nIn, f.nIn).forEach((n) => this.mk(n)); const o = outs ?? Array.from({length: f.nOut}, () => this.fresh('o')); assert.equal(o.length, f.nOut); this.st.push(...o);
    } else {
      // every touched item must sit at the same symbolic and physical depth; untouched items are carried through
      const L = this.st.length, E = f.entry.length, W = f.window; assert.ok(L >= W, `bound function ${name}: stack shorter than its window`);
      this.compatCtx(f.entryCtx, 'bound function ' + name);
      for (const [t, pos] of f.touchedPos) { const i = this.st.lastIndexOf(t); assert.ok(i >= 0 && L - i === pos.rel, `bound function ${name}: '${t}' at a different position`); assert.equal(this.depth(t), pos.phys, `bound function ${name}: '${t}' at a different physical depth`); }
      const top = this.st.slice(L - W), entryTop = f.entry.slice(E - W);
      const carried = entryTop.filter((n) => !f.touched.has(n)); assert.equal(new Set(carried).size, carried.length, `bound function ${name}: duplicate untouched names in the window`);
      this.st = [...this.st.slice(0, L - W), ...f.exit.slice(E - W).map((n) => (f.touched.has(n) || !entryTop.includes(n) ? n : top[entryTop.lastIndexOf(n)]))];
      if (this.touched) for (const t of f.touched) this.touched.add(t);
      this.alt = [...f.exitCtx.alt]; this.piles = new Map(f.exitCtx.piles);
    }
    return this;
  }
  // prologue that defines every function used (in id order); function bodies may invoke other functions
  prologue() { const out = []; for (const f of [...this.ctx.defs].sort((a, b) => a.id - b.id)) out.push(...pushData(f.code), ...pushFunctionId(f.id), OP.DEFINE); return out; }
  bytes() { return Uint8Array.from(this.code); }

  // ---- kernels ----
  // K: Kernel; ins: names consumed (may be anywhere in the stack); env: other referenced names (read-only);
  // outs: names given to the outputs, which end on top in order.
  kernel(K, outs, {iters = 3000, seed = 1, lazy = LAZY} = {}) {
    assert.equal(outs.length, K.outs.length);
    const res = scheduleKernel(this, K, iters, seed, lazy);
    if (process.env.DEBUG_K) console.error('kernel', outs.join(',').slice(0, 40), 'est op', res.cost, 'bytes', res.code.length);
    this.emit(...res.code); this.st = res.st; // outputs on top with internal ids
    for (let i = 0; i < outs.length; i++) this.st[this.st.length - outs.length + i] = outs[i];
    return res;
  }
}

// ---------------- kernel DAG ----------------
export class Kernel {
  constructor() { this.nodes = []; this.refs = new Map(); this.inputs = new Set(); }
  node(op, args, extra = {}) { const id = this.nodes.length; this.nodes.push({id, op, args, ...extra}); return id; }
  // reference a stack item; consumed=true: it is an input that is consumed at its last use
  ref(name, consumed = false, sample) { if (!this.refs.has(name)) { this.refs.set(name, this.node('ref', [], {name, sample})); } if (consumed) this.inputs.add(name); return this.refs.get(name); }
  in(name, sample) { return this.ref(name, true, sample); }
  env(name, sample) { return this.ref(name, false, sample); }
  c(v) { return this.node('const', [], {value: BigInt(v)}); }
  add(a, b) { return this.node('add', [a, b]); }
  sub(a, b) { return this.node('sub', [a, b]); }
  mul(a, b) { return this.node('mul', [a, b]); }
  mod(a) { return this.node('mod', [a]); }
  neg(a) { return this.node('neg', [a]); }
  mm(a, b) { return this.mod(this.mul(a, b)); }
  small(a, k) { return k === 1 ? a : k === 2 ? this.add(a, a) : this.mul(a, this.c(k)); }
  sum(...xs) { return xs.reduce((a, b) => this.add(a, b)); }
  output(...ids) { this.outs = ids.flat(); return this; }
  simulate(vals, P) {
    const v = [];
    for (const n of this.nodes) {
      const a = n.args.map((x) => v[x]);
      v[n.id] = n.op === 'ref' ? BigInt(vals(n)) : n.op === 'const' ? n.value : n.op === 'add' ? a[0] + a[1] : n.op === 'sub' ? a[0] - a[1]
        : n.op === 'mul' ? a[0] * a[1] : n.op === 'neg' ? -a[0] : a[0] % P;
    }
    return v;
  }
}

const COMM = new Set(['add', 'mul']);
const OPC = {add: OP.ADD, sub: OP.SUB, mul: OP.MUL};
function scheduleKernel(asm, K, iters, seed, lazy) {
  const N = K.nodes; const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
  // sample lengths: refs are 32-byte unless a sample is given
  let ctr = 7n; const sampleOf = (n) => (n.sample !== undefined ? n.sample : (ctr = (ctr * 6364136223846793005n + 1442695040888963407n) % (1n << 64n), (P - 1n) - ctr * 12345n));
  const samples = new Map(); for (const n of N) if (n.op === 'ref') samples.set(n.id, sampleOf(n)); // (same sequence as before)
  const sv = (n) => samples.get(n.id);
  const plan = (iters, final) => {
  const vals = K.simulate(sv, P); const lens = vals.map((x) => numLen(x)); lens.p = 32;
  // live nodes in topological order
  const live = new Set(); const stk = [...K.outs];
  while (stk.length) { const x = stk.pop(); if (live.has(x)) continue; live.add(x); stk.push(...N[x].args); }
  const order0 = N.filter((n) => live.has(n.id) && n.op !== 'ref').map((n) => n.id);
  const hasMod = order0.some((id) => N[id].op === 'mod');
  const pOnStack = asm.has('p');
  // emit/cost for an order
  const run = (order, want) => {
    const st = asm.st.slice(); const code = []; let cost = 0;
    const em = (...b) => { if (want) code.push(...b); };
    const uses = new Map(); const bump = (x) => uses.set(x, (uses.get(x) ?? 0) + 1);
    order.forEach((id) => N[id].args.forEach(bump)); K.outs.forEach(bump);
    // stack entries are names (strings) for pre-existing items and numbers for node results
    const keyOf = (id) => (N[id].op === 'ref' ? N[id].name : id);
    const consumable = (id) => N[id].op !== 'ref' || K.inputs.has(N[id].name);
    // returns [physical depth, index distance]; items below a pile of known size are reachable
    const depthOf = (key) => { if (asm.touched && typeof key === 'string') asm.touched.add(key); let ph = 0;
      for (let i = st.length - 1; i > asm.localFloor; i--) { if (st[i] === key) return [ph, st.length - 1 - i]; if (asm.piles.has(st[i])) { const c = asm.piles.get(st[i]); if (c === null) break; ph += c; } else ph++; }
      throw new Error('kernel: missing (or below a pile of varying size) ' + key); };
    const lenOf = (id) => lens[id];
    const fetch = (id) => {
      const key = keyOf(id); const last = consumable(id) && uses.get(id) === 1; uses.set(id, uses.get(id) - 1);
      const [d, di] = depthOf(key); const L = lenOf(id);
      if (last) {
        if (d === 0) return; if (d === 1) { em(OP.SWAP); cost += 100; } else if (d === 2) { em(OP.ROT); cost += 100; } else { em(...pushNum(d), OP.ROLL); cost += 200 + numLen(d) + L + d; }
        st.splice(st.length - 1 - di, 1); st.push(key);
      } else {
        if (d === 0) em(OP.DUP); else if (d === 1) em(OP.OVER); else { em(...pushNum(d), OP.PICK); cost += 100 + numLen(d); }
        cost += 100 + L; st.push(key);
      }
    };
    const fetchP = () => {
      if (pOnStack) { const [d] = depthOf('p'); if (d === 0) em(OP.DUP); else if (d === 1) em(OP.OVER); else { em(...pushNum(d), OP.PICK); cost += 101; } cost += 132; st.push('p'); }
      else { const f = asm.ctx.funcs.get('P'); assert.ok(f, 'p is not on the stack and no P function'); em('PINV'); cost += 100 + 100 + 133; st.push('p'); }
    };
    // drop unused consumable inputs first
    for (const name of K.inputs) { const id = K.refs.get(name); if (!uses.get(id)) { uses.set(id, 1); fetch(id); em(OP.DROP); cost += 100; st.pop(); } }
    for (const id of order) {
      const n = N[id];
      if (n.op === 'const') { em(...pushNum(n.value)); cost += 100 + lens[id]; st.push(id); continue; }
      if (n.op === 'mod') { fetch(n.args[0]); fetchP(); em(OP.MOD); cost += 100 + lenOf(n.args[0]) * 32 + 2 * lens[id]; st.pop(); st.pop(); st.push(id); continue; }
      if (n.op === 'neg') { fetch(n.args[0]); em(OP.NEGATE); cost += 100 + 2 * lens[id]; st.pop(); st.push(id); continue; }
      let [a, b] = n.args;
      if (a === b) { const last = consumable(a) && uses.get(a) === 2; if (last) { uses.set(a, 1); fetch(a); } else { fetch(a); uses.set(a, uses.get(a) - 1); } em(OP.DUP); cost += 100 + lenOf(a); st.push(keyOf(a)); }
      else {
        if (COMM.has(n.op)) { const c1 = pairCost(a, b), c2 = pairCost(b, a); if (c2 < c1) [a, b] = [b, a]; }
        fetch(a); fetch(b);
      }
      em(OPC[n.op]); cost += 100 + 2 * lens[id] + (n.op === 'mul' ? lenOf(a) * lenOf(b) : 0); st.pop(); st.pop(); st.push(id);
    }
    for (const o of K.outs) fetch(o);
    return {code, cost, st};
    function pairCost(a, b) {
      const s2 = st.slice(); let c = 0;
      for (const [k, id] of [a, b].entries()) {
        const key = keyOf(id); const last = consumable(id) && uses.get(id) === 1 && !(k === 1 && a === id);
        let d = -1; for (let i = s2.length - 1; i >= 0; i--) if (s2[i] === key) { d = s2.length - 1 - i; break; }
        c += last ? (d === 0 ? 0 : d <= 2 ? 100 : 300 + d) : 200;
        if (last && d >= 0) s2.splice(s2.length - 1 - d, 1); s2.push(key);
      }
      return c;
    }
  };
  let order = order0; let best = run(order, false).cost;
  const succ = new Map(); for (const id of order) for (const a of N[id].args) { if (!succ.has(a)) succ.set(a, []); succ.get(a).push(id); }
  let s = seed; const rnd = (n) => { s = (s * 1103515245 + 12345) % 2147483648; return s % n; };
  for (let it = 0; it < iters; it++) {
    const i = rnd(order.length), id = order[i]; const pos = new Map(order.map((x, j) => [x, j]));
    let lo = 0, hi = order.length - 1;
    for (const a of N[id].args) if (pos.has(a)) lo = Math.max(lo, pos.get(a) + 1);
    for (const sId of succ.get(id) ?? []) if (pos.has(sId)) hi = Math.min(hi, pos.get(sId) - 1);
    if (hi <= lo) continue;
    const j = lo + rnd(hi - lo + 1); if (j === i) continue;
    const cand = order.slice(); cand.splice(i, 1); cand.splice(j, 0, id);
    const c = run(cand, false).cost; if (c <= best) { best = c; order = cand; }
  }
  return final ? {out: run(order, true), hasMod} : best;
  };
  // lazy reduction (extension (4) vs the SI-GLS copy): greedily bypass an interior MOD node when the scheduled cost
  // (short schedule) decreases. Never an output, and every path to an output must still pass through a MOD, so all
  // outputs stay reduced; values are unchanged mod p.
  let orig = null;
  if (lazy) {
    orig = N.map((n) => n.args.slice());
    const LI = 300; let base = plan(LI, false); const outSet = new Set(K.outs);
    const usersOf = (id) => N.filter((u) => u.args.includes(id));
    const reachesRaw = (id, seen = new Set()) => { if (seen.has(id)) return false; seen.add(id); return usersOf(id).some((u) => u.op !== 'mod' && (outSet.has(u.id) || reachesRaw(u.id, seen))); };
    for (const n of N) {
      if (n.op !== 'mod' || outSet.has(n.id)) continue; const users = usersOf(n.id); if (!users.length || reachesRaw(n.id)) continue;
      const saved = users.map((u) => u.args.slice()); users.forEach((u) => { u.args = u.args.map((x) => (x === n.id ? n.args[0] : x)); });
      const c = plan(LI, false); if (c < base) base = c; else users.forEach((u, i) => { u.args = saved[i]; });
    }
  }
  // keep the lazy DAG only if its full schedule is cheaper than the original's
  if (lazy) { const cl = plan(iters, false); const mod = N.map((n) => n.args.slice()); N.forEach((n, i) => { n.args = orig[i]; }); const co = plan(iters, false);
    if (process.env.DEBUG_LAZY) console.error('lazy', co, '->', cl);
    if (cl < co) N.forEach((n, i) => { n.args = mod[i]; }); }
  const {out, hasMod} = plan(iters, true);
  // resolve the P-invoke placeholder
  const code = []; for (const b of out.code) { if (b === 'PINV') { const f = asm.ctx.funcs.get('P'); if (f.id === null) { f.id = asm.ctx.nextId++; f.code = asm.compileLocal(f); asm.ctx.defs.push(f); } code.push(...pushFunctionId(f.id), OP.INVOKE); } else code.push(b); }
  // the symbolic stack: replace numeric keys of outputs; everything else must be gone
  const st = out.st.map((x) => (typeof x === 'number' ? `__k${x}` : x));
  const extra = st.length - asm.st.length + [...K.inputs].length - K.outs.length;
  if (extra !== 0) throw new Error('kernel left stray items: ' + extra);
  return {code, st, cost: out.cost, hasMod};
}
