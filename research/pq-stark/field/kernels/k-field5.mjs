// Track 5 field-cost kernels: the field arithmetic of the Track 4 SHA-256 STARK verifier and the Track 5 replacements,
// measured on libauth 3.1.0-next.8 BCH_2026 with the Track 4 kernel harness (../../../pq-hash/kernels/lib/measure.mjs).
//
// Every kernel uses the generator's own code: the Track 4 functions (generator modes fp 'grp', fold 'pair', deep 'pt')
// and the Track 5 ones (fp 'gpd', fold 'rot' / 'pk', deep 'pk', xtab) are built by makeCtx/defineShared of the Track 5
// generator copy (groth16_cashscript wip/pq-stark-field, research/pq-stark/field/verifier/gen.mjs; path in
// PQ_FIELD_SRC, default: the sibling worktree). Each case pushes random inputs, runs the code and compares every output
// with an independent JS BigInt reference (OP_NUMEQUALVERIFY / OP_EQUALVERIFY), so an accepted run is a correctness check.
// Reference: plain F_p / F_p^3 arithmetic (Ext of field.mjs is not used here; ref3 below is written from the definition
// u^3 = 7), the fold from its even/odd definition, the final polynomial by Horner, DEEP by its defining formula.
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, resolve} from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SRC = process.env.PQ_FIELD_SRC ?? resolve(here, '../../../../../g16/research/pq-stark/field/verifier');
const VEC = process.env.PQ_VECTOR ?? resolve(SRC, '../../../pq-hash/prover/vectors/P128-0.json');
const gen = await import(resolve(SRC, 'gen.mjs'));
const {asm, Stk, numBytes} = await import(resolve(SRC, 'lib/asm.mjs'));
const {compileSlp, V, K, chk} = await import(resolve(SRC, 'lib/slp.mjs'));
const {makeParams} = await import(resolve(SRC, 'params.mjs'));
const {makeCtx, defineShared, PB, emitFinalGpd, emitFinalGrp, emitUnpackGpd, emitUnpack, SK} = gen;

const P = (1n << 64n) - (1n << 32n) + 1n;
const md = (a) => ((a % P) + P) % P;
const powp = (b, e) => { let r = 1n; b = md(b); e = BigInt(e); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; };
const invp = (a) => powp(a, P - 2n);
const rou = (k) => powp(7n, (P - 1n) / BigInt(k));
const nb = (v) => numBytes(BigInt(v));
// independent F_p^e reference (u^e = 7), schoolbook from the definition
const ref = (e) => ({
  mul: (a, b) => { const c = Array(2 * e - 1).fill(0n); for (let i = 0; i < e; i++) for (let j = 0; j < e; j++) c[i + j] += a[i] * b[j]; for (let k = 2 * e - 2; k >= e; k--) c[k - e] += 7n * c[k]; return c.slice(0, e).map(md); },
  add: (a, b) => a.map((x, i) => md(x + b[i])), sub: (a, b) => a.map((x, i) => md(x - b[i])), sc: (a, s) => a.map((x) => md(x * s)),
});
const pack = (vals, sb) => vals.reduce((acc, v, k) => acc + (v << BigInt(8 * sb * k)), 0n);
// rotation columns (numbers): column k = b * u^k
const colsOf = (e, b, sb) => Array.from({length: e}, (_, k) => pack(Array.from({length: e}, (_, j) => (j >= k ? b[j - k] : 7n * b[j - k + e])), sb));

const vec = JSON.parse(readFileSync(VEC, 'utf8'));
const PRM = makeParams(vec.params);
const ctxCache = new Map();
function ctx(opts = {}, prmOver = {}) {
  const key = JSON.stringify(opts) + JSON.stringify(prmOver);
  if (!ctxCache.has(key)) { const c = makeCtx({...PRM, ...prmOver}, opts); defineShared(c); ctxCache.set(key, c); }
  return ctxCache.get(key);
}
const defsOf = (c) => [...c.fns.values()].map((f) => ({id: f.id, body: f.body}));
const T4 = {fp: 'grp', fold: 'pair', deep: 'pt', xtab: false};
const T5 = {};
const enc = (x) => (x instanceof Uint8Array ? x : nb(x));
// a function kernel: args pushed (first deepest), `<id> OP_INVOKE`, outputs checked
function fnCase(c, name, args, outs) {
  const f = c.fns.get(name);
  if (!f) throw new Error('no function ' + name);
  return {inputs: args.map(enc), defs: defsOf(c), body: asm(f.id, 'INVOKE'), outputs: outs.map((o) => (o instanceof Uint8Array ? {bin: o} : {num: o}))};
}
// an inline kernel compiled on a symbolic stack
function stkCase(c, inNames, inVals, build, outs) {
  const st = new Stk(inNames);
  build(st);
  return {inputs: inVals.map(enc), defs: defsOf(c), body: Uint8Array.from(st.code), outputs: outs.map((o) => (o instanceof Uint8Array ? {bin: o} : {num: o}))};
}

const kernels = [];
const def = (id, group, name, build, notes = '', trials = 8, extra) => kernels.push({id, group, name, build, notes, trials, extra});
const r = (rng) => rng.below(P), r64 = (rng) => rng.below(1n << 64n);
const rv = (rng, e, f = r) => Array.from({length: e}, () => f(rng));
const N = (b, e) => Array.from({length: e}, (_, i) => b + i);

// ---------------- A: extension multiplication, lazy reduction ----------------
for (const e of [3, 2]) {
  const R = ref(e);
  def('A1', 'ext-mul', `F_p^${e} mul, schoolbook lazy (Track 4 MULE, one OP_MOD per coefficient), as a function`, (rng) => {
    const a = rv(rng, e), b = rv(rng, e); return fnCase(ctx(T4, {e}), 'MULE', [...a, ...b], R.mul(a, b)); });
}
def('A2', 'ext-mul', 'F_p^3 times a per-proof constant beta: Track 4 MULE with beta as arguments', (rng) => {
  const a = rv(rng, 3), b = rv(rng, 3); return fnCase(ctx(T4), 'MULE', [...a, ...b], ref(3).mul(a, b)); });
def('A2', 'ext-mul', 'F_p^3 times a per-proof constant beta: packed rotation columns (3 OP_MUL + unpack + 3 OP_MOD), inline', (rng) => {
  const w = rv(rng, 3), b = rv(rng, 3); const c = ctx(T5);
  return stkCase(c, ['R0', 'R1', 'R2', 'w0', 'w1', 'w2'], [...colsOf(3, b, 17), ...w], (st) => {
    const pb = new PB(3); pb.let(V('w0'), 'x'); // placeholder to reuse compileSlp: T = sum w_k R_k
    pb.prog.length = 0; pb.let({t: 'op', o: 'ADD', args: [{t: 'op', o: 'ADD', args: [{t: 'op', o: 'MUL', args: [V('w0'), V('R0')]}, {t: 'op', o: 'MUL', args: [V('w1'), V('R1')]}]}, {t: 'op', o: 'MUL', args: [V('w2'), V('R2')]}]}, 'T');
    compileSlp(st, pb.prog); st.raw(gen.unpackCode(3, 17, true), 1, ['c0', 'c1', 'c2']);
  }, ref(3).mul(w, b)); }, 'per-proof cost: the 3 columns (COLS, measured below)');
def('A2', 'ext-mul', 'rotation columns of a per-proof constant (COLS, 17-byte slots), once per constant', (rng) => {
  const b = rv(rng, 3); return fnCase(ctx(T5, {}), 'COLS', b, colsOf(3, b, 17)); });
def('A3', 'lazy', 'a*b + c*d in F_p^3: two MULE + ADDE (each reduced, Track 4 style)', (rng) => {
  const [a, b, x, d] = [0, 1, 2, 3].map(() => rv(rng, 3)); const c = ctx(T4); const R = ref(3);
  return stkCase(c, [...N('a', 3), ...N('b', 3), ...N('x', 3), ...N('d', 3)], [...a, ...b, ...x, ...d], (st) => {
    const pb = new PB(3, c.F); const p1 = pb.mul(N('a', 3), N('b', 3)), p2 = pb.mul(N('x', 3), N('d', 3)); pb.add(p1, p2, N('o', 3)); compileSlp(st, pb.prog); st.arrange(N('o', 3));
  }, R.add(R.mul(a, b), R.mul(x, d))); });
def('A3', 'lazy', 'a*b + c*d in F_p^3: lazy, 18 products, one OP_MOD per coefficient, inline', (rng) => {
  const [a, b, x, d] = [0, 1, 2, 3].map(() => rv(rng, 3)); const c = ctx(T5); const R = ref(3);
  return stkCase(c, [...N('a', 3), ...N('b', 3), ...N('x', 3), ...N('d', 3)], [...a, ...b, ...x, ...d], (st) => {
    const pb = new PB(3); const s1 = gen.mulE(3, N('a', 3), N('b', 3)), s2 = gen.mulE(3, N('x', 3), N('d', 3));
    s1.forEach((t, k) => pb.red({t: 'op', o: 'ADD', args: [t, s2[k]]}, 'o' + k)); compileSlp(st, pb.prog); st.arrange(N('o', 3));
  }, R.add(R.mul(a, b), R.mul(x, d))); });

// ---------------- B: fold pair and fold per coset (arity) ----------------
const pairRef = (u, v, beta, xi) => { const R = ref(3); const s = R.add(u.map(md), v.map(md)), d = R.sub(u.map(md), v.map(md)); return R.add(s, R.mul(R.sc(beta, xi), d)); };
def('B1', 'fold', 'fold pair u + v + beta x^-1 (u - v): Track 4 MULF (g = beta x^-1) + PAIR (MULE inside)', (rng) => {
  const u = rv(rng, 3, r64), v = rv(rng, 3, r64), beta = rv(rng, 3), xi = r(rng); const c = ctx(T4);
  return stkCase(c, [...N('b', 3), 'xi', ...N('u', 3), ...N('v', 3)], [...beta, xi, ...u, ...v], (st) => {
    const pb = new PB(3, c.F); const g = pb.mulF(N('b', 3), 'xi'); pb.call(c.F.PAIR, [...g, ...N('u', 3), ...N('v', 3)], 3, N('o', 3)); compileSlp(st, pb.prog); st.arrange(N('o', 3));
  }, pairRef(u, v, beta, xi)); });
def('B1', 'fold', 'fold pair: PAIRP (rotation columns of beta, 17-byte slots; unpacked values)', (rng) => {
  const u = rv(rng, 3, r64), v = rv(rng, 3, r64), beta = rv(rng, 3), xi = r(rng);
  return fnCase(ctx({fold: 'rot'}), 'PAIRP', [...colsOf(3, beta, 17), xi, ...u, ...v], pairRef(u, v, beta, xi)); });
def('B1', 'fold', 'fold pair: PAIRK (packed values, 26-byte slots) + UR (unpack, reduce)', (rng) => {
  const u = rv(rng, 3, r64), v = rv(rng, 3, r64), beta = rv(rng, 3), xi = r(rng); const c = ctx(T5);
  return stkCase(c, ['R0', 'R1', 'R2', 'xi', 'u', 'v'], [...colsOf(3, beta, SK), xi, pack(u, SK), pack(v, SK)], (st) => {
    st.raw([c.F.PAIRK, 'INVOKE', c.F.UR, 'INVOKE'], 6, N('o', 3)); }, pairRef(u, v, beta, xi)); }, 'the UR is paid once per fold, not per pair');
// fold of a coset of arity a (unscaled: a times the folded value), from the even/odd definition
function foldRef(vals, beta, xinv, a) {
  // F_t = sum_j v_j w^-jt ; fold = sum_t (beta xinv)^t F_t  (equals a * sum_t beta^t f_t)
  const R = ref(3), w = rou(a), g = R.sc(beta, xinv);
  let acc = [0n, 0n, 0n];
  for (let t = a - 1; t >= 0; t--) {
    let Ft = [0n, 0n, 0n];
    for (let j = 0; j < a; j++) Ft = R.add(Ft, R.sc(vals[j].map(md), powp(invp(w), BigInt(j * t))));
    acc = R.add(R.mul(acc, g), Ft);
  }
  return acc;
}
for (const ai of [2, 4, 8, 16]) {
  const L = Math.log2(ai);
  const bpow = (beta) => Array.from({length: L}, (_, l) => { let b = beta; for (let i = 0; i < l; i++) b = ref(3).mul(b, b); return b; });
  const prmA = {a: [16, 8, 4, 2], r: 4};
  def('B2', 'fold', `FRI fold, arity ${ai}: Track 4 FOLD${ai} (binary folds, MULF + PAIR)`, (rng) => {
    const vals = Array.from({length: ai}, () => rv(rng, 3, r64)), beta = rv(rng, 3), xi = r(rng); const c = ctx(T4, prmA);
    return fnCase(c, 'FOLD' + ai, [...vals.flat(), ...bpow(beta).flat(), xi], foldRef(vals, beta, xi, ai)); });
  def('B2', 'fold', `FRI fold, arity ${ai}: Track 5 FOLD${ai} (packed values, PAIRK) + UR`, (rng) => {
    const vals = Array.from({length: ai}, () => rv(rng, 3, r64)), beta = rv(rng, 3), xi = r(rng); const c = ctx(T5, prmA);
    const names = [...N('v', ai), ...Array.from({length: L}, (_, l) => N(`b${l}_`, 3)).flat(), 'X'];
    return stkCase(c, names, [...vals.map((v) => pack(v, SK)), ...bpow(beta).flatMap((b) => colsOf(3, b, SK)), xi], (st) => {
      st.raw([c.F['FOLD' + ai], 'INVOKE', c.F.UR, 'INVOKE'], names.length, N('o', 3)); }, foldRef(vals, beta, xi, ai)); }, 'columns of beta^(2^l) are per-proof constants (COLSK)');
}

// ---------------- B3: DEEP at one point ----------------
function deepCase(rng, mode) {
  const R = ref(3);
  const X = r64(rng), Y = r64(rng), H0 = rv(rng, 3, r64), H1 = rv(rng, 3, r64), a1 = rv(rng, 3), n1 = r(rng), a2 = rv(rng, 3), n2 = r(rng);
  const g = [1, 2, 3, 4, 5].map(() => rv(rng, 3)), C1 = rv(rng, 3), C2 = rv(rng, 3);
  const num1 = R.sub(R.add(R.add(R.sc(g[0], X), R.sc(g[1], Y)), R.add(R.mul(g[3], H0.map(md)), R.mul(g[4], H1.map(md)))), C1);
  const num2 = R.sub(R.sc(g[2], X), C2);
  const f0 = R.add(R.mul(num1, R.sc(a1, n1)), R.mul(num2, R.sc(a2, n2)));
  const data = [X, Y, ...H0, ...H1, ...a1, n1, ...a2, n2];
  if (mode === 'pt') return fnCase(ctx(T4), 'DEEPPT', [...data, ...g.flat(), ...C1, ...C2], f0);
  const pk = [pack(g[0], 17), pack(g[1], 17), ...colsOf(3, g[3], 17), ...colsOf(3, g[4], 17), pack(C1.map((x) => P - x), 17), pack(g[2], 17), pack(C2.map((x) => P - x), 17)];
  return fnCase(ctx(T5), 'DPK', [...data, ...pk], [pack(f0, SK)]);
}
def('B3', 'deep', 'DEEP at one point: Track 4 DEEPPT (MULF, MULE calls; 25 per-proof constants as arguments)', (rng) => deepCase(rng, 'pt'));
def('B3', 'deep', 'DEEP at one point: Track 5 DPK (packed numerators, 11 packed constants, lazy f0, packed output)', (rng) => deepCase(rng, 'pk'));

// ---------------- B4: final polynomial, per query and per proof ----------------
const finRef = (C, y) => { const R = ref(3); let acc = [0n, 0n, 0n]; for (let i = C.length - 1; i >= 0; i--) acc = R.add(R.sc(acc, y), C[i].map(md)); return acc; };
const finBytes = (C) => Uint8Array.from(C.flatMap((c) => c.flatMap((x) => Array.from({length: 8}, (_, i) => Number((x >> BigInt(8 * i)) & 255n)))));
for (const D of [32, 64, 128, 256]) {
  const prmD = {D, a: [1], r: 1};
  def('B4', 'final', `final polynomial per query, D = ${D}: Track 4 (packed coefficients, GRP groups of 32 + HORN)`, (rng) => {
    const C = Array.from({length: D}, () => rv(rng, 3, r64)), y = r(rng); const c = ctx(T4, prmD);
    const Cn = N('C', D), Cv = C.map((x) => pack(x, 17));
    return stkCase(c, [...Cn, 'xb', 'F0', 'F1', 'F2'], [...Cv, y, ...finRef(C, y)], (st) => emitFinalGrp(c, st, 'xb', ['F0', 'F1', 'F2']), Cv);
  }, 'outputs: the coefficients left on the stack (checked unchanged)', 4);
  for (const H of [4, 8, 16].filter((h) => h <= D / 2)) {
    def('B4', 'final', `final polynomial per query, D = ${D}: Track 5 group-packed dot product, H = ${H} (G = ${D / H})`, (rng) => {
      const C = Array.from({length: D}, () => rv(rng, 3, r64)), y = r(rng); const c = ctx({gpdH: H}, prmD);
      const G = D / H, Pv = Array.from({length: G}, (_, k) => pack(Array.from({length: H}, (_, m) => C[k + G * m]).flat(), 17));
      return stkCase(c, [...N('P', G), 'xb', 'F0', 'F1', 'F2'], [...Pv, y, ...finRef(C, y)], (st) => emitFinalGpd(c, st, 'xb', ['F0', 'F1', 'F2']), Pv);
    }, 'outputs: the packed groups left on the stack', 4);
  }
  def('B4', 'final', `final polynomial per proof (unpack FIN), D = ${D}: Track 4 (16-coefficient chunks -> packed coefficients)`, (rng) => {
    const C = Array.from({length: D}, () => rv(rng, 3, r64)); const c = ctx(T4, prmD);
    return stkCase(c, ['FIN'], [finBytes(C)], (st) => emitUnpack(c, st), C.map((x) => pack(x, 17))); }, '', 2);
  def('B4', 'final', `final polynomial per proof (regroup FIN), D = ${D}: Track 5 group-packed, H = 8`, (rng) => {
    const C = Array.from({length: D}, () => rv(rng, 3, r64)); const c = ctx({gpdH: 8}, prmD); const G = D / 8;
    return stkCase(c, ['FIN'], [finBytes(C)], (st) => emitUnpackGpd(c, st), Array.from({length: G}, (_, k) => pack(Array.from({length: 8}, (_, m) => C[k + G * m]).flat(), 17)));
  }, '', 2);
}

// ---------------- C: inversions (DEEP denominators: 8 norms and x0 per query) ----------------
function batchCase(rng, mode, n = 9) {
  const xs = Array.from({length: n}, () => r(rng) || 1n); const inv = xs.map(invp); const c = ctx(T5);
  if (mode === 'batch') {
    // Montgomery: prefix products, one hinted inverse T of the product (checked), back-substitution (all via MM)
    const T = invp(xs.reduce((a, b) => a * b % P, 1n));
    return stkCase(c, [...N('x', n), 'T'], [...xs, T], (st) => {
      const b = new PB(3, c.F); const pre = ['x0'];
      for (let m = 1; m < n; m++) pre.push(b.mm(pre[m - 1], 'x' + m));
      b.chk(chk('NUMEQUALVERIFY', V(b.mm(pre[n - 1], 'T')), K(1)));
      const out = new Array(n); let Tm = 'T';
      for (let m = n - 1; m >= 1; m--) { out[m] = b.mm(Tm, pre[m - 1]); Tm = b.mm(Tm, 'x' + m); }
      out[0] = Tm; compileSlp(st, b.prog); st.arrange(out);
    }, inv);
  }
  // every inverse witnessed (8 B each) and checked x * xi == 1 (mod p)
  return stkCase(c, [...N('x', n), ...N('i', n)], [...xs, ...inv], (st) => {
    const b = new PB(3, c.F); for (let m = 0; m < n; m++) b.chk(chk('NUMEQUALVERIFY', {t: 'op', o: 'MOD', args: [{t: 'op', o: 'MUL', args: [V('x' + m), V('i' + m)]}, K(P)]}, K(1)));
    compileSlp(st, b.prog, {keep: N('i', n)}); st.arrange(N('i', n));
  }, inv);
}
def('C1', 'inverse', 'invert 9 F_p values (8 DEEP norms and x0): Montgomery batch, one witnessed inverse (+8 proof bytes)', (rng) => batchCase(rng, 'batch'));
def('C1', 'inverse', 'invert 9 F_p values: every inverse witnessed and checked x * x^-1 == 1 (+72 proof bytes)', (rng) => batchCase(rng, 'wit'));

// ---------------- D: x0 = 7 w^idx ----------------
{
  const w = rou(PRM.sizes[0]), bits = Math.log2(PRM.sizes[1]), nw = Math.ceil(bits / 4);
  def('D1', 'x0', `x0 = 7 w^idx (idx < 2^${bits}): Track 4 XPOW, square and multiply`, (rng) => {
    const idx = rng.below(BigInt(PRM.sizes[1])); return fnCase(ctx(T4), 'XPOW', [idx], [md(7n * powp(w, idx))]); });
  def('D1', 'x0', 'x0: Track 4 fast XPOW, 4-bit windows from tables in the code (+768 B code)', (rng) => {
    const idx = rng.below(BigInt(PRM.sizes[1])); return fnCase(ctx({...T4, fast: true}), 'XPOW', [idx], [md(7n * powp(w, idx))]); });
  def('D1', 'x0', `x0: Track 5 runtime 4-bit window tables on the stack (${nw} x 16 values, built once per proof)`, (rng) => {
    const idx = rng.below(BigInt(PRM.sizes[1])); const c = ctx(T5);
    const tn = [], tv = [];
    for (let k = 0; k < nw; k++) for (let j = 0; j < 16; j++) { tn.push(`XT${k}_${j}`); tv.push(md((k === 0 ? 7n : 1n) * powp(w, BigInt(j) << BigInt(4 * k)))); }
    return stkCase(c, [...tn, 'idx'], [...tv, idx], (st) => {
      st.pick('idx', 'v');
      for (let k = 0; k < nw; k++) {
        const last = k === nw - 1;
        if (!last) st.raw(['DUP'], 0, ['n']);
        const d = st.depth(`XT${k}_0`) - 1;
        st.raw([...(last ? [] : [16, 'MOD']), d, 'SWAP', 'SUB', 'PICK'], 1, ['t']);
        if (k === 0) { if (last) { st.rename('t', 'x0'); break; } st.raw(['SWAP', 4, 'RSHIFTNUM'], 2, ['x', 'v']); continue; }
        if (last) { st.raw(['MUL', P, 'MOD'], 2, ['x0']); break; }
        st.raw(['ROT', 'MUL', P, 'MOD', 'SWAP', 4, 'RSHIFTNUM'], 3, ['x', 'v']);
      }
      st.roll('idx'); st.raw(['DROP'], 1);
    }, [...tv, md(7n * powp(w, idx))]);
  }, 'per query; outputs include the tables (left unchanged)');
}

// ---------------- E: leaf parsing ----------------
def('E1', 'parse', 'parse 64 leaf bytes into 8 F_p values (Track 4 PARSE8)', (rng) => {
  const v = rv(rng, 8, r64); return fnCase(ctx(T4), 'PARSE8', [finBytes([v.slice(0, 3), v.slice(3, 6), [...v.slice(6), 0n]]).subarray(0, 64)], v); });
def('E1', 'parse', 'parse a 192-byte FRI leaf into 8 packed F_p^3 values (Track 5 PKL, 26-byte slots)', (rng) => {
  const vals = Array.from({length: 8}, () => rv(rng, 3, r64)); return fnCase(ctx(T5), 'PKL', [finBytes(vals)], vals.map((v) => pack(v, SK))); });

export default kernels;
