// Track 6 design: VM-measured op-cost of the kernels a CashVM PLONK/KZG verifier needs that the Groth16
// sources do not already measure: BN254 G1 Jacobian doubling / mixed addition / full addition (the MSM),
// one Fr multiply-mod, and the fixed-G2 "event" of the KZG pairing (two baked SI delta-type chains, one per
// SRS point [1]_2 and [x]_2, plus the F+- update). Kernels are scheduled with the SI-GLS kernel compiler
// (groth16_cashscript chunked/bn254/sound-si-gls/asm.mjs) and run in the libauth BCH_2026 VM (standard).
//
//   S=<dir with symlinks g16 -> groth16_cashscript and node_modules -> this checkout's node_modules>
//   G16=$S/g16 node --preserve-symlinks research/plonk-kzg/kernels.mjs > research/plonk-kzg/kernels.json
//
// Every kernel output is checked twice: against the DAG simulation (compilation) and, for the G1 kernels,
// against noble's point arithmetic (formulas).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';

const G16 = process.env.G16;
assert.ok(G16, 'set G16 to the groth16_cashscript checkout (see header)');
const {Asm, Kernel} = await import(`${G16}/chunked/bn254/sound-si-gls/asm.mjs`);
const {kDStep} = await import(`${G16}/chunked/bn254/sound-si-gls/script.mjs`);
const {runBare, numPush, num} = await import(`${G16}/research/sound-bn254-native/prototypes/vm26.mjs`);

const p = bn254.fields.Fp.ORDER;
const mod = (x) => ((x % p) + p) % p;
const ITERS = Number(process.env.SCHED_ITERS ?? 3000);
const ops = (k) => ({I: (n) => k.in(n), E: (n) => k.env(n), m: (x) => k.mod(x), mul: (a, b) => k.mul(a, b),
  add: (a, b) => k.add(a, b), sub: (a, b) => k.sub(a, b)});

// ---- G1 Jacobian doubling, a = 0 (EFD dbl-2009-l): 2M + 5S
function kG1Dbl() {
  const k = new Kernel(); const {I, m, mul, add, sub} = ops(k);
  const [X, Y, Z] = ['X', 'Y', 'Z'].map(I);
  const A = m(mul(X, X)), B = m(mul(Y, Y)), C = m(mul(B, B));
  const xb = add(X, B); const D = m(k.small(sub(sub(mul(xb, xb), A), C), 2));
  const E = k.small(A, 3); const F = m(mul(E, E));
  const X3 = m(sub(F, add(D, D)));
  const Y3 = m(sub(mul(E, sub(D, X3)), k.small(C, 8)));
  const Z3 = m(k.small(mul(Y, Z), 2));
  return k.output(X3, Y3, Z3);
}
// ---- G1 Jacobian + affine (EFD madd-2007-bl): 7M + 4S; also outputs H mod p (exceptional-case guard H != 0)
function kG1MAdd() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [X1, Y1, Z1] = ['X', 'Y', 'Z'].map(I); const [x2, y2] = ['qx', 'qy'].map(I);
  const Z1Z1 = m(mul(Z1, Z1)); const U2 = m(mul(x2, Z1Z1)); const S2 = m(mul(mul(y2, Z1), Z1Z1));
  const H = m(sub(U2, X1)); const HH = m(mul(H, H)); const I4 = k.small(HH, 4); const J = m(mul(H, I4));
  const rr = k.small(sub(S2, Y1), 2); const V = m(mul(X1, I4));
  const X3 = m(sub(sub(mul(rr, rr), J), add(V, V)));
  const Y3 = m(sub(mul(rr, sub(V, X3)), k.small(mul(Y1, J), 2)));
  const zh = add(Z1, H); const Z3 = m(sub(sub(mul(zh, zh), Z1Z1), HH));
  return k.output(X3, Y3, Z3, H);
}
// ---- G1 Jacobian + Jacobian (EFD add-2007-bl): 11M + 5S; outputs H mod p as the guard
function kG1Add() {
  const k = new Kernel(); const {I, m, mul, add, sub} = ops(k);
  const [X1, Y1, Z1, X2, Y2, Z2] = ['X', 'Y', 'Z', 'X2', 'Y2', 'Z2'].map(I);
  const Z1Z1 = m(mul(Z1, Z1)), Z2Z2 = m(mul(Z2, Z2));
  const U1 = m(mul(X1, Z2Z2)), U2 = m(mul(X2, Z1Z1));
  const S1 = m(mul(mul(Y1, Z2), Z2Z2)), S2 = m(mul(mul(Y2, Z1), Z1Z1));
  const H = m(sub(U2, U1)); const h2 = k.small(H, 2); const I4 = m(mul(h2, h2)); const J = m(mul(H, I4));
  const rr = k.small(sub(S2, S1), 2); const V = m(mul(U1, I4));
  const X3 = m(sub(sub(mul(rr, rr), J), add(V, V)));
  const Y3 = m(sub(mul(rr, sub(V, X3)), k.small(mul(S1, J), 2)));
  const zz = add(Z1, Z2); const Z3 = m(mul(sub(sub(mul(zz, zz), Z1Z1), Z2Z2), H));
  return k.output(X3, Y3, Z3, H);
}
// ---- G1 affine addition with a witnessed slope l (32 B): require l (x2 - x1) == y2 - y1 and x2 != x1 (outputs the two
// guard values, both mod p: chk must be 0, ex must be nonzero); x3 = l^2 - x1 - x2, y3 = l (x1 - x3) - y1
function kG1AffAddW() {
  const k = new Kernel(); const {I, m, mul, add, sub} = ops(k);
  const [x1, y1, x2, y2, l] = ['x1', 'y1', 'qx', 'qy', 'l'].map(I);
  const dx = sub(x2, x1);
  const chk = m(sub(mul(l, dx), sub(y2, y1))); const ex = m(dx);
  const x3 = m(sub(sub(mul(l, l), x1), x2)); const y3 = m(sub(mul(l, sub(x1, x3)), y1));
  return k.output(x3, y3, chk, ex);
}
// ---- G1 affine doubling with a witnessed slope l: require 2 y l == 3 x^2 (y != 0 holds on G1: odd order);
// x3 = l^2 - 2x, y3 = l (x - x3) - y
function kG1AffDblW() {
  const k = new Kernel(); const {I, m, mul, add, sub} = ops(k);
  const [x, y, l] = ['x1', 'y1', 'l'].map(I);
  const chk = m(sub(k.small(mul(y, l), 2), k.small(mul(x, x), 3)));
  const x3 = m(sub(mul(l, l), add(x, x))); const y3 = m(sub(mul(l, sub(x, x3)), y));
  return k.output(x3, y3, chk);
}
// ---- one modular multiply (Fr work has the same operand sizes: r and p are both 254-bit)
function kMulMod() { const k = new Kernel(); return k.output(k.mod(k.mul(k.in('a'), k.in('b')))); }
// ---- one modular multiply-accumulate acc + a*b (Horner / folding step)
function kMulAdd() { const k = new Kernel(); return k.output(k.mod(k.add(k.in('acc'), k.mul(k.in('a'), k.in('b'))))); }

// ---- fixed-G2 chain step (the SI delta step, kDStep), as a sub-DAG with its own names; returns L(+-z) at P
// state (x, c, l) of the baked chain, next slope n, s = x-shift (0 for a doubling, the fixed Q's x for an add).
// The line is evaluated at a JACOBIAN P = (X:Y:Z): Z^3 * L = Y + (X Z) X Phi(l1) + Z^3 X^3 Phi(l3); the setup
// folds Z^3 and X Z into the env constants (z3_*, z3t_*, cz_*, czt_*, y_*), so the per-step cost is the same.
function chainPart(k, t) {
  const {I, E, m, mul, add, sub} = ops(k);
  const nm = (s) => s + '_' + t;
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map((s) => I(nm(s)));
  const a0 = add(l0, n0), a1 = add(l1, n1);
  const u0 = mul(a0, x0), u1 = mul(a1, x1), u2 = mul(add(a0, a1), add(x0, x1));
  const nc0 = m(sub(sub(u0, u1), c0)), nc1 = m(sub(sub(sub(u2, u0), u1), c1));
  const o = m(sub(add(mul(E(nm('z3')), nc0), mul(E(nm('z3t')), nc1)), add(mul(E(nm('cz')), n0), mul(E(nm('czt')), n1))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  return {state: [nx0, nx1, nc0, nc1, n0, n1], Lp: add(E(nm('y')), o), Lm: sub(E(nm('y')), o)};
}
// KZG event: both chains ([1]_2 at P_left, [x]_2 at P_right) and F+- <- F+-^2 * La * Lb (doubling event) or
// F+- <- F+- * La * Lb * c+- (addition event: no squaring, times the residue factor S_c(-+z) as in SI-GLS)
function kKzgEvent(dbl) {
  const k = new Kernel(); const {I, m, mul} = ops(k);
  const a = chainPart(k, 'a'), b = chainPart(k, 'b');
  const Fp = I('Fp'), Fm = I('Fm');
  const fp = dbl ? m(mul(m(mul(mul(Fp, Fp), a.Lp)), b.Lp)) : m(mul(m(mul(mul(Fp, a.Lp), b.Lp)), I('cp')));
  const fm = dbl ? m(mul(m(mul(mul(Fm, Fm), a.Lm)), b.Lm)) : m(mul(m(mul(mul(Fm, a.Lm), b.Lm)), I('cm')));
  return k.output(...a.state, ...b.state, fp, fm);
}

// ---------------- measurement ----------------
// full-size pseudo-random field elements (operand lengths drive OP_MUL / OP_MOD cost)
const rnd = (s) => mod(BigInt('0x' + createHash('sha256').update('plonk-kzg-design/' + s).digest('hex')));
function measure(name, K, outs, values, check) {
  const ins = [...K.inputs]; const env = [...K.refs.keys()].filter((n) => !K.inputs.has(n));
  const stack = ['p', ...env, ...ins];
  const a = new Asm(stack); const res = a.kernel(K, outs, {iters: ITERS});
  const pushes = stack.map((n) => numPush(n === 'p' ? p : values[n]));
  const run = runBare(a.code, pushes, 'standard');
  assert.equal(run.error, undefined, name + ': ' + run.error);
  const got = run.stack.slice(-outs.length).map((b) => mod(num(b)));
  const sim = K.simulate((n) => values[n.name], p); const want = K.outs.map((id) => mod(sim[id]));
  assert.deepEqual(got, want, name + ': VM != DAG simulation');
  if (check) check(got);
  return {name, opCost: run.opCost, codeBytes: a.code.length, schedulerEstimate: res.cost};
}

const G = bn254.G1.Point;
const P1 = G.BASE.multiply(0x1234567n), Q1 = G.BASE.multiply(0x7654321n);
// Jacobian representation of an affine point with a nontrivial Z
const jac = (P, z) => { const a = P.toAffine(); return {X: mod(a.x * z * z), Y: mod(a.y * z * z * z), Z: z}; };
const toAff = (X, Y, Z) => { const zi = bn254.fields.Fp.inv(Z); return {x: mod(X * zi * zi), y: mod(Y * zi * zi * zi)}; };
const eqPt = (got, P) => { const g = toAff(got[0], got[1], got[2]); const a = P.toAffine(); assert.equal(g.x, a.x); assert.equal(g.y, a.y); };

const out = [];
{ const J = jac(P1, rnd('z1'));
  out.push(measure('G1 Jacobian doubling (dbl-2009-l)', kG1Dbl(), ['X3', 'Y3', 'Z3'], J, (g) => eqPt(g, P1.double()))); }
{ const J = jac(P1, rnd('z1')); const q = Q1.toAffine();
  out.push(measure('G1 mixed addition Jacobian + affine (madd-2007-bl)', kG1MAdd(), ['X3', 'Y3', 'Z3', 'H'], {...J, qx: q.x, qy: q.y}, (g) => eqPt(g, P1.add(Q1)))); }
{ const J = jac(P1, rnd('z1')), J2 = jac(Q1, rnd('z2'));
  out.push(measure('G1 full addition Jacobian + Jacobian (add-2007-bl)', kG1Add(), ['X3', 'Y3', 'Z3', 'H'], {...J, X2: J2.X, Y2: J2.Y, Z2: J2.Z}, (g) => eqPt(g, P1.add(Q1)))); }
{ const a = P1.toAffine(), q = Q1.toAffine(); const l = mod((q.y - a.y) * bn254.fields.Fp.inv(mod(q.x - a.x)));
  out.push(measure('G1 affine addition, witnessed slope (+32 B witness)', kG1AffAddW(), ['x3', 'y3', 'chk', 'ex'], {x1: a.x, y1: a.y, qx: q.x, qy: q.y, l},
    (g) => { const s = P1.add(Q1).toAffine(); assert.deepEqual(g.slice(0, 3), [s.x, s.y, 0n]); assert.notEqual(g[3], 0n); })); }
{ const a = P1.toAffine(); const l = mod(3n * a.x * a.x * bn254.fields.Fp.inv(mod(2n * a.y)));
  out.push(measure('G1 affine doubling, witnessed slope (+32 B witness)', kG1AffDblW(), ['x3', 'y3', 'chk'], {x1: a.x, y1: a.y, l},
    (g) => { const s = P1.double().toAffine(); assert.deepEqual(g, [s.x, s.y, 0n]); })); }
out.push(measure('modular multiply (Fp or Fr)', kMulMod(), ['o'], {a: rnd(3), b: rnd(5)}));
out.push(measure('modular multiply-accumulate', kMulAdd(), ['o'], {acc: rnd(2), a: rnd(3), b: rnd(5)}));
{ const v = {}; const K = kDStep(); for (const n of K.refs.keys()) v[n] = rnd(n.length * 31 + n.charCodeAt(0) * 7 + n.charCodeAt(n.length - 1));
  out.push(measure('SI delta step kDStep (one fixed-G2 chain, Groth16 reference)', K, K.outs.map((_, i) => 'o' + i), v)); }
for (const dbl of [true, false]) {
  const K = kKzgEvent(dbl); const v = {};
  let i = 0; for (const n of K.refs.keys()) v[n] = rnd(1000 + 17 * i++);
  out.push(measure(`KZG event, two fixed-G2 chains + F update (${dbl ? 'doubling: F^2 La Lb' : 'addition: F La Lb c'})`, K, K.outs.map((_, j) => 'o' + j), v));
}
console.log(JSON.stringify({vm: 'libauth BCH_2026 standard (createVirtualMachineBch2026(true)), op-cost net of input pushes', schedIters: ITERS, kernels: out}, null, 1));
