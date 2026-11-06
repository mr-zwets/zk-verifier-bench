// Arithmetic kernels (DAGs over named stack items, scheduled by asm.mjs).
//   - kADblN / kAAddN: the AFFINE B steps with a witnessed inverse norm t (design-1 prototype
//     research/sound-bn254-native/prototypes/kernels.mjs, checked there against noble). The slope is computed
//     on-chain as lambda = num * conj(den) * t and the exact equation t * N(den) == 1 (scaled by 2 for the
//     doubling) is returned as a reduced value that the caller requires to be 0. Since p = 3 (mod 4) the Fp2 norm
//     vanishes only at 0, so the equation also forces den != 0 and t = 1 / N(den).
//   - kDStep, kEval, kTable: verbatim from the reviewed SI-GLS script (../sound-si-gls/script.mjs).
import {Kernel} from './asm.mjs';

const ops = (k) => ({I: (n) => k.in(n), E: (n) => k.env(n), m: (x) => k.mod(x), mul: (a, b) => k.mul(a, b), add: (a, b) => k.add(a, b), sub: (a, b) => k.sub(a, b)});

// after lambda: x' = lambda^2 - x - xq (xq = x for the doubling), c = lambda x - y, y' = c - lambda x';
// line (1, -lambda, c) at P = (xA, yP = -yA): L(+-z) = yP +- o, o = z^3 Phi(c)(z) - xA z Phi(lambda)(z),
// Phi(a)(z) = a0 + a1 (z^6 - 9) (env: z3, z3t = z^3 (z^6 - 9), xz = xA z, xzt = xA z (z^6 - 9), yP)
// doubling: F <- F^2 L;  addition: F <- F L c (cp / cm: the residue-root factor at +-z)
function affineTail(k, x0, x1, y0, y1, l0, l1, q, outs, cpcm) {
  const {I, E, m, mul, add, sub} = ops(k);
  const fm = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const nx0 = q ? m(sub(sub(mul(add(l0, l1), sub(l0, l1)), x0), q[0])) : m(sub(mul(add(l0, l1), sub(l0, l1)), add(x0, x0)));
  const nx1 = q ? m(sub(sub(mul(add(l0, l0), l1), x1), q[1])) : m(sub(mul(add(l0, l0), l1), add(x1, x1)));
  const [lx0, lx1] = fm(l0, l1, x0, x1); const c0 = m(sub(lx0, y0)), c1 = m(sub(lx1, y1));
  const [ln0, ln1] = fm(l0, l1, nx0, nx1); const ny0 = m(sub(c0, ln0)), ny1 = m(sub(c1, ln1));
  const o = m(sub(add(mul(E('z3'), c0), mul(E('z3t'), c1)), add(mul(E('xz'), l0), mul(E('xzt'), l1))));
  const Lp = add(E('yP'), o), Lm = sub(E('yP'), o);
  const Fp = I('Fp'), Fm = I('Fm');
  const fp = cpcm ? m(mul(mul(Fp, Lp), I('cp'))) : m(mul(mul(Fp, Fp), Lp));
  const fmm = cpcm ? m(mul(mul(Fm, Lm), I('cm'))) : m(mul(mul(Fm, Fm), Lm));
  return [nx0, nx1, ny0, ny1, fp, fmm, ...outs];
}
// doubling at T = (X, Y): lambda = 3 X^2 conj(Y) t, check t * 2 N(Y) - 1 == 0 (mod p)
// outputs: X', X', Y', Y', Fp, Fm, chk
export function kADblN() {
  const k = new Kernel(); const {I, m, mul, add, sub} = ops(k);
  const [x0, x1, y0, y1, t] = ['X0', 'X1', 'Y0', 'Y1', 't'].map(I);
  const A0 = m(k.small(mul(add(x0, x1), sub(x0, x1)), 3)), A1 = m(k.small(mul(add(x0, x0), x1), 3)); // 3 x^2
  const w0 = m(add(mul(A0, y0), mul(A1, y1))), w1 = m(sub(mul(A1, y0), mul(A0, y1)));                  // 3x^2 conj(y)
  const l0 = m(mul(w0, t)), l1 = m(mul(w1, t));
  const chk = m(sub(mul(t, k.small(add(mul(y0, y0), mul(y1, y1)), 2)), k.c(1n)));                     // t * 2 N(y) - 1
  return k.output(...affineTail(k, x0, x1, y0, y1, l0, l1, null, [chk], false));
}
// addition of Q = (xq, yq) (env) at T = (X, Y): lambda = (Y - yq) conj(X - xq) t, check t * N(X - xq) - 1 == 0 (mod p)
export function kAAddN() {
  const k = new Kernel(); const {I, E, m, mul, add, sub} = ops(k);
  const [x0, x1, y0, y1, t] = ['X0', 'X1', 'Y0', 'Y1', 't'].map(I);
  const [q0, q1, r0, r1] = ['xq0', 'xq1', 'yq0', 'yq1'].map(E);
  const d0 = sub(x0, q0), d1 = sub(x1, q1), e0 = sub(y0, r0), e1 = sub(y1, r1);
  const w0 = m(add(mul(e0, d0), mul(e1, d1))), w1 = m(sub(mul(e1, d0), mul(e0, d1)));                  // (y - yq) conj(x - xq)
  const l0 = m(mul(w0, t)), l1 = m(mul(w1, t));
  const chk = m(sub(mul(t, add(mul(d0, d0), mul(d1, d1))), k.c(1n)));                                // t * N(x - xq) - 1
  return k.output(...affineTail(k, x0, x1, y0, y1, l0, l1, [q0, q1], [chk], true));
}
// ---- verbatim from ../sound-si-gls/script.mjs ----
// delta step j: n = lambda_j (read), c_j = (lambda_{j-1} + lambda_j) x_j - c_{j-1}, line (1, -lambda_j, c_j) at C,
// x_{j+1} = lambda_j^2 - x_j - s. env: yC cz czt z3 z3t
export function kDStep() {
  const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [x0, x1, c0, c1, l0, l1, n0, n1, s0, s1] = ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'n0', 'n1', 's0', 's1'].map(I);
  const a0 = add(l0, n0), a1 = add(l1, n1);
  const u0 = mul(a0, x0), u1 = mul(a1, x1), u2 = mul(add(a0, a1), add(x0, x1));
  const nc0 = m(sub(sub(u0, u1), c0)), nc1 = m(sub(sub(sub(u2, u0), u1), c1));
  const o = m(sub(add(mul(E('z3'), nc0), mul(E('z3t'), nc1)), add(mul(E('cz'), n0), mul(E('czt'), n1))));
  const nx0 = m(sub(sub(mul(add(n0, n1), sub(n0, n1)), x0), s0)), nx1 = m(sub(sub(mul(add(n0, n0), n1), x1), s1));
  k.output(nx0, nx1, nc0, nc1, n0, n1, m(mul(I('Fp'), add(E('yC'), o))), m(mul(I('Fm'), sub(E('yC'), o))));
  return k;
}
// monic degree-6 evaluation at +-x: (Ev + Od, Ev - Od) from s0..s5 and x..x6 (all consumed)
export function kEval() {
  const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const ev = k.mod(k.sum(s[0], k.mul(s[2], x[1]), k.mul(s[4], x[3]), x[5]));
  const od = k.mod(k.sum(k.mul(s[1], x[0]), k.mul(s[3], x[2]), k.mul(s[5], x[4])));
  return k.output(k.add(ev, od), k.sub(ev, od));
}
// Universal degree-6 chart evaluation at +-x. Inputs are c1..c6, x..x^6,
// and tau..tau^6; c0 is reconstructed from S(tau)=1. Every transmitted
// coefficient and both power vectors are consumed by this kernel.
export function kDegree6Eval() {
  const k = new Kernel();
  const c = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i));
  const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const t = [12, 13, 14, 15, 16, 17].map((i) => k.in('in' + i));
  const c0 = k.mod(k.sub(k.c(1n), k.sum(...c.map((v, i) => k.mul(v, t[i])))));
  const ev = [c0], od = [];
  c.forEach((v, i) => ((i + 1) & 1 ? od : ev).push(k.mul(v, x[i])));
  const even = k.mod(k.sum(...ev)), odd = k.mod(k.sum(...od));
  return k.output(k.mod(k.add(even, odd)), k.mod(k.sub(even, odd)));
}
// 16-entry subset table from v0..v3 (consumed): T[n] = prod (or sum) over bits of n; outputs T[15] .. T[0]
export function kTable(mult) {
  const k = new Kernel(); const v = [0, 1, 2, 3].map((i) => k.in('in' + i)); const T = [k.c(mult ? 1n : 0n)];
  for (let n = 1; n < 16; n++) { const lo = n & -n, b = Math.log2(lo); T[n] = n === lo ? v[b] : mult ? k.mod(k.mul(T[n ^ lo], v[b])) : k.add(T[n ^ lo], v[b]); }
  return k.output(...T.slice().reverse());
}
