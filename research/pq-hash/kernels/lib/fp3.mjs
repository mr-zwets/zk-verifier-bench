// F_p^3 = F_p[u]/(u^3 - 7) (Goldilocks) helpers on top of the straight-line program compiler.
// A Builder appends named assignments; F_p^3 values are arrays of 3 names (or 3 exprs). Products are lazy
// (sum of products, one OP_MOD per output coefficient); subtraction adds a multiple of p to stay non-negative
// (CashVM OP_MOD keeps the dividend's sign).
import {V, K, add, sub, mul, modp, sum} from './slp.mjs';
import {P, md} from './ref-field.mjs';

export const p = P.gl;
let n = 0;
export class Builder {
  constructor() { this.prog = []; }
  let(e, name) { const nm = name ?? `_${n++}`; this.prog.push([nm, e]); return nm; }
  // inputs are named stack items: in3('a') -> ['a0','a1','a2']
  static in3(name) { return [name + '0', name + '1', name + '2']; }
  // a*b in F_p^3, schoolbook lazy; a, b arrays of names; returns names (canonical)
  mul3(a, b, out) {
    const A = a.map(V), B = b.map(V);
    const c0 = add(mul(A[0], B[0]), mul(add(mul(A[1], B[2]), mul(A[2], B[1])), K(7)));
    const c1 = add(add(mul(A[0], B[1]), mul(A[1], B[0])), mul(mul(A[2], B[2]), K(7)));
    const c2 = add(add(mul(A[0], B[2]), mul(A[2], B[0])), mul(A[1], B[1]));
    return [c0, c1, c2].map((e, i) => this.let(modp(e, p), out ? out + i : undefined));
  }
  sq3(a, out) {
    const A = a.map(V);
    const c0 = add(mul(A[0], A[0]), mul(mul(A[1], A[2]), K(14)));
    const c1 = add(mul(mul(A[0], A[1]), K(2)), mul(mul(A[2], A[2]), K(7)));
    const c2 = add(mul(mul(A[0], A[2]), K(2)), mul(A[1], A[1]));
    return [c0, c1, c2].map((e, i) => this.let(modp(e, p), out ? out + i : undefined));
  }
  // a (F_p^3) times s (F_p name)
  mulFp(a, s, out) { return a.map((x, i) => this.let(modp(mul(V(x), V(s)), p), out ? out + i : undefined)); }
  add3(a, b, out) { return a.map((x, i) => this.let(modp(add(V(x), V(b[i])), p), out ? out + i : undefined)); }
  sub3(a, b, out) { return a.map((x, i) => this.let(modp(add(sub(V(x), V(b[i])), K(p)), p), out ? out + i : undefined)); }
  // generic: arbitrary expression per coefficient, reduced
  red(e, out) { return this.let(modp(e, p), out); }
}

// reference F_p^3
export const r3 = {
  mul: (a, b) => {
    const c = [0n, 0n, 0n, 0n, 0n];
    for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) c[i + j] += a[i] * b[j];
    return [md(c[0] + 7n * c[3], p), md(c[1] + 7n * c[4], p), md(c[2], p)];
  },
  add: (a, b) => a.map((x, i) => md(x + b[i], p)),
  sub: (a, b) => a.map((x, i) => md(x - b[i], p)),
  fp: (a, s) => a.map((x) => md(x * s, p)),
  pow: (a, e) => { let r = [1n, 0n, 0n], b = a; while (e > 0n) { if (e & 1n) r = r3.mul(r, b); b = r3.mul(b, b); e >>= 1n; } return r; },
  inv: (a) => r3.pow(a, p ** 3n - 2n),
};
export {V, K, add, sub, mul, modp, sum};
