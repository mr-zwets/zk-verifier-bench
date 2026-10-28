// K1, K2, K19 and the comparison fields: base-field mulmod/add/sub, Goldilocks reduction variants and lazy dot
// products, extension-field multiplication (Goldilocks^2, Goldilocks^3 schoolbook / Karatsuba / Kronecker,
// BabyBear^4, M31^4 = QM31), Goldilocks^3 square, x F_p, add.
// Values are VM numbers (canonical, 0 <= v < p) on the stack; extension elements are k stack items (c0 at the bottom).
import {Stk, numBytes, asm} from './lib/asm.mjs';
import {compileSlp, V, K, add, sub, mul, modp, sum, evalSlp} from './lib/slp.mjs';
import {P, md, binMul, qm31Mul, structureConstants} from './lib/ref-field.mjs';

const nb = (v) => numBytes(v);
const rnd = (rng, p) => rng.below(p);

// build a case from a straight-line program
export function slpCase(prog, ins, outNames, outVals, {keep = []} = {}) {
  const names = Object.keys(ins);
  const s = new Stk(names);
  compileSlp(s, prog, {keep});
  const extra = s.st.filter((x) => !outNames.includes(x));
  if (extra.length) throw new Error('slpCase: leftover items ' + extra.join(','));
  s.arrange(outNames);
  // the program itself is checked against an independent reference via outVals; evalSlp checks the compiler
  const ev = evalSlp(prog, ins);
  outNames.forEach((n, i) => { if (ev.get(n) !== outVals[i]) throw new Error(`slp/reference mismatch at ${n}: ${ev.get(n)} vs ${outVals[i]}`); });
  return {inputs: names.map((n) => nb(ins[n])), body: s.bytes(), outputs: outVals.map((v) => ({num: v}))};
}

const A = (k) => Array.from({length: k}, (_, i) => 'a' + i), B = (k) => Array.from({length: k}, (_, i) => 'b' + i);
const env = (names, vals) => Object.fromEntries(names.map((n, i) => [n, vals[i]]));

// lazy schoolbook extension multiplication from structure constants, one OP_MOD per output coefficient
export function extMulProg(k, T, p) {
  const prog = [];
  for (let o = 0; o < k; o++) {
    const groups = new Map();
    for (let j = 0; j < k; j++) for (let l = 0; l < k; l++) { const c = T[j][l][o]; if (c !== 0n) { if (!groups.has(c)) groups.set(c, []); groups.get(c).push([j, l]); } }
    let e = null, negMax = 0n;
    const ordered = [...groups.entries()].sort((x, y) => (x[0] === 1n ? -1 : y[0] === 1n ? 1 : Number(y[0] - x[0])));
    for (const [c, terms] of ordered) {
      let t = sum(...terms.map(([j, l]) => mul(V('a' + j), V('b' + l))));
      const ac = c < 0n ? -c : c;
      if (ac !== 1n) t = mul(t, K(ac));
      if (c > 0n) e = e ? add(e, t) : t;
      else { negMax += ac * BigInt(terms.length) * (p - 1n) ** 2n; e = e ? sub(e, t) : sub(K(0), t); }
    }
    if (negMax > 0n) e = add(e, K((negMax / p + 1n) * p));
    prog.push(['c' + o, modp(e, p)]);
  }
  return prog;
}

const glMul3 = (a, b) => binMul(a, b, 7n, P.gl);
const kernels = [];
const def = (id, group, name, build, notes = '', trials = 16) => kernels.push({id, group, name, build, notes, trials});

// ---------- base fields ----------
const FIELDS = [['gl', 'Goldilocks (64-bit)'], ['bb', 'BabyBear (31-bit)'], ['m31', 'M31 (31-bit)'], ['p128', '128-bit prime 2^128-159'], ['p192', '192-bit prime (P-192)'], ['bn254r', 'BN254 Fr (254-bit), context']];
for (const [f, label] of FIELDS) {
  const p = P[f];
  def(f === 'p192' ? 'K19' : 'K1', 'field', `${label}: mulmod a*b mod p`, (rng) => { const a = rnd(rng, p), b = rnd(rng, p);
    return slpCase([['c', modp(mul(V('a'), V('b')), p)]], {a, b}, ['c'], [a * b % p]); });
  def(f === 'p192' ? 'K19' : 'K1', 'field', `${label}: addmod (a+b) mod p`, (rng) => { const a = rnd(rng, p), b = rnd(rng, p);
    return slpCase([['c', modp(add(V('a'), V('b')), p)]], {a, b}, ['c'], [(a + b) % p]); });
  def(f === 'p192' ? 'K19' : 'K1', 'field', `${label}: submod (a-b+p) mod p`, (rng) => { const a = rnd(rng, p), b = rnd(rng, p);
    return slpCase([['c', modp(add(sub(V('a'), V('b')), K(p)), p)]], {a, b}, ['c'], [md(a - b, p)]); });
}
def('K1', 'field', 'Goldilocks: lazy add a+b (no reduction)', (rng) => { const a = rnd(rng, P.gl), b = rnd(rng, P.gl);
  return slpCase([['c', add(V('a'), V('b'))]], {a, b}, ['c'], [a + b]); });
for (const t of [2, 3, 4]) {
  def('K1', 'field', `Goldilocks: lazy dot product of ${t} (sum a_i*b_i, one OP_MOD)`, (rng) => {
    const a = Array.from({length: t}, () => rnd(rng, P.gl)), b = Array.from({length: t}, () => rnd(rng, P.gl));
    const ins = {}; a.forEach((v, i) => { ins['a' + i] = v; ins['b' + i] = b[i]; });
    return slpCase([['c', modp(sum(...a.map((_, i) => mul(V('a' + i), V('b' + i)))), P.gl)]], ins, ['c'], [a.reduce((s, v, i) => s + v * b[i], 0n) % P.gl]);
  }, `per product: divide by ${t}`);
}
// Goldilocks special-form reduction: 2^64 = 2^32 - 1, 2^96 = -1 (mod p), with OP_RSHIFTNUM / OP_LSHIFTNUM
def('K1', 'field', 'Goldilocks: mulmod with special-form reduction (shifts) + final OP_MOD', (rng) => {
  const a = rnd(rng, P.gl), b = rnd(rng, P.gl);
  const body = asm('MUL', 'DUP', 64, 'RSHIFTNUM', 'TUCK', 64, 'LSHIFTNUM', 'SUB', // xh xl
    'SWAP', 'DUP', 32, 'RSHIFTNUM', 'TUCK', 32, 'LSHIFTNUM', 'SUB', // xl h1 h0
    'DUP', 32, 'LSHIFTNUM', 'SWAP', 'SUB', // xl h1 h0*(2^32-1)
    'ROT', 'ADD', 'SWAP', 'SUB', P.gl, 'ADD', P.gl, 'MOD');
  return {inputs: [nb(a), nb(b)], body, outputs: [{num: a * b % P.gl}]};
}, 'r = xl + h0*(2^32-1) - h1 + p, then OP_MOD on a 9-byte operand');

// ---------- extension fields ----------
const EXT = [
  ['Goldilocks^2 (u^2 = 7)', 2, P.gl, (a, b) => binMul(a, b, 7n, P.gl)],
  ['Goldilocks^3 (u^3 = 7), schoolbook lazy', 3, P.gl, glMul3],
  ['BabyBear^4 (x^4 = 11), schoolbook lazy', 4, P.bb, (a, b) => binMul(a, b, 11n, P.bb)],
  ['M31^4 = QM31 (Stwo tower), schoolbook lazy', 4, P.m31, (a, b) => qm31Mul(a, b)],
  ['BabyBear^5 (x^5 = 2), schoolbook lazy (Plonky3 deg-5 option)', 5, P.bb, (a, b) => binMul(a, b, 2n, P.bb)],
];
for (const [label, k, p, ref] of EXT) {
  const T = structureConstants(k, ref, p);
  const prog = extMulProg(k, T, p);
  def(label.startsWith('Goldilocks^3') ? 'K2' : 'K2c', 'ext', `${label}: mul`, (rng) => {
    const a = Array.from({length: k}, () => rnd(rng, p)), b = Array.from({length: k}, () => rnd(rng, p));
    return slpCase(prog, {...env(A(k), a), ...env(B(k), b)}, A(k).map((_, i) => 'c' + i), ref(a, b));
  });
  def(label.startsWith('Goldilocks^3') ? 'K2' : 'K2c', 'ext', `${label.split(',')[0]}: add (reduced)`, (rng) => {
    const a = Array.from({length: k}, () => rnd(rng, p)), b = Array.from({length: k}, () => rnd(rng, p));
    const pr = A(k).map((_, i) => ['c' + i, modp(add(V('a' + i), V('b' + i)), p)]);
    return slpCase(pr, {...env(A(k), a), ...env(B(k), b)}, A(k).map((_, i) => 'c' + i), a.map((x, i) => (x + b[i]) % p));
  });
}
// Goldilocks^3 Karatsuba (6 products)
def('K2', 'ext', 'Goldilocks^3: mul, Karatsuba (6 MUL)', (rng) => {
  const a = [0, 1, 2].map(() => rnd(rng, P.gl)), b = [0, 1, 2].map(() => rnd(rng, P.gl));
  const prog = [
    ['m0', mul(V('a0'), V('b0'))], ['m1', mul(V('a1'), V('b1'))], ['m2', mul(V('a2'), V('b2'))],
    ['s12', mul(add(V('a1'), V('a2')), add(V('b1'), V('b2')))],
    ['s01', mul(add(V('a0'), V('a1')), add(V('b0'), V('b1')))],
    ['s02', mul(add(V('a0'), V('a2')), add(V('b0'), V('b2')))],
    ['c0', modp(add(V('m0'), mul(sub(sub(V('s12'), V('m1')), V('m2')), K(7))), P.gl)],
    ['c1', modp(add(sub(sub(V('s01'), V('m0')), V('m1')), mul(V('m2'), K(7))), P.gl)],
    ['c2', modp(add(sub(sub(V('s02'), V('m0')), V('m2')), V('m1')), P.gl)],
  ];
  return slpCase(prog, {...env(A(3), a), ...env(B(3), b)}, ['c0', 'c1', 'c2'], glMul3(a, b));
});
def('K2', 'ext', 'Goldilocks^3: square, schoolbook lazy', (rng) => {
  const a = [0, 1, 2].map(() => rnd(rng, P.gl));
  const prog = [
    ['c0', modp(add(mul(V('a0'), V('a0')), mul(mul(V('a1'), V('a2')), K(14))), P.gl)],
    ['c1', modp(add(mul(mul(V('a0'), V('a1')), K(2)), mul(mul(V('a2'), V('a2')), K(7))), P.gl)],
    ['c2', modp(add(mul(mul(V('a0'), V('a2')), K(2)), mul(V('a1'), V('a1'))), P.gl)],
  ];
  return slpCase(prog, env(A(3), a), ['c0', 'c1', 'c2'], glMul3(a, a));
});
def('K2', 'ext', 'Goldilocks^3: x F_p (scalar times extension element)', (rng) => {
  const a = [0, 1, 2].map(() => rnd(rng, P.gl)), s = rnd(rng, P.gl);
  const prog = [0, 1, 2].map((i) => ['c' + i, modp(mul(V('a' + i), V('s')), P.gl)]);
  return slpCase(prog, {...env(A(3), a), s}, ['c0', 'c1', 'c2'], a.map((x) => x * s % P.gl));
});
def('K2', 'ext', 'Goldilocks^3: add, lazy (no reduction)', (rng) => {
  const a = [0, 1, 2].map(() => rnd(rng, P.gl)), b = [0, 1, 2].map(() => rnd(rng, P.gl));
  const prog = [0, 1, 2].map((i) => ['c' + i, add(V('a' + i), V('b' + i))]);
  return slpCase(prog, {...env(A(3), a), ...env(B(3), b)}, ['c0', 'c1', 'c2'], a.map((x, i) => x + b[i]));
});

// Kronecker-packed Goldilocks^3 mul: one OP_MUL on 3-coefficient integers with 136-bit (17-byte) slots.
// product coefficients <= 3(p-1)^2 < 2^130; after folding x^3 = 7: c_k + 7 c_{k+3} < 17 p^2 < 2^133 (fits a slot)
const S = 136, SB = 17;
// pack helper: stack [x0 x1 x2] -> X = x0 + x1 2^S + x2 2^2S via NUM2BIN/CAT (17-byte LE slots, top bit clear)
const pack3 = ['ROT', SB, 'NUM2BIN', 'ROT', SB, 'NUM2BIN', 'CAT', 'SWAP', SB, 'NUM2BIN', 'CAT', 'BIN2NUM'];
// unpack-reduce helper: C (packed product) -> d0 d1 d2 canonical, d0 at the bottom
const reduce3 = [
  5 * SB, 'NUM2BIN', 3 * SB, 'SPLIT', 'BIN2NUM', 7, 'MUL', 'SWAP', 'BIN2NUM', 'ADD', // D = lo + 7*hi
  3 * SB, 'NUM2BIN', SB, 'SPLIT', SB, 'SPLIT', // d0b d1b d2b
  'BIN2NUM', P.gl, 'MOD', 'ROT', 'BIN2NUM', P.gl, 'MOD', 'ROT', 'BIN2NUM', P.gl, 'MOD', 'ROT', // -> d0 d1 d2
];
def('K2', 'ext', 'Goldilocks^3: mul, Kronecker-packed (pack both, 1 OP_MUL, unpack, 3 OP_MOD)', (rng) => {
  const a = [0, 1, 2].map(() => rnd(rng, P.gl)), b = [0, 1, 2].map(() => rnd(rng, P.gl));
  // a0 a1 a2 b0 b1 b2 -> pack b, move under a, pack a
  const body = asm(pack3, 'TOALTSTACK', pack3, 'FROMALTSTACK', 'MUL', reduce3);
  return {inputs: [...a, ...b].map(nb), body, outputs: glMul3(a, b).map((v) => ({num: v}))};
}, 'slot 17 B');
def('K2', 'ext', 'Goldilocks^3: mul, Kronecker packed in / packed out (1 OP_MUL, unpack, 3 OP_MOD, repack)', (rng) => {
  const a = [0, 1, 2].map(() => rnd(rng, P.gl)), b = [0, 1, 2].map(() => rnd(rng, P.gl));
  const packv = (x) => x[0] + (x[1] << BigInt(S)) + (x[2] << BigInt(2 * S));
  const body = asm('MUL', reduce3, pack3);
  return {inputs: [packv(a), packv(b)].map(nb), body, outputs: [{num: packv(glMul3(a, b))}]};
});
def('K2', 'ext', 'Goldilocks^3: add, Kronecker packed (1 OP_ADD, lazy)', (rng) => {
  const a = [0, 1, 2].map(() => rnd(rng, P.gl)), b = [0, 1, 2].map(() => rnd(rng, P.gl));
  const packv = (x) => x[0] + (x[1] << BigInt(S)) + (x[2] << BigInt(2 * S));
  return {inputs: [packv(a), packv(b)].map(nb), body: asm('ADD'), outputs: [{num: packv(a) + packv(b)}]};
});

export default kernels;
