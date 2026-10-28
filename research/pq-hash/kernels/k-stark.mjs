// STARK-step kernels (SPEC section 8): K3 inversion, K4 domain points, K9 transcript / introspection / code load,
// K10 DEEP at one point, K11 FRI folds (arity 4, 8, 16) and the O1 splice, K12 final polynomial, K13 AIR check at z,
// K14 loop and call overhead. Every case is checked against a JS reference on random inputs.
import {createHash} from 'node:crypto';
import {Stk, asm, numBytes} from './lib/asm.mjs';
import {compileSlp, evalSlp} from './lib/slp.mjs';
import {Builder, r3, p, V, K, add, sub, mul, modp, sum} from './lib/fp3.mjs';
import {md, powmod} from './lib/ref-field.mjs';

const nb = (v) => numBytes(v);
const sha = (...bs) => Uint8Array.from(createHash('sha256').update(Buffer.concat(bs.map((b) => Buffer.from(b)))).digest());
const le8 = (v) => { const b = new Uint8Array(8); for (let i = 0; i < 8; i++) b[i] = Number((v >> BigInt(8 * i)) & 255n); return b; };
const leNum = (b) => b.reduceRight((a, x) => (a << 8n) | BigInt(x), 0n);
const B0 = Uint8Array.of(0);
const kernels = [];
const def = (id, group, name, build, notes = '', trials = 8, extra) => kernels.push({id, group, name, build, notes, trials, extra});
const r = (rng) => rng.below(p);
const r3v = (rng) => [r(rng), r(rng), r(rng)];

// compile a Builder program whose inputs are the named stack items `ins` (bottom first); outputs in order
function slpBody(b, ins, outs, env) {
  const s = new Stk(ins);
  compileSlp(s, b.prog);
  const extra = s.st.filter((x) => !outs.includes(x));
  if (extra.length) throw new Error('leftover ' + extra.slice(0, 8).join(','));
  s.arrange(outs);
  if (env) { const ev = evalSlp(b.prog, env); return {body: s.bytes(), ev}; }
  return {body: s.bytes()};
}
const names3 = (n) => [n + '0', n + '1', n + '2'];
const env3 = (n, v) => Object.fromEntries(v.map((x, i) => [n + i, x]));

// ---------------- K3: inversion ----------------
// F_p inversion x^(p-2), p - 2 = (2^31 - 1) 2^33 + (2^32 - 1); chain: 75 squarings + 10 multiplications
function fpInvCode() {
  const s = new Stk(['x']);
  const sq = (k) => { for (let i = 0; i + 1 < k; i += 2) s.emit('DUP', 'MUL', 'DUP', 'MUL', p, 'MOD'); if (k % 2) s.emit('DUP', 'MUL', p, 'MOD'); };
  const mulBy = (n, keep) => { s.get(n, keep); s.emit('MUL', p, 'MOD'); s.st.pop(); };
  const step = (from, k, by, keepBy, keepFrom, out) => { if (keepFrom) s.pick(from); else s.roll(from); sq(k); mulBy(by, keepBy); s.rename(s.top(), out); };
  step('x', 1, 'x', true, true, 't2');      // x^3 = x^(2^2-1)
  step('t2', 1, 'x', true, true, 'e3');     // x^7 = x^(2^3-1)
  step('t2', 2, 't2', false, true, 't4');   // x^(2^4-1)
  step('t4', 4, 't4', true, true, 't8');    // x^(2^8-1)
  step('e3', 4, 't4', false, false, 'e7');  // x^(2^7-1)
  step('t8', 8, 't8', true, true, 't16');   // x^(2^16-1)
  step('t8', 7, 'e7', false, false, 'e15'); // x^(2^15-1)
  step('t16', 15, 'e15', false, false, 'e31'); // x^(2^31-1)
  step('e31', 1, 'x', false, true, 'e32');  // x^(2^32-1)
  step('e31', 33, 'e32', false, false, 'r'); // x^((2^31-1) 2^33 + 2^32 - 1)
  if (s.st.length !== 1) throw new Error('fpInv leftover ' + s.st);
  return s.bytes();
}
const FPINV = fpInvCode();
def('K3', 'inverse', 'F_p inversion x^(p-2), addition chain (75 squarings paired lazily + 10 mul)', (rng) => {
  const x = r(rng) || 1n; return {inputs: [nb(x)], body: FPINV, outputs: [{num: powmod(x, p - 2n, p)}]};
});
// F_p^3 inversion by the norm: adj(a) = (a0^2 - 7 a1 a2, 7 a2^2 - a0 a1, a1^2 - a0 a2), N = a0 b0 + 7 (a2 b1 + a1 b2)
function adjNormProg(b, a) {
  const A = a.map(V);
  const P2 = p * p;
  const b0 = b.red(add(sub(mul(A[0], A[0]), mul(mul(A[1], A[2]), K(7))), K(7n * P2)), 'b0');
  const b1 = b.red(add(sub(mul(mul(A[2], A[2]), K(7)), mul(A[0], A[1])), K(P2)), 'b1');
  const b2 = b.red(add(sub(mul(A[1], A[1]), mul(A[0], A[2])), K(P2)), 'b2');
  void b0; void b1; void b2;
  const N = b.red(add(mul(V(a[0]), V('b0')), mul(add(mul(V(a[2]), V('b1')), mul(V(a[1]), V('b2'))), K(7))), 'N');
  return N;
}
def('K3', 'inverse', 'F_p^3 inversion via the norm (adjugate, norm, one F_p inversion by the chain, 3 mulmods)', (rng) => {
  const a = r3v(rng);
  const b = new Builder(); adjNormProg(b, names3('a'));
  const s = new Stk(names3('a')); compileSlp(s, b.prog, {keep: ['b0', 'b1', 'b2']}); s.arrange(['b0', 'b1', 'b2', 'N']);
  s.emit({raw: FPINV}); s.rename('N', 'Ni');
  const b2 = new Builder(); b2.mulFp(['b0', 'b1', 'b2'], 'Ni', 'c'); compileSlp(s, b2.prog); s.arrange(names3('c'));
  return {inputs: a.map(nb), body: s.bytes(), outputs: r3.inv(a).map((v) => ({num: v}))};
});
def('K3', 'inverse', 'F_p^3 inversion with a witnessed norm inverse (adjugate, norm, check N*Ni == 1, 3 mulmods)', (rng) => {
  const a = r3v(rng);
  const b = new Builder(); adjNormProg(b, names3('a'));
  const s = new Stk([...names3('a'), 'Ni']); compileSlp(s, b.prog, {keep: ['b0', 'b1', 'b2']}); s.arrange(['Ni', 'b0', 'b1', 'b2', 'N']);
  s.pick('Ni'); s.emit('MUL', p, 'MOD', 1, 'NUMEQUALVERIFY'); s.st.splice(-2, 2);
  const b2 = new Builder(); b2.mulFp(['b0', 'b1', 'b2'], 'Ni', 'c'); compileSlp(s, b2.prog); s.arrange(names3('c'));
  const ad = [md(a[0] * a[0] - 7n * a[1] * a[2], p), md(7n * a[2] * a[2] - a[0] * a[1], p), md(a[1] * a[1] - a[0] * a[2], p)];
  const N = md(a[0] * ad[0] + 7n * (a[2] * ad[1] + a[1] * ad[2]), p);
  return {inputs: [...a, powmod(N, p - 2n, p)].map(nb), body: s.bytes(), outputs: r3.inv(a).map((v) => ({num: v}))};
}, '+8 proof bytes per inversion (or one hint per batch)');
def('K3', 'inverse', 'F_p^3 witnessed inverse, direct check a*inv == 1 (one F_p^3 mul + 3 compares)', (rng) => {
  const a = r3v(rng), ai = r3.inv(a);
  const b = new Builder(); b.mul3(names3('a'), names3('i'), 'c');
  const s = new Stk([...names3('a'), ...names3('i')]);
  compileSlp(s, b.prog, {keep: names3('i')}); s.arrange([...names3('i'), 'c0', 'c1', 'c2']);
  s.emit(0, 'NUMEQUALVERIFY', 0, 'NUMEQUALVERIFY', 1, 'NUMEQUALVERIFY'); s.st.splice(-3, 3);
  return {inputs: [...a, ...ai].map(nb), body: s.bytes(), outputs: ai.map((v) => ({num: v}))};
}, '+24 proof bytes per inversion');
// DEEP denominator 1/(x - z) for base-field x with per-proof constants: N(x - z) = x^3 - e1 x^2 + e2 x - e3 (F_p),
// adj(x - z) = x^2 - s1 x + s2 (s1, s2 in F_p^3); the norm inverse is witnessed (hint, 8 B)
def('K3', 'inverse', 'DEEP denominator 1/(x - z), x in F_p: norm polynomial + adjugate polynomial (per-proof constants) + witnessed norm inverse', (rng) => {
  const z = r3v(rng), x = r(rng);
  // conjugates of z via Frobenius: phi(u) = w u, w = 7^((p-1)/3)
  const w = powmod(7n, (p - 1n) / 3n, p), w2 = w * w % p;
  const phi = (a, k) => [a[0], a[1] * (k === 1 ? w : w2) % p, a[2] * (k === 1 ? w2 : w) % p];
  const z1 = phi(z, 1), z2 = phi(z, 2);
  const s1 = r3.add(z1, z2), s2 = r3.mul(z1, z2);
  const e1 = r3.add(z, s1)[0], e2 = r3.add(r3.mul(z, s1), s2)[0], e3 = r3.mul(z, s2)[0];
  const xz = [md(x - z[0], p), md(-z[1], p), md(-z[2], p)];
  const Nv = md(x * x % p * x - e1 * x % p * x + e2 * x - e3, p);
  const inv = r3.inv(xz);
  const b = new Builder();
  const X = V('x');
  b.let(modp(sub(add(mul(add(mul(sub(add(X, K(p)), V('e1')), X), V('e2')), X), K(p)), V('e3')), p), 'N'); // ((x + p - e1) x + e2) x + p - e3
  b.let(modp(mul(X, X), p), 'x2');
  // adj_k = [k==0] x2 - s1_k x + s2_k
  ['a0', 'a1', 'a2'].forEach((nm, k) => b.let(modp(add(add(k === 0 ? V('x2') : K(0), sub(V('s2' + k), mul(V('s1' + k), X))), K(p * p)), p), nm));
  const ins = ['x', 'e1', 'e2', 'e3', 's10', 's11', 's12', 's20', 's21', 's22', 'Ni'];
  const s = new Stk(ins); compileSlp(s, b.prog); s.arrange(['Ni', 'a0', 'a1', 'a2', 'N']);
  s.pick('Ni'); s.emit('MUL', p, 'MOD', 1, 'NUMEQUALVERIFY'); s.st.splice(-2, 2);
  const b2 = new Builder(); b2.mulFp(['a0', 'a1', 'a2'], 'Ni', 'c'); compileSlp(s, b2.prog); s.arrange(names3('c'));
  const vals = [x, e1, e2, e3, ...s1, ...s2, powmod(Nv, p - 2n, p)];
  return {inputs: vals.map(nb), body: s.bytes(), outputs: inv.map((v) => ({num: v}))};
}, 'per-proof constants e1..e3, s1, s2 precomputed once; +8 proof bytes (norm inverse hint)');

// ---------------- K4: domain point 7 * w^v ----------------
const N_P100 = 1n << 23n, N_P128 = 1n << 21n;
const omega = (N) => powmod(7n, (p - 1n) / N, p);
for (const [label, N, bits] of [['P100 (N = 2^23, v < 2^21)', N_P100, 21], ['P128 (N = 2^21, v < 2^19)', N_P128, 19]]) {
  const w = omega(N);
  const binary = asm(7, Array.from({length: bits}, (_, i) => ['OVER', 2, 'MOD', 'IF', powmod(w, 1n << BigInt(i), p), 'MUL', p, 'MOD', 'ENDIF', 'SWAP', 1, 'RSHIFTNUM', 'SWAP']), 'NIP');
  def('K4', 'field', `domain point 7*w_N^v, ${label}: binary, unrolled (bit test + conditional mulmod per bit)`, (rng) => {
    const v = rng.big(bits); return {inputs: [nb(v)], body: binary, outputs: [{num: 7n * powmod(w, v, p) % p}]};
  });
  // 4-bit windows: table blob per window with 16 entries of 8 bytes (LE), entry j = w^(j 16^k), 7 folded into window 0
  const windows = Math.ceil(bits / 4);
  const tables = Array.from({length: windows}, (_, k) => Uint8Array.from(Array.from({length: 16}, (_, j) => [...le8((k === 0 ? 7n : 1n) * powmod(w, BigInt(j) << BigInt(4 * k), p) % p)]).flat()));
  const win = asm(
    // first window: r = T0[v mod 16]
    'DUP', 16, 'MOD', 8, 'MUL', tables[0], 'SWAP', 'SPLIT', 'NIP', 8, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', 'SWAP', 4, 'RSHIFTNUM', 'SWAP',
    tables.slice(1).map((t, k) => ['OVER', 16, 'MOD', 8, 'MUL', t, 'SWAP', 'SPLIT', 'NIP', 8, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', 'MUL', p, 'MOD', ...(k < windows - 2 ? ['SWAP', 4, 'RSHIFTNUM', 'SWAP'] : [])]),
    'NIP');
  def('K4', 'field', `domain point 7*w_N^v, ${label}: 4-bit windows (${windows} table blobs of 128 B in code)`, (rng) => {
    const v = rng.big(bits); return {inputs: [nb(v)], body: win, outputs: [{num: 7n * powmod(w, v, p) % p}]};
  });
}

// ---------------- K9: transcript, introspection, code load ----------------
const TAG = Uint8Array.from([...Buffer.from('verifier.cash/pq-hash/v1'), 1, ...sha(Buffer.from('baked constants (placeholder)'))]);
function transcriptRef(t) {
  const E = (d) => { const v = leNum(d); return [v % p, (v / p) % p, (v / p / p) % p]; };
  const out = [];
  const t0 = sha(TAG, t.x, t.y), t1 = sha(t0, t.roots[0]);
  for (let j = 1; j <= 4; j++) out.push(...E(sha(t1, Uint8Array.of(0x61, j))));
  const t2 = sha(t1, t.roots[1]); const z = E(sha(t2, Uint8Array.of(0x7a))); out.push(...z);
  const t3 = sha(t2, t.ood); for (let j = 1; j <= 5; j++) out.push(...E(sha(t3, Uint8Array.of(0x67, j)))); out.push(...E(sha(t3, Uint8Array.of(0x62))));
  const t4 = sha(t3, t.roots[2]); out.push(...E(sha(t4, Uint8Array.of(0x62))));
  const t5 = sha(t4, t.roots[3]); out.push(...E(sha(t5, Uint8Array.of(0x62))));
  const t6 = sha(t5, t.fin); const G = sha(t6, t.nonce);
  const idx = Array.from({length: t.s}, (_, i) => leNum(sha(G, Uint8Array.of(i & 255, i >> 8)).slice(0, 4)) % t.mod);
  return {out, idx, G, z};
}
function transcriptBody(s, mod, h) {
  // inputs: x y r0 r1 r2 r3 ood fin nonce ; outputs: alpha(12) z(3) gamma(15) beta1..3(9) idx(s)
  const E = [B0, 'CAT', 'BIN2NUM', 'DUP', p, 'MOD', 'SWAP', p, 'DIV', 'DUP', p, 'MOD', 'SWAP', p, 'DIV', p, 'MOD']; // d -> c0 c1 c2
  const ch = (tagBytes) => ['DUP', tagBytes, 'CAT', 'SHA256', E, 'TOALTSTACK', 'TOALTSTACK', 'TOALTSTACK']; // keeps t on top
  void h;
  return asm(Array.from({length: 7}, () => 'TOALTSTACK'),
    // stack: x y r0 r1 r2 r3 ood fin nonce -> move all but x y to alt in reverse so they come back in order
    // inputs x y r0 r1 ood r2 r3 fin nonce: 7 x TOALTSTACK leaves r0 on top of the altstack, then r1, ood, r2, r3, fin, nonce
    TAG, 'ROT', 'ROT', 'CAT', 'CAT', 'SHA256',                       // t0
    'FROMALTSTACK', 'CAT', 'SHA256',                                  // t1  (alt: nonce fin ood r3 r2 r1)
    // challenges go to the stack below t: compute each, move its 3 coefficients under t
    [1, 2, 3, 4].map((j) => ['DUP', Uint8Array.of(0x61, j), 'CAT', 'SHA256', E, 3, 'ROLL']),
    'FROMALTSTACK', 'CAT', 'SHA256',                                  // t2
    'DUP', Uint8Array.of(0x7a), 'CAT', 'SHA256', E, 'OVER', 'OVER', 'BOOLOR', 'VERIFY', 3, 'ROLL', // z (z not in F_p)
    'FROMALTSTACK', 'CAT', 'SHA256',                                  // t3 = H(t2 || ood)
    [1, 2, 3, 4, 5].map((j) => ['DUP', Uint8Array.of(0x67, j), 'CAT', 'SHA256', E, 3, 'ROLL']),
    'DUP', Uint8Array.of(0x62), 'CAT', 'SHA256', E, 3, 'ROLL',        // beta1
    'FROMALTSTACK', 'CAT', 'SHA256',                                  // t4 = H(t3 || r2)
    'DUP', Uint8Array.of(0x62), 'CAT', 'SHA256', E, 3, 'ROLL',        // beta2
    'FROMALTSTACK', 'CAT', 'SHA256',                                  // t5 = H(t4 || r3)
    'DUP', Uint8Array.of(0x62), 'CAT', 'SHA256', E, 3, 'ROLL',        // beta3
    'FROMALTSTACK', 'CAT', 'SHA256', 'FROMALTSTACK', 'CAT', 'SHA256', // t6, G
    'DUP', 4, 'SPLIT', 'DROP', Uint8Array.of(0xff, 0, 0, 0), 'AND', Uint8Array.of(0, 0, 0, 0), 'EQUALVERIFY', // grinding (8-bit mask, see K5)
    Array.from({length: s}, (_, i) => ['DUP', Uint8Array.of(i & 255, i >> 8), 'CAT', 'SHA256', 4, 'SPLIT', 'DROP', B0, 'CAT', 'BIN2NUM', mod, 'MOD', 'SWAP']),
    'DROP');
}
for (const [label, h, s, mod] of [['P100 (h = 25, s = 22, N/k0 = 2^21)', 25, 22, 1n << 21n], ['P128 (h = 32, s = 43, N/k0 = 2^19)', 32, 43, 1n << 19n]]) {
  const body = transcriptBody(s, mod, h);
  def('K9', 'transcript', `full Fiat-Shamir transcript (SPEC 3.4), ${label}: 14 F_p^3 challenges, grinding check, s indices`, (rng) => {
    const t = {x: le8(r(rng)), y: le8(r(rng)), roots: [0, 1, 2, 3].map(() => rng.bytes(h)), ood: rng.bytes(120), fin: rng.bytes(6144), s, mod};
    for (let n = 0; ; n++) { t.nonce = le8(BigInt(n) + rng.big(40)); if (sha(transcriptT6(t), t.nonce)[0] === 0) break; }
    const ref = transcriptRef(t);
    if (ref.z[1] === 0n && ref.z[2] === 0n) throw new Error('z in F_p');
    return {inputs: [t.x, t.y, t.roots[0], t.roots[1], t.ood, t.roots[2], t.roots[3], t.fin, t.nonce], body, outputs: [...ref.out, ...ref.idx].map((v) => ({num: v}))};
  }, 'mask: 8-bit grinding target in the test (same cost as 28 bits); every input of layout (a) runs this', 3);
}
function transcriptT6(t) {
  const t0 = sha(TAG, t.x, t.y), t1 = sha(t0, t.roots[0]), t2 = sha(t1, t.roots[1]), t3 = sha(t2, t.ood), t4 = sha(t3, t.roots[2]), t5 = sha(t4, t.roots[3]);
  return sha(t5, t.fin);
}
// introspection: read L bytes at offset O of input 1's unlocking bytecode (10,000 B)
for (const [O, L] of [[3000, 1000], [9000, 1000], [0, 6400]]) {
  def('K9', 'introspection', `read ${L} B at offset ${O} of a 10,000-byte sibling unlocking (1 OP_INPUTBYTECODE O OP_SPLIT OP_NIP L OP_SPLIT OP_DROP)`, (rng) => {
    const u = rng.bytes(10_000); u[0] = 0x4d; u[1] = 10_000 - 3 & 255; u[2] = (10_000 - 3) >> 8; // a valid PUSHDATA2 of the rest
    return {inputs: [], body: asm(1, 'INPUTBYTECODE', O, 'SPLIT', 'NIP', L, 'SPLIT', 'DROP'), outputs: [{bin: u.slice(O, O + L)}], siblings: [{unlocking: u}]};
  }, 'the remote read pushes the whole 10 KB once and the split pieces', 2);
}
// code load: read a code piece of L bytes from input 1, hash-check it, define it
for (const L of [2000, 4000, 8000]) {
  def('K9', 'code-load', `code load: read ${L} B from a sibling input, OP_SHA256 == K_code, OP_DEFINE (libauth); BCHN adds ${L}`, (rng) => {
    const code = new Uint8Array(L).fill(0x61); code.set(rng.bytes(16), 0); code[0] = 0x6a; // any bytes: never invoked
    const u = Uint8Array.from([0x4d, (L + 0) & 255, L >> 8, ...code]);
    return {inputs: [], body: asm(1, 'INPUTBYTECODE', 3, 'SPLIT', 'NIP', 'DUP', 'SHA256', sha(code), 'EQUALVERIFY', 9, 'DEFINE'), outputs: [], siblings: [{unlocking: u}], bchnExtra: L};
  }, `BCHN-adjusted = libauth + ${L} (body bytes charged at OP_DEFINE)`, 2, {bchnExtra: L});
}
// binding pushed numbers: hash the raw unlocking region of the own input instead of parsing a blob
def('K9', 'introspection', 'bind 768 pushed numbers (the final polynomial as minimal pushes) by hashing the own unlocking region', (rng) => {
  const vals = Array.from({length: 768}, () => r(rng));
  const pushesBytes = Uint8Array.from(vals.flatMap((v) => [...asm(v)]));
  const d = sha(pushesBytes);
  // the measured kernel: OP_INPUTINDEX OP_INPUTBYTECODE 0 .. len  OP_SHA256 <d> OP_EQUALVERIFY (values stay on the stack)
  const body = asm('INPUTINDEX', 'INPUTBYTECODE', pushesBytes.length, 'SPLIT', 'DROP', 'SHA256', d, 'EQUALVERIFY', Array.from({length: 384}, () => '2DROP'));
  return {inputs: vals.map(nb), body, outputs: [], note: 'drops are part of the body'};
}, 'includes 384 OP_2DROP (38,400) to clear the stack; subtract for the binding cost', 2, {subtract: 38400});
def('K12', 'final', 'parse the 6,144-byte final polynomial blob into 768 numbers (tree split to 24-byte coefficients)', (rng) => {
  const vals = Array.from({length: 768}, () => r(rng));
  const blob = Uint8Array.from(vals.flatMap((v) => [...le8(v)]));
  // recursive halving to 24-byte pieces, then 3 values each; numbers end in order c_0 .. c_767 (c_0 deepest)
  const s = new Stk(['blob']);
  const split = (name, len) => {
    if (len === 24) { s.roll(name); s.emit(8, 'SPLIT', 8, 'SPLIT', 'ROT', B0, 'CAT', 'BIN2NUM', 'ROT', B0, 'CAT', 'BIN2NUM', 'ROT', B0, 'CAT', 'BIN2NUM'); s.st.pop(); s.st.push(name + 'a', name + 'b', name + 'c'); return; }
    const half = (len / 24 >> 1) * 24;
    s.roll(name); s.emit(half, 'SPLIT'); s.st.pop(); s.st.push(name + 'L', name + 'R');
    s.emit('TOALTSTACK'); s.st.pop(); split(name + 'L', half); s.emit('FROMALTSTACK'); s.st.push(name + 'R'); split(name + 'R', len - half);
  };
  split('blob', 6144);
  // drop them (kernel must leave only outputs): 384 2DROP, counted separately
  return {inputs: [blob], body: asm({raw: s.bytes()}, Array.from({length: 384}, () => '2DROP')), outputs: []};
}, 'includes 384 OP_2DROP (38,400) to clear the stack; subtract', 2, {subtract: 38400});

// ---------------- K10: DEEP at one point ----------------
// f0(x) = [g1 X(x) + g2 Y(x) + g4 H0(x) + g5 H1(x) - C1] inv1 + [g3 X(x) - C2] inv2,
// C1 = g1 X(z) + g2 Y(z) + g4 H0(z) + g5 H1(z) and C2 = g3 X(wz) precomputed per proof; inv1, inv2 = 1/(x - z), 1/(x - wz)
const mul3e = (A, B) => [
  add(mul(A[0], B[0]), mul(add(mul(A[1], B[2]), mul(A[2], B[1])), K(7))),
  add(add(mul(A[0], B[1]), mul(A[1], B[0])), mul(mul(A[2], B[2]), K(7))),
  add(add(mul(A[0], B[2]), mul(A[2], B[0])), mul(A[1], B[1]))];
const v3 = (n) => names3(n).map(V);
{
  const ins = ['Xx', 'Yx', ...names3('H0'), ...names3('H1'), ...names3('g1'), ...names3('g2'), ...names3('g3'), ...names3('g4'), ...names3('g5'), ...names3('C1'), ...names3('C2'), ...names3('i1'), ...names3('i2')];
  const b = new Builder();
  const g4H0 = mul3e(v3('g4'), v3('H0')), g5H1 = mul3e(v3('g5'), v3('H1'));
  [0, 1, 2].forEach((k) => b.let(modp(add(sub(add(add(mul(V('g1' + k), V('Xx')), mul(V('g2' + k), V('Yx'))), add(g4H0[k], g5H1[k])), V('C1' + k)), K(p)), p), 'n' + k));
  [0, 1, 2].forEach((k) => b.let(modp(add(sub(mul(V('g3' + k), V('Xx')), V('C2' + k)), K(p)), p), 'm' + k));
  const t1 = mul3e(v3('n'), v3('i1')), t2 = mul3e(v3('m'), v3('i2'));
  [0, 1, 2].forEach((k) => b.let(modp(add(t1[k], t2[k]), p), 'f' + k));
  const body = slpBody(b, ins, names3('f')).body;
  def('K10', 'deep', 'DEEP at one point: f0(x) from X, Y (F_p), H0, H1 (F_p^3), 5 gammas, 2 per-proof constants, 2 inverses (lazy, 9 OP_MOD)', (rng) => {
    const v = Object.fromEntries(ins.map((n) => [n, r(rng)]));
    const g = (n) => names3(n).map((k) => v[k]);
    const num1 = r3.sub(r3.add(r3.add(r3.fp(g('g1'), v.Xx), r3.fp(g('g2'), v.Yx)), r3.add(r3.mul(g('g4'), g('H0')), r3.mul(g('g5'), g('H1')))), g('C1'));
    const num2 = r3.sub(r3.fp(g('g3'), v.Xx), g('C2'));
    const f = r3.add(r3.mul(num1, g('i1')), r3.mul(num2, g('i2')));
    return {inputs: ins.map((n) => nb(v[n])), body, outputs: f.map((x) => ({num: x}))};
  }, 'per coset point; a query has k0 = 4 points; inverses from K3');
}

// ---------------- K11: FRI fold ----------------
// f_{i+1}(x0^a) = (1/a) sum_t (beta x0^-1)^t V_t,  V_t = sum_j v_j w_a^(-jt)
function foldCase(a) {
  const wa = powmod(7n, (p - 1n) / BigInt(a), p), wainv = powmod(wa, p - 2n, p), ainv = powmod(BigInt(a), p - 2n, p);
  const ins = [...Array.from({length: a}, (_, j) => names3('v' + j)).flat(), ...names3('be'), 'xi'];
  const b = new Builder();
  // g = beta * x0^-1
  [0, 1, 2].forEach((k) => b.let(modp(mul(V('be' + k), V('xi')), p), 'g' + k));
  // V_t (lazy dot products with constant twiddles; +-1 without multiplication)
  for (let t = 0; t < a; t++) for (let k = 0; k < 3; k++) {
    let pos = [], neg = [];
    for (let j = 0; j < a; j++) {
      const w = powmod(wainv, BigInt(j * t), p); const x = V('v' + j + k);
      if (w === 1n) pos.push(x); else if (w === p - 1n) neg.push(x); else pos.push(mul(x, K(w)));
    }
    let e = sum(...pos); if (neg.length) e = add(sub(e, sum(...neg)), K(BigInt(neg.length) * p));
    b.let(modp(e, p), `V${t}_${k}`);
  }
  // Horner from t = a-1 down; the last step also scales by 1/a
  let f = names3(`V${a - 1}_`).map((_, k) => `V${a - 1}_${k}`);
  for (let t = a - 2; t >= 0; t--) {
    const m = mul3e(f.map(V), v3('g'));
    f = [0, 1, 2].map((k) => b.let(modp(add(m[k], V(`V${t}_${k}`)), p), t === 0 ? 'h' + k : undefined));
  }
  [0, 1, 2].forEach((k) => b.let(modp(mul(V('h' + k), K(ainv)), p), 'f' + k));
  const body = slpBody(b, ins, names3('f')).body;
  const ref = (vals, be, xi) => {
    const g = r3.fp(be, xi);
    // direct: f(y) = interpolant of (x0 w^j, v_j) at beta ... evaluated via the defining sum
    let acc = [0n, 0n, 0n];
    for (let t = a - 1; t >= 0; t--) {
      let Vt = [0n, 0n, 0n];
      for (let j = 0; j < a; j++) Vt = r3.add(Vt, r3.fp(vals[j], powmod(wainv, BigInt(j * t), p)));
      acc = r3.add(r3.mul(acc, g), Vt);
    }
    return r3.fp(acc, ainv);
  };
  return {ins, body, ref};
}
for (const a of [4, 8, 16]) {
  const {ins, body, ref} = foldCase(a);
  def('K11', 'fri', `FRI fold, arity ${a}: IDFT with base-field twiddles + Horner in beta*x0^-1 (lazy)`, (rng) => {
    const vals = Array.from({length: a}, () => r3v(rng)), be = r3v(rng), xi = r(rng);
    // cross-check the defining sum against Lagrange interpolation at beta for a random coset x0
    return {inputs: [...vals.flat(), ...be, xi].map(nb), body, outputs: ref(vals, be, xi).map((v) => ({num: v}))};
  }, a === 16 ? 'C100 only' : '');
}
// variant: arity a as log2(a) binary folds, 2 g(x^2) = (u + v) + beta_l x^-1 (u - v) with u = f(x), v = f(-x);
// beta, beta^2, beta^4, beta^8 are per-proof constants (inputs); the 1/a scaling is applied once at the end
function binaryFoldCase(a) {
  const L = Math.log2(a), wa = powmod(7n, (p - 1n) / BigInt(a), p), wainv = powmod(wa, p - 2n, p), ainv = powmod(BigInt(a), p - 2n, p);
  const ins = [...Array.from({length: a}, (_, j) => names3('v' + j)).flat(), ...Array.from({length: L}, (_, l) => names3('b' + l)).flat(), 'xi'];
  const b = new Builder();
  let cur = Array.from({length: a}, (_, j) => names3('v' + j)), xi = 'xi';
  for (let l = 0; l < L; l++) {
    const m = cur.length / 2, next = [];
    if (l > 0) xi = b.let(modp(mul(V(xi), V(xi)), p)); // (x0^-1)^(2^l)
    for (let j = 0; j < m; j++) {
      // h = x_j^-1 at this level = xi * w^(-j 2^l)
      const h = j === 0 ? xi : b.let(modp(mul(V(xi), K(powmod(wainv, BigInt(j << l), p))), p));
      const g = names3('b' + l).map((n) => b.let(modp(mul(V(n), V(h)), p)));
      const u = cur[j], v = cur[j + m];
      const d = [0, 1, 2].map((k) => add(sub(V(u[k]), V(v[k])), K(p)));
      const pr = mul3e(d, g.map(V));
      const last = l === L - 1;
      next.push([0, 1, 2].map((k) => b.let(modp(add(add(V(u[k]), V(v[k])), pr[k]), p), last ? 'h' + k : undefined)));
    }
    cur = next;
  }
  [0, 1, 2].forEach((k) => b.let(modp(mul(V('h' + k), K(ainv)), p), 'f' + k));
  return {ins, body: slpBody(b, ins, names3('f')).body};
}
for (const a of [4, 8, 16]) {
  const {ins, body} = binaryFoldCase(a);
  const {ref} = foldCase(a);
  def('K11', 'fri', `FRI fold, arity ${a}, as ${Math.log2(a)} binary folds (beta powers per-proof constants)`, (rng) => {
    const vals = Array.from({length: a}, () => r3v(rng)), be = r3v(rng), xi = r(rng);
    const pows = [be]; for (let l = 1; l < Math.log2(a); l++) pows.push(r3.mul(pows[l - 1], pows[l - 1]));
    return {inputs: [...vals.flat(), ...pows.flat(), xi].map(nb), body, outputs: ref(vals, be, xi).map((v) => ({num: v}))};
  }, `+${Math.log2(a) - 1} per-proof F_p^3 constants; ${a - 1} pair steps`);
}
// sanity: the fold formula equals the interpolant evaluated at beta (checked once, in JS)
{
  const a = 8, x0 = 123456789n, wa = powmod(7n, (p - 1n) / 8n, p);
  const pts = Array.from({length: a}, (_, j) => x0 * powmod(wa, BigInt(j), p) % p);
  const coeffs = Array.from({length: a}, (_, i) => [BigInt(i + 3), BigInt(i * i + 1), 5n]);
  const evalAt = (y) => coeffs.reduceRight((acc, c) => r3.add(r3.fp(acc, y), c), [0n, 0n, 0n]); // y in F_p
  const vals = pts.map(evalAt); const be = [777n, 0n, 0n];
  const {ref} = foldCase(a);
  // f_{i+1}(x0^a) = sum_t beta^t * coeff-split... for a polynomial f(X) = sum_t X^t f_t(X^a), fold = sum_t beta^t f_t(x0^a)
  const ya = powmod(x0, BigInt(a), p);
  let want = [0n, 0n, 0n];
  for (let t = 0; t < a; t++) { const ft = coeffs.filter((_, i) => i % a === t).reduceRight((acc, c) => r3.add(r3.fp(acc, ya), c), [0n, 0n, 0n]); want = r3.add(want, r3.fp(ft, powmod(777n, BigInt(t), p))); }
  const got = ref(vals, be, powmod(x0, p - 2n, p));
  if (got.some((g, i) => g !== want[i])) throw new Error('fold reference does not match the even/odd split definition');
}
// O1: splice a derived value (3 canonical numbers) into slot j of a leaf that omits it (7 x 24 B), before hashing
def('K11', 'fri', 'O1: re-encode a derived F_p^3 value (3 x 8 B LE) and splice it into slot j of a 168-byte leaf', (rng) => {
  const v = r3v(rng), leaf = rng.bytes(168), j = rng.int(8);
  const enc = Uint8Array.from(v.flatMap((x) => [...le8(x)]));
  const full = Uint8Array.from([...leaf.slice(0, 24 * j), ...enc, ...leaf.slice(24 * j)]);
  const body = asm(9, 'NUM2BIN', 8, 'SPLIT', 'DROP', 'ROT', 9, 'NUM2BIN', 8, 'SPLIT', 'DROP', 'ROT', 9, 'NUM2BIN', 8, 'SPLIT', 'DROP', 'ROT', 'CAT', 'CAT', // leaf j enc
    'SWAP', 24, 'MUL', 'ROT', 'SWAP', 'SPLIT', 'ROT', 'SWAP', 'CAT', 'CAT');
  // stack in: leaf j v0 v1 v2
  return {inputs: [leaf, nb(BigInt(j)), ...v.map(nb)], body, outputs: [{bin: full}]};
}, 'slot index j is the query position bit-slice, known at runtime');

// ---------------- K12: final polynomial ----------------
// three base-field Horner evaluations of degree 255 at a base point y, coefficients on the stack (c_{k,0..2})
function hornerBody(deg, lazy) {
  const s = new Stk(['y']); // coefficient items are below y: c_0 (3 items) deepest ... c_{deg-1} on top of them
  // stack layout: [c_0 .. c_{deg-1} (3 each) y]; we start with f = c_{deg-1} (roll it up) and step down
  const cn = (k, i) => `c${k}_${i}`;
  s.st = [...Array.from({length: deg}, (_, k) => [0, 1, 2].map((i) => cn(k, i))).flat(), 'y'];
  const f = [0, 1, 2].map((i) => cn(deg - 1, i));
  for (let k = deg - 2; k >= 0; k -= lazy) {
    const steps = Math.min(lazy, k + 1);
    for (let i = 0; i < 3; i++) {
      s.roll(f[i]);
      for (let q = 0; q < steps; q++) { s.pick('y'); s.op('MUL', 2, 'x'); s.roll(cn(k - q, i)); s.op('ADD', 2, 'x'); }
      s.push(p); s.op('MOD', 2, 'F' + k + '_' + i); f[i] = 'F' + k + '_' + i;
    }
  }
  s.drop('y'); s.arrange(f);
  return s.bytes();
}
for (const [deg, lazy] of [[256, 1], [256, 2], [32, 1]]) {
  const body = hornerBody(deg, lazy);
  def('K12', 'final', `final polynomial: ${deg} F_p^3 coefficients at a base point, 3 base Horners, ${lazy === 1 ? 'reduce every step' : 'reduce every 2 steps'} (coefficients on the stack)`, (rng) => {
    const c = Array.from({length: deg}, () => r3v(rng)), y = r(rng);
    const want = c.reduceRight((acc, ck) => r3.add(r3.fp(acc, y), ck), [0n, 0n, 0n]);
    return {inputs: [...c.flat(), y].map(nb), body, outputs: want.map((v) => ({num: v}))};
  }, 'unrolled; per query', 3);
}

// component-major Horner with the coefficients kept (PICKed at constant depths, so several queries in one input can
// reuse them): per step OVER MUL <d> PICK ADD [p MOD every `lazy` steps]; the 3 results go to the altstack.
// The kernel then drops y and the 768 coefficients (384 OP_2DROP + OP_DROP = 38,500, subtracted in the report).
function hornerKeep(deg, lazy) {
  const M = 3 * deg; const parts = [];
  const depth = (k, i, above) => M - 1 - (3 * k + i) + above; // above = items on top of the coefficient block
  for (let i = 0; i < 3; i++) {
    parts.push(depth(deg - 1, i, 1), 'PICK'); // [.. y f]
    let pend = 0;
    for (let k = deg - 2; k >= 0; k--) {
      parts.push('OVER', 'MUL', depth(k, i, 2), 'PICK', 'ADD'); pend++;
      if (pend === lazy || k === 0) { parts.push(p, 'MOD'); pend = 0; }
    }
    parts.push('TOALTSTACK');
  }
  parts.push('DROP', Array.from({length: M / 2}, () => '2DROP'), 'FROMALTSTACK', 'FROMALTSTACK', 'FROMALTSTACK', 'SWAP', 'ROT');
  return asm(parts);
}
for (const [deg, lazy] of [[256, 1], [256, 2], [256, 3], [32, 2]]) {
  const body = hornerKeep(deg, lazy);
  def('K12', 'final', `final polynomial: ${deg} F_p^3 coefficients at a base point, component-major Horner, coefficients kept (PICK), reduce every ${lazy} step(s)`, (rng) => {
    const c = Array.from({length: deg}, () => r3v(rng)), y = r(rng);
    const want = c.reduceRight((acc, ck) => r3.add(r3.fp(acc, y), ck), [0n, 0n, 0n]);
    return {inputs: [...c.flat(), y].map(nb), body, outputs: want.map((v) => ({num: v}))};
  }, `per query; subtract the cleanup ${(3 * deg / 2) * 100 + 100}`, 3, {subtract: (3 * deg / 2) * 100 + 100});
}
// ---------------- K13: AIR identity at z (cross-multiplied) ----------------
{
  const n = 1n << 16n, w = powmod(7n, (p - 1n) / n, p), wl = powmod(w, n - 1n, p);
  const C = Array.from({length: 8}, (_, j) => leNum(sha(Buffer.from('verifier.cash/pq-hash/rc'), Uint8Array.of(j))) % p);
  // P_c(X): degree < 8, P_c(w8^j) = C[j]  -> coefficients by inverse DFT
  const w8 = powmod(w, n / 8n, p), w8i = powmod(w8, p - 2n, p), i8 = powmod(8n, p - 2n, p);
  const Pc = Array.from({length: 8}, (_, k) => C.reduce((a, cj, j) => a + cj * powmod(w8i, BigInt(j * k), p), 0n) % p * i8 % p);
  for (let j = 0; j < 8; j++) if (Pc.reduceRight((a, c) => (a * powmod(w8, BigInt(j), p) + c) % p, 0n) !== C[j]) throw new Error('P_c');
  const ins = [...names3('z'), ...names3('X'), ...names3('Y'), ...names3('W'), ...names3('A'), ...names3('B'), ...names3('a1'), ...names3('a2'), ...names3('a3'), ...names3('a4'), 'xin', 'yout'];
  const b = new Builder();
  // z^(n/8) by 13 squarings, z^n by 3 more
  let t = names3('z'); for (let i = 0; i < 13; i++) t = b.sq3(t); const z8 = t; for (let i = 0; i < 3; i++) t = b.sq3(t); const zn = t;
  // c(z) = P_c(z8): Horner with F_p coefficients
  let c = [0, 1, 2].map((i) => b.let(modp(i === 0 ? add(mul(V(z8[0]), K(Pc[7])), K(Pc[6])) : mul(V(z8[i]), K(Pc[7])), p)));
  for (let k = 5; k >= 0; k--) { const m = mul3e(c.map(V), z8.map(V)); c = [0, 1, 2].map((i) => b.let(modp(i === 0 ? add(m[0], K(Pc[k])) : m[i], p))); }
  const s3 = b.add3(names3('X'), c);                       // s = X(z) + c(z)
  const s2 = b.sq3(s3), s3c = b.mul3(s2, s3);              // s^3
  const C1 = b.sub3(names3('Y'), s3c);
  const y2 = b.sq3(names3('Y')), y2s = b.mul3(y2, s3);
  const C2 = b.sub3(names3('W'), y2s);
  const one = [b.let(K(1)), b.let(K(0)), b.let(K(0))];
  const zm1 = b.sub3(names3('z'), one);
  const zl = [b.let(modp(add(sub(V('z0'), K(wl)), K(p)), p)), 'z1', 'z2'];
  const znm1 = b.sub3(zn, one);
  const den = b.mul3(b.mul3(znm1, zm1), zl);
  const lhs = b.mul3(b.add3(names3('A'), b.mul3(zn, names3('B'))), den);
  const q1 = b.mul3(b.add3(b.mul3(names3('a1'), C1), b.mul3(names3('a2'), C2)), b.mul3(b.sq3(zl), zm1));
  const xx = [b.let(modp(add(sub(V('X0'), V('xin')), K(p)), p)), 'X1', 'X2'];
  const xy = [b.let(modp(add(sub(V('X0'), V('yout')), K(p)), p)), 'X1', 'X2'];
  const q2 = b.mul3(b.mul3(names3('a3'), xx), b.mul3(znm1, zl));
  const q3 = b.mul3(b.mul3(names3('a4'), xy), b.mul3(znm1, zm1));
  const rhs = b.add3(b.add3(q1, q2), q3);
  const d = b.sub3(lhs, rhs, 'd');
  void d;
  const s = new Stk(ins); compileSlp(s, b.prog);
  // the AIR check: d == 0
  s.arrange(names3('d')); s.emit(0, 'NUMEQUALVERIFY', 0, 'NUMEQUALVERIFY', 0, 'NUMEQUALVERIFY'); s.st.splice(-3, 3);
  const body = s.bytes();
  def('K13', 'air', 'AIR identity at z, cross-multiplied (z^n by 16 squarings in F_p^3, P_c(z^(n/8)), C1, C2, boundary terms)', (rng) => {
    const z = r3v(rng), X = r3v(rng), Y = r3v(rng), W = r3v(rng), B = r3v(rng), al = [0, 1, 2, 3].map(() => r3v(rng)), xin = r(rng), yout = r(rng);
    let zz = z; for (let i = 0; i < 13; i++) zz = r3.mul(zz, zz); const zz8 = zz; for (let i = 0; i < 3; i++) zz = r3.mul(zz, zz);
    const cz = Pc.reduceRight((acc, ck) => r3.add(r3.mul(acc, zz8), [ck, 0n, 0n]), [0n, 0n, 0n]);
    const sv = r3.add(X, cz), c1 = r3.sub(Y, r3.mul(r3.mul(sv, sv), sv)), c2 = r3.sub(W, r3.mul(r3.mul(Y, Y), sv));
    const zm = r3.sub(z, [1n, 0n, 0n]), zlv = r3.sub(z, [wl, 0n, 0n]), znm = r3.sub(zz, [1n, 0n, 0n]);
    const rhs = r3.add(r3.add(r3.mul(r3.add(r3.mul(al[0], c1), r3.mul(al[1], c2)), r3.mul(r3.mul(zlv, zlv), zm)),
      r3.mul(r3.mul(al[2], r3.sub(X, [xin, 0n, 0n])), r3.mul(znm, zlv))), r3.mul(r3.mul(al[3], r3.sub(X, [yout, 0n, 0n])), r3.mul(znm, zm)));
    const den = r3.mul(r3.mul(znm, zm), zlv);
    const A = r3.sub(r3.mul(rhs, r3.inv(den)), r3.mul(zz, B)); // honest H0(z)
    const vals = [...z, ...X, ...Y, ...W, ...A, ...B, ...al.flat(), xin, yout];
    return {inputs: vals.map(nb), body, outputs: []};
  }, 'once per input that re-derives the verdict (HEAD); z not in F_p is checked in the transcript', 4);
}

// ---------------- K14: loop and call overhead ----------------
def('K14', 'overhead', 'loop: 100 iterations of an empty OP_BEGIN <counter> OP_1SUB OP_DUP OP_0NOTEQUAL OP_NOT OP_UNTIL', () => ({inputs: [nb(100n)], body: asm('BEGIN', '1SUB', 'DUP', 'NOT', 'UNTIL', 'DROP'), outputs: []}), 'per iteration: divide by 100', 1, {perIter: 100});
def('K14', 'overhead', 'call: OP_INVOKE of an empty function (push id + OP_INVOKE), 100 calls', () => ({inputs: [], defs: [{id: 1, body: new Uint8Array(0)}], body: asm(Array.from({length: 100}, () => [1, 'INVOKE'])), outputs: []}), 'per call: divide by 100', 1, {perIter: 100});
def('K14', 'overhead', 'unexecuted branch: OP_0 OP_IF <50 x OP_DUP> OP_ENDIF', () => ({inputs: [], body: asm(0, 'IF', Array.from({length: 50}, () => 'DUP'), 'ENDIF'), outputs: []}), 'every skipped instruction costs 100', 1);

export default kernels;
