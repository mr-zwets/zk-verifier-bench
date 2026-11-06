// SI-GLS redeem script generator (bch-spec). See README.md for the protocol and the spec rules.
// Unlocking: <WQ> <WS> <redeem>. Every item is named on the assembler's symbolic stack.
import assert from 'node:assert/strict';
import {Asm, Kernel, OP, pushNum, pushData} from './asm.mjs';
import {p, r, mod, ETA, GAMMA1, frob1Affine, PI, PI_SUM_OFFSET, PSI, B_TWIST, DIGITS, NE, VKC} from './math.mjs';
import {TAG, WS_SIZE, NQ_MAX, NSTATES, le32} from './protocol.mjs';

const ITERS = Number(process.env.SCHED_ITERS ?? 4000);
const F2c = (a) => [a.c0, a.c1];

// ---------------- kernels (DAGs over named stack items) ----------------
// B projective doubling + line at +-z + F^2 accumulation. env: yP yPt xz3 xz3t z3 z3t
export function kBDbl() {
  const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map(I);
  const [b0, b1] = [E('b30'), E('b31')];
  const B0 = m(mul(add(Y0, Y1), sub(Y0, Y1))), B1 = m(mul(add(Y0, Y0), Y1));
  const C0 = m(mul(add(Z0, Z1), sub(Z0, Z1))), C1 = m(mul(add(Z0, Z0), Z1));
  const E0 = m(sub(mul(b0, C0), mul(b1, C1))), E1 = m(add(mul(b0, C1), mul(b1, C0)));
  const F0 = k.small(E0, 3), F1 = k.small(E1, 3);
  const t0 = mul(X0, Y0), t1 = mul(X1, Y1), t2 = mul(add(X0, X1), add(Y0, Y1));
  const XY0 = m(sub(t0, t1)), XY1 = m(sub(sub(t2, t0), t1));
  const D0 = k.small(sub(B0, F0), 2), D1 = k.small(sub(B1, F1), 2);
  const X30 = m(sub(mul(XY0, D0), mul(XY1, D1))), X31 = m(add(mul(XY0, D1), mul(XY1, D0)));
  const G0 = add(B0, F0), G1 = add(B1, F1);
  const Y30 = m(sub(mul(add(G0, G1), sub(G0, G1)), k.small(mul(add(E0, E1), sub(E0, E1)), 12)));
  const Y31 = m(sub(k.small(mul(G0, G1), 2), k.small(mul(E0, E1), 24)));
  const S0 = add(Y0, Z0), S1 = add(Y1, Z1);
  const H0 = m(sub(sub(mul(add(S0, S1), sub(S0, S1)), B0), C0)), H1 = m(sub(sub(mul(add(S0, S0), S1), B1), C1));
  const B40 = k.small(B0, 4), B41 = k.small(B1, 4);
  const Z30 = m(sub(mul(B40, H0), mul(B41, H1))), Z31 = m(add(mul(B40, H1), mul(B41, H0)));
  const X20 = mul(add(X0, X1), sub(X0, X1)), X21 = mul(add(X0, X0), X1);
  const o = m(k.sum(mul(E('xz3'), X20), mul(E('xz3t'), X21), mul(E('z3'), sub(E0, B0)), mul(E('z3t'), sub(E1, B1))));
  const e = m(add(mul(E('yP'), H0), mul(E('yPt'), H1)));
  const Fp = I('Fp'), Fm = I('Fm');
  k.output(X30, X31, Y30, Y31, Z30, Z31, m(mul(mul(Fp, Fp), sub(e, o))), m(mul(mul(Fm, Fm), add(e, o))));
  return k;
}
// B projective mixed addition with (xq, yq) + line + accumulation * (cp, cm). env: yP yPt xz xzt z3 z3t
export function kBAdd() {
  const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (a, b) => k.mul(a, b), add = (a, b) => k.add(a, b), sub = (a, b) => k.sub(a, b);
  const [X0, X1, Y0, Y1, Z0, Z1, xq0, xq1, yq0, yq1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'xq0', 'xq1', 'yq0', 'yq1'].map(I);
  const fm = (a0, a1, b0, b1) => { const u0 = mul(a0, b0), u1 = mul(a1, b1), u2 = mul(add(a0, a1), add(b0, b1)); return [sub(u0, u1), sub(sub(u2, u0), u1)]; };
  const fs = (a0, a1, b0, b1) => [sub(mul(a0, b0), mul(a1, b1)), add(mul(a0, b1), mul(a1, b0))];
  const [qz0, qz1] = fs(yq0, yq1, Z0, Z1); const th0 = m(sub(Y0, qz0)), th1 = m(sub(Y1, qz1));
  const [xz0, xz1] = fs(xq0, xq1, Z0, Z1); const la0 = m(sub(X0, xz0)), la1 = m(sub(X1, xz1));
  const Cc0 = m(mul(add(th0, th1), sub(th0, th1))), Cc1 = m(mul(add(th0, th0), th1));
  const D0 = m(mul(add(la0, la1), sub(la0, la1))), D1 = m(mul(add(la0, la0), la1));
  const [e0, e1] = fm(la0, la1, D0, D1); const E0 = m(e0), E1 = m(e1);
  const [f0, f1] = fm(Z0, Z1, Cc0, Cc1); const F0 = m(f0), F1 = m(f1);
  const [g0, g1] = fm(X0, X1, D0, D1); const G0 = m(g0), G1 = m(g1);
  const H0 = sub(add(E0, F0), k.small(G0, 2)), H1 = sub(add(E1, F1), k.small(G1, 2));
  const [x30, x31] = fm(la0, la1, H0, H1);
  const [a0, a1] = fs(th0, th1, sub(G0, H0), sub(G1, H1)), [b0, b1] = fs(Y0, Y1, E0, E1);
  const [z30, z31] = fm(Z0, Z1, E0, E1);
  const [tx0, tx1] = fs(th0, th1, xq0, xq1), [ly0, ly1] = fs(la0, la1, yq0, yq1);
  const o = m(sub(add(mul(E('z3'), sub(tx0, ly0)), mul(E('z3t'), sub(tx1, ly1))), add(mul(E('xz'), th0), mul(E('xzt'), th1))));
  const e = m(add(mul(E('yP'), la0), mul(E('yPt'), la1)));
  k.output(m(x30), m(x31), m(sub(a0, b0)), m(sub(a1, b1)), m(z30), m(z31), m(mul(mul(I('Fp'), add(e, o)), I('cp'))), m(mul(mul(I('Fm'), sub(e, o)), I('cm'))));
  return k;
}
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
function kEval() {
  const k = new Kernel(); const s = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i)); const x = [6, 7, 8, 9, 10, 11].map((i) => k.in('in' + i));
  const ev = k.mod(k.sum(s[0], k.mul(s[2], x[1]), k.mul(s[4], x[3]), x[5]));
  const od = k.mod(k.sum(k.mul(s[1], x[0]), k.mul(s[3], x[2]), k.mul(s[5], x[4])));
  return k.output(k.add(ev, od), k.sub(ev, od));
}
// Affine chart evaluation at +-x: 1 +- x*(b0 + b1*x^2 + ... + b5*x^10).
// The public EA wrapper has 12 inputs; x^3 and x^5 are dropped explicitly
// after this kernel consumes the ten values used by the polynomial.
function kAffineEval() {
  const k = new Kernel(); const b = [0, 1, 2, 3, 4, 5].map((i) => k.in('in' + i));
  const [x, x2, x4, x6] = [6, 7, 9, 11].map((i) => k.in('in' + i));
  const x8 = k.mod(k.mul(x6, x2)), x10 = k.mod(k.mul(x6, x4));
  const h = k.mod(k.sum(b[0], k.mul(b[1], x2), k.mul(b[2], x4), k.mul(b[3], x6), k.mul(b[4], x8), k.mul(b[5], x10)));
  const odd = k.mod(k.mul(x, h));
  return k.output(k.mod(k.add(k.c(1n), odd)), k.mod(k.sub(k.c(1n), odd)));
}

// Frob(1 + X*b) is linear in the six b words. Bake its six basis images
// from the field implementation and retain all 12 coefficients for terminal
// evaluation at z and eta*z.
const AFFINE_FROB_BASIS = Array.from({length: 6}, (_, j) => {
  const b = Array(6).fill(0n); b[j] = 1n; return frob1Affine(b);
});
AFFINE_FROB_BASIS.forEach((poly) => {
  assert.equal(poly[0], 1n, 'affine Frob constant');
  assert.ok([2, 4, 6, 8, 10].every((i) => poly[i] === 0n), 'affine Frob even terms');
});
function affineFrobPair(k, words, powers) {
  const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
  const full = [k.c(1n), ...powers, ...powers.slice(0, 5).map((x) => m(mul(powers[5], x)))];
  const ev = [k.c(1n)], od = [];
  for (let j = 0; j < 6; j++) for (let d = 1; d < 12; d++) {
    const c = AFFINE_FROB_BASIS[j][d]; if (!c) continue;
    (d & 1 ? od : ev).push(mul(mul(words[j], k.c(c)), full[d]));
  }
  const even = m(k.sum(...ev)), odd = m(k.sum(...od));
  return [m(k.add(even, odd)), m(k.sub(even, odd))];
}
// 16-entry subset table from v0..v3 (consumed): T[n] = prod (or sum) over bits of n; outputs T[15] .. T[0]
function kTable(mult) {
  const k = new Kernel(); const v = [0, 1, 2, 3].map((i) => k.in('in' + i)); const T = [k.c(mult ? 1n : 0n)];
  for (let n = 1; n < 16; n++) { const lo = n & -n, b = Math.log2(lo); T[n] = n === lo ? v[b] : mult ? k.mod(k.mul(T[n ^ lo], v[b])) : k.add(T[n ^ lo], v[b]); }
  return k.output(...T.slice().reverse());
}

// ---------------- program ----------------
// Layout during the event loop (bottom -> top):
//   main: [Dp (pile of 11 delta-slope pieces) | setup/terminal env | GT-GLS tables | hot env | loop state]
//   alt:  [WQ | WSp (pile of state pieces) | WSr (current state piece) | R]
// The loop-state order is the fixed point of the event body (computed by iterating the generator), so the
// loop needs no re-arrangement; bound functions (BADD, DSTEP) see one identical layout at every call site.
export function buildRedeem({stop} = {}) {
  let L0 = null;
  for (let attempt = 0; attempt < 8; attempt++) {
    try { return gen(L0, stop); } catch (e) { if (e.retryL0) { L0 = e.retryL0; continue; } throw e; }
  }
  throw new Error('loop layout did not converge');
}
const D_PIECE = 8; // delta slopes per pile piece (64 B each)
const WS_PIECE = 4; // states per altstack piece (192 B each)
function gen(L0guess, stop) {
  const a = new Asm(['WQ', 'WS']);
  const info = {sections: {}}; let mark = 0; const section = (name) => { info.sections[name] = (info.sections[name] ?? 0) + a.code.length - mark; mark = a.code.length; a.mark('end:' + name); };
  const STOP = (label) => { if (stop === label) throw {stopAt: label, asm: a}; };
  const U = (x) => a.pushBytes([0x00]).op(OP.CAT, 2, x + '#c').op(OP.BIN2NUM, 1, x); // unsigned LE decode of the top item
  // ---- functions ----
  a.defLocal('P', 0, 1, (s) => s.push(p, 'p'));
  // RD: [blob] -> [v, rest]: split one 32-byte LE word, decode unsigned (BIN2NUM(w || 0x00)), require v < p
  a.defLocal('RD', 1, 2, (s) => { s.push(32).op(OP.SPLIT, 2, 'w', 'rest').roll('w').pushBytes([0]).op(OP.CAT, 2, 'w0').op(OP.BIN2NUM, 1, 'v');
    s.pick('v').invoke('P', ['p']).op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1).roll('rest'); });
  a.defLocal('EV', 12, 2, (s) => s.kernel(kEval(), ['vp', 'vm'], {iters: ITERS}));
  a.defLocal('EA', 12, 2, (s) => { s.kernel(kAffineEval(), ['vp', 'vm'], {iters: ITERS}); s.drop('in8').drop('in10'); });
  a.defLocal('TM', 4, 16, (s) => s.kernel(kTable(true), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  a.defLocal('TA', 4, 16, (s) => s.kernel(kTable(false), Array.from({length: 16}, (_, i) => 'T' + (15 - i)), {iters: ITERS}));
  a.defLocal('G1C', 2, 0, (s) => { const k = new Kernel(); const x = k.in('in0'), y = k.in('in1'); k.output(k.mod(k.sub(k.mul(y, y), k.add(k.mul(k.mul(x, x), x), k.c(3n))))); s.kernel(k, ['d'], {iters: 200}); s.op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1); });
  a.defBound('BADD', (s) => s.kernel(kBAdd(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS}));
  a.defBound('DSTEP', (s) => {
    s.roll('D').emit(OP.SIZE); s.st.push('dsz'); s.op(OP.NOT, 1, 'dempty').ifElse((t) => { t.drop('D').pileTake('Dp', 'D'); });
    s.push(64).op(OP.SPLIT, 2, 'lb', 'D').roll('lb').push(32).op(OP.SPLIT, 2, 'w0', 'w1');
    s.op(OP.BIN2NUM, 1, 'n1').roll('w0').op(OP.BIN2NUM, 1, 'n0'); // baked slopes: < p < 2^254, so the LE word is a nonnegative number
    s.kernel(kDStep(), ['dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm'], {iters: ITERS});
  });
  section('init');

  // ---- 1. layout pin; WQ to the altstack; the delta-slope pile at the bottom; transcript and challenges ----
  a.emit(OP.DEPTH, ...pushNum(2), OP.NUMEQUALVERIFY); // exactly two witness items (with clean stack: layout pinned)
  a.roll('WQ').pick('WQ', 'WQc').roll('WQ').toAlt();  // alt: [WQ]
  const dlams = [...VKC.lams, VKC.frob2.lam]; assert.equal(dlams.length, 88); assert.equal(dlams.length % D_PIECE, 0);
  const pieces = []; for (let i = 0; i < dlams.length; i += D_PIECE) pieces.push(Buffer.concat(dlams.slice(i, i + D_PIECE).flatMap((l) => [le32(l.c0), le32(l.c1)])));
  a.pushPile('Dp', pieces.reverse()); // the first piece on top
  a.roll('WS').roll('WQc');
  a.pick('WS').emit(OP.SIZE); a.st.push('sz'); a.push(WS_SIZE).op(OP.NUMEQUALVERIFY, 2).drop();
  a.pushBytes(TAG, 'tag').pick('WS').op(OP.CAT, 2, 'tw').op(OP.SHA256, 1, 'h0');
  a.pick('h0').pushBytes(Buffer.from('rho')).op(OP.CAT, 2, 'hr').op(OP.SHA256, 1, 'rhoRaw');
  a.pick('WQc', 'WQs').emit(OP.SIZE); a.st.push('qsz'); a.drop('WQs');
  a.pick('qsz').push(32).op(OP.MOD, 2, 'qm').op(OP.NOT, 1, 'qok').op(OP.VERIFY, 1);
  a.pick('qsz', 'c').push(32).op(OP.NUMEQUAL, 2, 'qz');
  a.roll('qsz').push(1).push(32 * NQ_MAX + 1).op(OP.WITHIN, 3, 'qin').op(OP.VERIFY, 1);
  // canonical n_q: the leading word is nonzero, except for one-word zero
  a.pick('WQc', 'WQs').push(32).op(OP.SPLIT, 2, 'q0', 'qr').drop('qr').op(OP.BIN2NUM, 1, 'q0');
  a.op(OP.ZERONOTEQUAL, 1, 'nz').roll('qz').op(OP.BOOLOR, 2, 'qok').op(OP.VERIFY, 1);
  a.roll('h0').pick('rhoRaw').op(OP.CAT, 2, 'hh').roll('WQc').op(OP.CAT, 2, 'hq').op(OP.SHA256, 1, 'zRaw');
  a.invoke('P', ['p']);
  a.roll('zRaw'); U('zRaw'); a.pick('p').op(OP.MOD, 2, 'z');
  a.roll('rhoRaw'); U('rhoRaw'); a.pick('p').op(OP.MOD, 2, 'rho');
  section('transcript');
  STOP('transcript');

  // ---- 2. parse WS: statement, GLS strings, residue root; checks ----
  a.roll('WS');
  for (const n of ['xA', 'yA', 'xB0', 'xB1', 'yB0', 'yB1', 'xC', 'yC']) { a.invoke('RD', [n, 'WS']); }
  a.push(r, 'r');
  for (const n of ['n0', 'n1']) { a.roll('WS').push(32).op(OP.SPLIT, 2, 'w', 'WS').roll('w'); U(n); a.pick(n).pick('r').op(OP.LESSTHAN, 2, 'ok').op(OP.VERIFY, 1); }
  // nibble strings: 130 bytes & 0x0f (canonical: every nibble < 16)
  a.roll('WS').push(130).op(OP.SPLIT, 2, 'G', 'WS').roll('G').pick('G', 'Gc');
  a.pushBytes([0x0f, 0x0f], 'mk'); for (let i = 0; i < 6; i++) a.pick('mk', 'mk2').op(OP.CAT, 2, 'mk');
  a.pushBytes([0x0f, 0x0f]).op(OP.CAT, 2, 'mk');
  a.op(OP.AND, 2, 'Gm').pick('G', 'Gc2').op(OP.EQUALVERIFY, 2);
  a.roll('G').push(65).op(OP.SPLIT, 2, 'N0', 'N1');
  a.roll('WS'); for (let j = 0; j < 6; j++) a.invoke('RD', ['sc' + j, 'WS']);
  // the 33 states: pieces of WS_PIECE states to the altstack, last piece first (the first piece ends on top)
  { const nst = NSTATES; const cuts = []; for (let k = 0; k < nst; k += WS_PIECE) cuts.push(k * 192); // piece starts
    for (let i = cuts.length - 1; i >= 1; i--) { a.push(cuts[i]).op(OP.SPLIT, 2, 'WS', 'tail').toAlt(); a.alt.pop(); }
    a.toAlt(); a.alt.pop(); a.pushAltPile('WSp', cuts.length); }
  a.push(0, 'WSr').toAlt().push(0, 'R').toAlt(); // alt: [WQ, WSp, WSr, R]
  // curve checks: A, C on y^2 = x^3 + 3; B on y^2 = x^3 + b'
  a.pick('xA').pick('yA').invoke('G1C', []); a.pick('xC').pick('yC').invoke('G1C', []);
  a.push(B_TWIST.c0, 'b0').push(B_TWIST.c1, 'b1');
  { const k = new Kernel(); const [x0, x1, y0, y1] = ['xB0', 'xB1', 'yB0', 'yB1'].map((n) => k.env(n)); const m = (x) => k.mod(x);
    const xx0 = m(k.mul(k.add(x0, x1), k.sub(x0, x1))), xx1 = m(k.mul(k.add(x0, x0), x1));
    const c0 = k.sub(k.mul(xx0, x0), k.mul(xx1, x1)), c1 = k.add(k.mul(xx0, x1), k.mul(xx1, x0));
    k.output(m(k.sub(k.sub(k.mul(k.add(y0, y1), k.sub(y0, y1)), c0), k.in('b0'))), m(k.sub(k.sub(k.mul(k.add(y0, y0), y1), c1), k.in('b1'))), k.small(k.in('b0'), 3), k.small(k.in('b1'), 3));
    a.kernel(k, ['tw0', 'tw1', 'b30', 'b31'], {iters: 300}); a.roll('tw1').roll('tw0'); a.op(OP.NOT, 1, 'ok1').op(OP.VERIFY, 1).op(OP.NOT, 1, 'ok0').op(OP.VERIFY, 1); }
  section('parse+checks');
  STOP('parsed');

  // ---- 3. powers of z and eta z ----
  { const k = new Kernel(); const z = k.env('z'); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const z2 = m(mul(z, z)), z3 = m(mul(z2, z)), z4 = m(mul(z2, z2)), z5 = m(mul(z4, z)), z6 = m(mul(z3, z3));
    const eta = k.c(ETA), eta2 = k.sub(eta, k.c(1n)); // eta^2 = eta - 1
    // gamma^2 and gamma^3 are retained for the terminal psi maps.
    const fm = (a0, a1, b0, b1) => [m(k.sub(mul(a0, b0), mul(a1, b1))), m(k.add(mul(a0, b1), mul(a1, b0)))];
    const g1 = [k.c(GAMMA1.c0), k.c(GAMMA1.c1)], g2 = fm(...g1, ...g1), g3 = fm(...g2, ...g1);
    k.output(z2, z3, z4, z5, z6, m(mul(eta, z)), m(mul(eta2, z2)), k.neg(z3), k.neg(m(mul(eta, z4))), k.neg(m(mul(eta2, z5))), ...g2, ...g3, eta2);
    a.kernel(k, ['z2', 'z3', 'z4', 'z5', 'z6', 'ez', 'ez2', 'ez3', 'ez4', 'ez5', 'g20', 'g21', 'g30', 'g31', 'om'], {iters: 1500}); }
  const ZP = ['z', 'z2', 'z3', 'z4', 'z5', 'z6'], EZP = ['ez', 'ez2', 'ez3', 'ez4', 'ez5', 'z6'];
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of ZP) a.pick(n); a.invoke('EA', ['Scp', 'Scm']);
  section('powers');
  // ---- 4. GT-GLS tables: TP_k[n] = prod_{i in n} R_{k,i}(z), TM_k at -z, TB[n] = sum_{i in n} pi_i ----
  // R_{k,0}, R_{k,1}: baked monic reps; R_{k,2}, R_{k,3} are R_{k,0}, R_{k,1} at eta z
  a.push(1, 'pi0').pick('p').pick('r').op(OP.SUB, 2, 'pi1').pick('pi1').pick('pi1').op(OP.MUL, 2, 'q').pick('r').op(OP.MOD, 2, 'pi2').pick('pi1').pick('pi2').op(OP.MUL, 2, 'q').pick('r').op(OP.MOD, 2, 'pi3').invoke('TA', Array.from({length: 16}, (_, n) => `TB_${15 - n}`));
  for (const k of [0, 1]) {
    for (const i of [0, 1]) for (let j = 0; j < 6; j++) a.push(VKC.R[k][i][j], `R${k}${i}_${j}`);
    for (const i of [0, 1, 2, 3]) {
      for (let j = 0; j < 6; j++) (i < 2 ? a.pick.bind(a) : a.roll.bind(a))(`R${k}${i % 2}_${j}`);
      for (const n of i < 2 ? ZP : EZP) a.pick(n);
      a.invoke('EV', [`vp${i}`, `vm${i}`]);
    }
    a.arrange(['vp0', 'vp1', 'vp2', 'vp3']).invoke('TM', Array.from({length: 16}, (_, n) => `TP${k}_${15 - n}`));
    a.arrange(['vm0', 'vm1', 'vm2', 'vm3']).invoke('TM', Array.from({length: 16}, (_, n) => `TM${k}_${15 - n}`));
  }
  section('gls-tables');
  STOP('tables');

  // ---- 5. loop environment and state ----
  { const k = new Kernel(); const m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const t = k.sub(k.env('z6'), k.c(9n)), z3 = k.env('z3'), z = k.env('z');
    const yP = k.neg(k.in('yA')); const xz = m(mul(k.in('xA'), z)), cz = m(mul(k.in('xC'), z));
    const xzt = m(mul(xz, t));
    k.output(m(mul(z3, t)), yP, m(mul(yP, t)), xz, xzt, k.small(xz, 3), k.small(xzt, 3), cz, m(mul(cz, t)));
    a.kernel(k, ['z3t', 'yP', 'yPt', 'xz', 'xzt', 'xz3', 'xz3t', 'cz', 'czt'], {iters: 500}); }
  a.pick('yB0').op(OP.NEGATE, 1, 'nyB0').pick('yB1').op(OP.NEGATE, 1, 'nyB1');
  // GLS/digit group lives on the altstack between events: alt = [WQ, WSp, WSr, R, SCH, N0, N1, acc0, acc1, d]
  a.pushBytes(Buffer.from(DIGITS.slice(1).map((d) => (d < 0 ? 0x81 : d)).concat([0])), 'SCH').toAlt('SCH').toAlt('N0').toAlt('N1');
  a.push(0, 'acc0').toAlt().push(0, 'acc1').toAlt().push(DIGITS[0], 'd').toAlt();
  a.pick('xB0', 'X0').pick('xB1', 'X1').pick('yB0', 'Y0').pick('yB1', 'Y1').push(1, 'Z0').push(0, 'Z1');
  a.push(VKC.deltaAff.x.c0, 'xd0').push(VKC.deltaAff.x.c1, 'xd1');
  a.push(0, 'D').pick('xd0', 'dx0').pick('xd1', 'dx1').push(VKC.deltaAff.y.c0, 'dc0').push(VKC.deltaAff.y.c1, 'dc1').push(0, 'dl0').push(0, 'dl1');
  a.pick('Scm', 'Fp').pick('Scp', 'Fm');
  const HOT = ['xd0', 'xd1', 'xB0', 'xB1', 'yB0', 'yB1', 'nyB0', 'nyB1', 'Scp', 'Scm', 'yC', 'cz', 'czt', 'b30', 'b31', 'z3t', 'yP', 'yPt', 'xz', 'xzt', 'xz3', 'xz3t', 'z3', 'p'];
  const STATE = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'D', 'dx0', 'dx1', 'dc0', 'dc1', 'dl0', 'dl1', 'Fp', 'Fm']; // fixed point of the event body
  const moved = new Set([...HOT, ...STATE]);
  const L0 = L0guess ?? [...a.st.filter((x) => !moved.has(x)), ...HOT, ...STATE];
  a.arrangeAll(L0);
  a.piles.set('Dp', null); a.piles.set('WSp', null); // pile sizes vary inside the loop
  section('loop-setup');
  STOP('preloop');

  // ---- 6. the event loop (65 events) ----
  const lookup = (s, tbl, idx, out) => {
    assert.equal(s.top(), idx); s.st.pop(); const d0 = s.depth(`${tbl}_0`); for (let n = 1; n < 16; n++) assert.equal(s.depth(`${tbl}_${n}`), d0 + n, 'table layout ' + tbl);
    s.emit(...pushNum(d0), OP.ADD, OP.PICK); s.st.push(out);
  };
  a.loop((s) => {
    s.mark('bdbl'); s.kernel(kBDbl(), ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1', 'Fp', 'Fm'], {iters: ITERS});
    s.mark('dstep').pick('dx0', 's0').pick('dx1', 's1').invoke('DSTEP');
    s.mark('add'); s.peekAlt('dt').ifElse((t) => {
      t.peekAlt('dt').push(0).op(OP.LESSTHAN, 2, 'neg').ifElse(
        (u) => { u.pick('xB0', 'xq0').pick('xB1', 'xq1').pick('nyB0', 'yq0').pick('nyB1', 'yq1').pick('Scp', 'cp').pick('Scm', 'cm'); },
        (u) => { u.pick('xB0', 'xq0').pick('xB1', 'xq1').pick('yB0', 'yq0').pick('yB1', 'yq1').pick('Scm', 'cp').pick('Scp', 'cm'); });
      t.invoke('BADD'); t.pick('xd0', 's0').pick('xd1', 's1').invoke('DSTEP');
    });
    // GLS/digit group out of the altstack; next digit (SCH holds the digits of events 1..64 and a dummy)
    s.mark('digit'); for (const n of ['d', 'acc1', 'acc0', 'N1', 'N0', 'SCH']) s.fromAlt(n);
    s.drop('d').roll('SCH').push(1).op(OP.SPLIT, 2, 'db', 'SCH').roll('db').op(OP.BIN2NUM, 1, 'd');
    // GT-GLS: one nibble per group from the hashed strings; binding accumulators, then F
    s.mark('gls');
    s.roll('N0').push(1).op(OP.SPLIT, 2, 'b0', 'N0').roll('b0').op(OP.BIN2NUM, 1, 'i0');
    s.roll('N1').push(1).op(OP.SPLIT, 2, 'b1', 'N1').roll('b1').op(OP.BIN2NUM, 1, 'i1');
    for (const k of [0, 1]) { s.roll('acc' + k).pick('acc' + k, 'accc').op(OP.ADD, 2, 'a2').pick('i' + k, 'x'); lookup(s, 'TB', 'x', 'tb'); s.op(OP.ADD, 2, 'acc' + k); }
    for (const [F, T] of [['Fp', 'TP'], ['Fm', 'TM']]) {
      s.pick('i0', 'x'); lookup(s, T + '0', 'x', 'u'); s.pick('i1', 'x'); lookup(s, T + '1', 'x', 'v');
      s.op(OP.MUL, 2, 'uv').roll(F).op(OP.MUL, 2, 'w').pick('p').op(OP.MOD, 2, F);
    }
    s.drop('i0').drop('i1');
    // boundary iff the remaining digit count m is odd or 0 (states after events 2, 4, .., 64, 65)
    s.mark('bnd');
    s.pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').pick('m').push(2).op(OP.MOD, 2, 'odd').roll('m').op(OP.NOT, 1, 'last').op(OP.BOOLOR, 2, 'bnd');
    s.ifElse((t) => {
      t.fromAlt('R').fromAlt('WSr').emit(OP.SIZE); t.st.push('wsz'); t.op(OP.NOT, 1, 'wempty').ifElse((u) => { u.drop('WSr').altPileTake('WSr'); });
      t.push(192).op(OP.SPLIT, 2, 'S', 'WSr').toAlt('WSr');
      for (let j = 0; j < 6; j++) t.invoke('RD', ['s' + j, 'S']);
      t.drop('S'); for (const n of ZP) t.pick(n); t.invoke('EA', ['Sp', 'Sm']);
      const k = new Kernel(); const R = k.in('R');
      k.output(k.in('Sp'), k.in('Sm'), k.mod(k.sub(k.add(k.mul(R, k.env('rho')), k.mul(k.in('Fp'), k.in('Sm'))), k.mul(k.in('Fm'), k.in('Sp')))));
      t.kernel(k, ['Fp', 'Fm', 'R'], {iters: 500}); t.toAlt('R');
    });
    s.mark('loopend').pick('SCH', 'SCHc').op(OP.SIZE, 1, 'SCHc', 'm').op(OP.NIP, 2, 'm').op(OP.NOT, 1, 'last');
    for (const n of ['SCH', 'N0', 'N1', 'acc0', 'acc1', 'd']) s.toAlt(n);
    s.roll('last');
  }, {onExit: (nat) => { if (nat.join() !== L0.join()) throw {retryL0: nat}; }});
  section('loop');
  STOP('postloop');

  // ---- 7. terminal ----
  // psi(B) = (conj(xB) PX1, conj(yB) PY1); -psi^2(B) = (omega xB, yB), omega = eta^2; -psi^3(B) = (omega psi_x, psi_y)
  const OMEGA = mod(ETA * ETA); assert.equal(OMEGA, PSI[1].x.c0); assert.equal(PSI[1].x.c1, 0n); assert.equal(PSI[1].y.c0, p - 1n); assert.equal(PSI[1].y.c1, 0n);
  // conj(a) * g = (a0 g0 + a1 g1, a0 g1 - a1 g0)
  const conjMul = (k, a0, a1, g0, g1) => [k.mod(k.add(k.mul(a0, g0), k.mul(a1, g1))), k.mod(k.sub(k.mul(a0, g1), k.mul(a1, g0)))];
  const psiKernel = () => { const k = new Kernel(); const [x0, x1, y0, y1, g20, g21, g30, g31] = ['xB0', 'xB1', 'yB0', 'yB1', 'g20', 'g21', 'g30', 'g31'].map((n) => k.env(n)); return {k, px: conjMul(k, x0, x1, g20, g21), py: conjMul(k, y0, y1, g30, g31)}; };
  { const {k, px, py} = psiKernel(); k.output(...px, ...py); a.kernel(k, ['xq0', 'xq1', 'yq0', 'yq1'], {iters: 300}); }
  a.push(1, 'cp').push(1, 'cm').invoke('BADD');
  { const k = new Kernel(); k.output(...conjMul(k, k.env('xd0'), k.env('xd1'), k.env('g20'), k.env('g21'))); a.kernel(k, ['s0', 's1'], {iters: 100}); } // x of psi(delta)
  a.invoke('DSTEP');
  { const k = new Kernel(); k.output(k.mod(k.mul(k.env('xB0'), k.env('om'))), k.mod(k.mul(k.env('xB1'), k.env('om')))); a.kernel(k, ['xq0', 'xq1'], {iters: 50}); }
  a.pick('yB0', 'yq0').pick('yB1', 'yq1').push(1, 'cp').push(1, 'cm').invoke('BADD');
  a.pick('dx0', 's0').pick('dx1', 's1').invoke('DSTEP'); // s is irrelevant for the last line
  a.roll('D').op(OP.SIZE, 1, 'D', 'dl').op(OP.NOT, 1, 'e').op(OP.VERIFY, 1).drop('D'); a.pileDone('Dp'); // all 88 delta slopes consumed
  // endpoint: (X : Y : Z) == -psi^3(B) = (omega px, py), Z != 0  (exact G2 membership; no exceptional step)
  { const {k, px, py} = psiKernel(); const [X0, X1, Y0, Y1, Z0, Z1] = ['X0', 'X1', 'Y0', 'Y1', 'Z0', 'Z1'].map((n) => k.in(n));
    const fs = (a0, a1, b0, b1) => [k.sub(k.mul(a0, b0), k.mul(a1, b1)), k.add(k.mul(a0, b1), k.mul(a1, b0))];
    const [u0, u1] = fs(px[0], px[1], Z0, Z1), [v0, v1] = fs(py[0], py[1], Z0, Z1);
    k.output(k.mod(k.sub(X0, k.mul(k.env('om'), u0))), k.mod(k.sub(X1, k.mul(k.env('om'), u1))), k.mod(k.sub(Y0, v0)), k.mod(k.sub(Y1, v1)), k.mod(Z0), k.mod(Z1));
    a.kernel(k, ['ex0', 'ex1', 'ey0', 'ey1', 'ez0', 'ez1'], {iters: 1000});
    a.op(OP.BOOLOR, 2, 'znz').op(OP.VERIFY, 1); for (let i = 0; i < 4; i++) a.op(OP.NOT, 1, 'q').op(OP.VERIFY, 1); }
  // F *= Rconst(+-z) * S_c(+-eta z)
  for (let j = 0; j < 6; j++) a.push(VKC.Rconst[j]); for (const n of ZP) a.pick(n); a.invoke('EV', ['rp', 'rm']);
  for (let j = 0; j < 6; j++) a.pick('sc' + j); for (const n of EZP) a.pick(n); a.invoke('EA', ['ep', 'em']); // S_c(+-eta z) = [c^(p^2)]
  { const k = new Kernel(); k.output(k.mod(k.mul(k.mul(k.in('Fp'), k.in('rp')), k.in('ep'))), k.mod(k.mul(k.mul(k.in('Fm'), k.in('rm')), k.in('em')))); a.kernel(k, ['Fp', 'Fm'], {iters: 200}); }
  // W(+-z) = Frob(S_c)(+-z) Frob(S_c)(+-eta z) = [c^p c^(p^3)];  R <- R rho + F+ W(-z) - F- W(+z)
  a.fromAlt('d').fromAlt('acc1').fromAlt('acc0').fromAlt('N1').fromAlt('N0').fromAlt('SCH');
  for (const n of ['d', 'N1', 'N0', 'SCH']) a.drop(n);
  a.fromAlt('R').fromAlt('WSr').drop('WSr'); a.pileDone('WSp'); a.fromAlt('WQ'); // all 33 states consumed (WS size pinned)
  // Frob(S_c)(x) is evaluated from the affine six-word Frobenius map.
  { const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n), m = (x) => k.mod(x), mul = (x, y) => k.mul(x, y);
    const sc = [0, 1, 2, 3, 4, 5].map((j) => I('sc' + j));
    const [a1, a2] = affineFrobPair(k, sc, ZP.map((n) => E(n))), [b1, b2] = affineFrobPair(k, sc, EZP.map((n) => E(n)));
    k.output(m(k.sub(k.add(mul(I('R'), E('rho')), mul(I('Fp'), m(mul(a2, b2)))), mul(I('Fm'), m(mul(a1, b1))))));
    a.kernel(k, ['R'], {iters: 1500}); }
  // GT-GLS binding (exact integers): acc_k = sum_i u_{k,i} pi_i, u = e + 2^64:  acc_k - 2^64 sum_i pi_i - n_k == 0 (mod r)
  a.push(PI_SUM_OFFSET, 'pso');
  for (const k of [0, 1]) a.roll('acc' + k).roll('n' + k).op(OP.SUB, 2, 'dn').pick('pso').op(OP.SUB, 2, 'dn2').pick('r').op(OP.MOD, 2, 'dr').op(OP.NOT, 1, 'ok').op(OP.VERIFY, 1);
  a.drop('pso');
  section('terminal');
  // ---- 8. quotient: Q(z) = z q(z^2), Horner over WQ (highest first) 4 words per step, each word < p ----
  // left-pad WQ with zero words to a multiple of 4 words (does not change the polynomial)
  a.push(0).push(96).op(OP.NUM2BIN, 2, 'zeros').push(128).pick('WQ').op(OP.SIZE, 1, 'WQ_', 'qs').op(OP.NIP, 2, 'qs').push(128).op(OP.MOD, 2, 'qr').op(OP.SUB, 2, 'pad')
    .push(128).op(OP.MOD, 2, 'pad').op(OP.SPLIT, 2, 'zp', 'zr').drop('zr').roll('WQ').op(OP.CAT, 2, 'WQ');
  { const k = new Kernel(); const z2 = k.env('z2'), z4 = k.env('z4'); k.output(k.mod(k.mul(z4, z4)), k.mod(k.mul(z2, z4))); a.kernel(k, ['z8', 'z6b'], {iters: 50}); }
  a.push(0, 'acc');
  a.loop((s) => {
    s.roll('WQ').push(128).op(OP.SPLIT, 2, 'Q4', 'WQ').roll('Q4');
    for (let j = 0; j < 4; j++) s.invoke('RD', ['q' + j, 'Q4']);
    s.drop('Q4');
    const k = new Kernel(); const I = (n) => k.in(n), E = (n) => k.env(n);
    k.output(k.mod(k.sum(k.mul(I('acc'), E('z8')), k.mul(I('q0'), E('z6b')), k.mul(I('q1'), E('z4')), k.mul(I('q2'), E('z2')), I('q3')))); s.kernel(k, ['acc'], {iters: 300});
    s.pick('WQ', 'WQc').op(OP.SIZE, 1, 'WQc', 'qs').op(OP.NIP, 2, 'qs').op(OP.NOT, 1, 'done');
  });
  a.drop('WQ');
  { const k = new Kernel(); const z6 = k.env('z6');
    const Mz = k.add(k.sub(k.mul(z6, z6), k.mul(k.c(18n), z6)), k.c(82n));
    k.output(k.mod(k.sub(k.in('R'), k.mul(k.mod(k.mul(k.env('z'), k.in('acc'))), k.mod(Mz))))); a.kernel(k, ['fin'], {iters: 300}); }
  a.op(OP.NOT, 1, 'result');
  section('final');
  // clean stack: drop everything below the result (the entry DEPTH check pins the item count)
  assert.equal(a.alt.length, 0, 'altstack not empty');
  a.op(OP.TOALT, 1); a.emit(OP.BEGIN, OP.DROP, OP.DEPTH, OP.NOT, OP.UNTIL, OP.FROMALT); a.st = ['result'];
  section('cleanup');
  const code = Uint8Array.from([...a.prologue(), ...a.code]);
  info.marks = a.marks.map((m) => ({name: m.name, off: m.off + a.prologue().length}));
  info.prologue = a.prologue().length; info.funcs = Object.fromEntries([...a.ctx.funcs].filter(([, f]) => f.id !== null).map(([n, f]) => [n, f.code.length]));
  info.L0 = L0;
  return {redeem: code, info};
}

// assemble a partial program for debugging: everything up to a STOP label (stack left as is)
export function buildPartial(label) {
  try { buildRedeem({stop: label}); } catch (e) { if (!e.stopAt) throw e; return {code: Uint8Array.from([...e.asm.prologue(), ...e.asm.code]), names: e.asm.st.slice()}; }
  throw new Error('label not reached: ' + label);
}
