// bn-native-sound (SI-MX3) protocol: the 3-input layout, transcript, degree-6 honest prover,
// B walk (one inverse-norm witness t per B step), and a value-level mirror of the on-chain computation.
//
// The mathematics is SI-GLS (../sound-si-gls/README.md): the same NAF schedule, 2-event chunks, 33 states,
// GT-GLS fold, residue root and batched odd identity at +-z. Only two things change:
//   - the B lines are the affine lines (1, -lambda, lambda x - y) instead of the projective ones (Fp2 multiples
//     of the same lines); all transmitted root/state representatives use the universal degree-6 quotient chart.
//   - the program runs as 3 roles (one per input) over the event ranges CUTS, chained by handovers.
import assert from 'node:assert/strict';
import {encodeDataPush} from '@bitauth/libauth';
import {bn254} from '@noble/curves/bn254.js';
import {p, r, mod, F2, F12, f2, g1, g2, DIGITS, NE, NADD, PI, GLS_BITS, GLS_OFFSET, glsDecompose, glsFactorPoly,
  VKC, psiK, ETA, degree6Poly, degree6Witnesses, frob1Degree6, linePoly, fromPoly, pmul, psub, pneg, psubst, peval, pdivM, M, VK, Fp} from '../sound-si-gls/math.mjs';
import {BOUNDS, NSTATES, K_IDS, isBoundary, le32, rdle, sha, toFp} from '../sound-si-gls/protocol.mjs';

export {BOUNDS, NSTATES, K_IDS, isBoundary, le32, rdle, sha, toFp};

// Degree-6 chart bookkeeping.  The native verifier owns this copy so the
// historical single-input affine protocol retains its sealed resource model.
export const eventDeg = (e, glsBits) => 18 + (DIGITS[e] ? 24 : 0) + 6 * glsBits;
export const chunkDegP = (k, bitsOf) => { let d = 6; for (let e = k ? BOUNDS[k - 1] : 0; e < BOUNDS[k]; e++) d = 2 * d + eventDeg(e, bitsOf(e)); return d; };
const nqOfDegD = (dD) => { const dq = (dD % 2 ? dD : dD - 1) - 12; return (dq + 1) / 2; };
export const NQ_MAX = Math.max(...Array.from({length: NSTATES}, (_, k) => nqOfDegD(chunkDegP(k, () => 8) + 6)), nqOfDegD(76));
export const nqFor = (bitsOf) => Math.max(...Array.from({length: NSTATES}, (_, k) => nqOfDegD(chunkDegP(k, bitsOf) + 6)), nqOfDegD(76));

// ---------------- roles and event ranges ----------------
export const CUTS = [0, 24, 48, 65];
export const NROLES = CUTS.length - 1;
for (const c of CUTS.slice(1)) assert.ok(BOUNDS.includes(c), 'cuts lie at chunk boundaries');
// chunk k covers events [BOUNDS[k-1], BOUNDS[k]); its state S_{k+1} is committed after event BOUNDS[k] - 1
export const chunkStart = (k) => (k ? BOUNDS[k - 1] : 0);
export const ROLES = Array.from({length: NROLES}, (_, i) => {
  const a = CUTS[i], b = CUTS[i + 1];
  const chunks = BOUNDS.map((_, k) => k).filter((k) => BOUNDS[k] > a && BOUNDS[k] <= b);
  assert.equal(chunkStart(chunks[0]), a);
  const bsteps = (e) => (DIGITS[e] ? 2 : 1);
  const records = chunks.map((k) => { let n = 0; for (let e = chunkStart(k); e < BOUNDS[k]; e++) n += bsteps(e); return 32 * n + 192; });
  const terminal = i === NROLES - 1 ? 64 : 0;                       // t_psi, t_{-psi^2}
  const nB = Array.from({length: b - a}, (_, j) => bsteps(a + j)).reduce((x, y) => x + y, 0);
  return {i, a, b, chunks, records, terminal, streamSize: records.reduce((x, y) => x + y, 0) + terminal, nB, nStates: chunks.length};
});
// delta-step index j before each event (88 delta lines: 65 doublings, 21 additions, 2 Frobenius lines)
export const J_AT = (() => { const j = [0]; for (let e = 0; e < NE; e++) j.push(j[e] + (DIGITS[e] ? 2 : 1)); return j; })();
assert.equal(J_AT[NE], NE + NADD);
export const DLAMS = [...VKC.lams, VKC.frob2.lam]; assert.equal(DLAMS.length, 88);
// role i's delta slice: slopes j in [J_AT[a], J_AT[b]) (+ the 2 Frobenius slopes for the last role)
export const DS = ROLES.map(({a, b, i}) => Buffer.concat(DLAMS.slice(J_AT[a], i === NROLES - 1 ? 88 : J_AT[b]).flatMap((l) => [le32(l.c0), le32(l.c1)])));
// the delta recursion state (x_j, c_{j-1}, lambda_{j-1}) before each event (start of every role), from one single
// chain over all 88 lines (the script's recursion: c_j = (lambda_{j-1} + lambda_j) x_j - c_{j-1}, x_{j+1} = lambda_j^2 - x_j - s)
export const DSTATE = (() => {
  const d = VKC.deltaAff; let x = d.x, c = d.y, l = F2.ZERO, j = 0; const out = [];
  const step = (s) => { const cj = F2.sub(F2.mul(F2.add(l, DLAMS[j]), x), c); const nx = F2.sub(F2.sub(F2.sqr(DLAMS[j]), x), s); c = cj; l = DLAMS[j]; x = nx; j++; };
  for (let e = 0; e < NE; e++) { out.push({x, c, l, j}); step(x); if (DIGITS[e]) step(d.x); }
  out.push({x, c, l, j}); return out;
})();
// per-role schedule: digits of events a+1..b-1 then a dummy byte (the first digit is pushed separately), and an
// explicit boundary flag per event; asserted against the single-input schedule
export const SCHEDULE = ROLES.map(({a, b}) => {
  const sch = Buffer.from(DIGITS.slice(a + 1, b).map((d) => (d < 0 ? 0x81 : d)).concat([0]));
  const bnd = Buffer.from(Array.from({length: b - a}, (_, j) => (isBoundary(a + j) ? 1 : 0)));
  return {d0: DIGITS[a], sch, bnd};
});
SCHEDULE.forEach(({sch, bnd, d0}, i) => { const {a, b} = ROLES[i]; assert.equal(bnd.at(-1), 1); assert.equal(sch.length, b - a);
  assert.deepEqual([d0, ...[...sch.subarray(0, -1)].map((x) => (x === 0x81 ? -1 : x))], DIGITS.slice(a, b)); assert.equal(bnd.reduce((x, y) => x + y, 0), ROLES[i].nStates); });

// ---------------- witness items and the transcript ----------------
export const VK_DIGEST = sha(...[VK.alpha.x, VK.alpha.y, ...[VK.beta, VK.gamma, VK.delta].flatMap((q) => [q.x.c0, q.x.c1, q.y.c0, q.y.c1]), ...VK.ic.flatMap((q) => [q.x, q.y])].map((v) => le32(BigInt(v))));
export const TAG = Buffer.concat([Buffer.from('BNMX3/DEGREE6-EVAL1'), VK_DIGEST]);
export const STMT_SIZE = 674, D_SIZE = 96, HAND_SIZE = 224, F_MAX = 10000, NQ_MIN = 1;
export const STMT_LAYOUT = {n0: 256, n1: 288, N0: 320, N1: 385, tau: 450, sc: 482};
export const pushLen = (n) => encodeDataPush(new Uint8Array(n)).length; // minimal push of n bytes (n = 0: OP_0)
export const hdrOf = (n) => Buffer.from(encodeDataPush(new Uint8Array(n)).subarray(0, pushLen(n) - n));

// ---------------- the native B walk and factor schedule (polynomials, shared by prover and mirror) ----------------
const N2 = (a) => mod(a.c0 * a.c0 + a.c1 * a.c1);
// doubling at T = (x, y): t = 1 / (2 N(y)), lambda = 3 x^2 conj(y) t; addition of Q: t = 1 / N(x - xQ), lambda = (y - yQ) conj(x - xQ) t
export const affDbl = (T) => { const t = Fp.inv(mod(2n * N2(T.y))); const lam = F2.div(F2.mul(f2(3n, 0n), F2.sqr(T.x)), F2.add(T.y, T.y));
  const x = F2.sub(F2.sqr(lam), F2.add(T.x, T.x)); const c = F2.sub(F2.mul(lam, T.x), T.y); return {t, lam, c, T: {x, y: F2.sub(c, F2.mul(lam, x))}}; };
export const affAdd = (T, Q) => { assert.ok(!F2.eql(T.x, Q.x), 'exceptional addition'); const t = Fp.inv(N2(F2.sub(T.x, Q.x)));
  const lam = F2.div(F2.sub(T.y, Q.y), F2.sub(T.x, Q.x)); const x = F2.sub(F2.sub(F2.sqr(lam), T.x), Q.x); const c = F2.sub(F2.mul(lam, T.x), T.y);
  return {t, lam, c, T: {x, y: F2.sub(c, F2.mul(lam, x))}}; };
// st = {xA, yA, xB, yB, xC, yC, N}; events[e] = {fs (polys, no c factor), cSign, ts (inverse norms), T (after the event)}
export function factorSchedule(st) {
  const {xA, yA, xB, yB, xC, yC, N} = st; const yP0 = mod(-yA);
  let T = {x: xB, y: yB}; const Bq = {x: xB, y: yB}, Bneg = {x: xB, y: F2.neg(yB)};
  let dx = VKC.deltaStart.x, dc = VKC.deltaStart.c, j = 0; const dAff = VKC.deltaAff; // dc = c_j of the current line j
  const dline = () => linePoly(xC, yC, F2.ONE, F2.neg(DLAMS[j]), dc);
  const dstep = (isAdd) => { const s = isAdd ? dAff.x : dx; const nx = F2.sub(F2.sub(F2.sqr(DLAMS[j]), dx), s); dc = F2.sub(F2.mul(F2.add(DLAMS[j], DLAMS[j + 1]), nx), dc); dx = nx; j++; };
  const bline = (o) => linePoly(xA, yP0, F2.ONE, F2.neg(o.lam), o.c);
  const tbl = (k, n) => { let poly = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) poly = pmul(poly, glsFactorPoly(k, i)); return poly; };
  const events = [];
  for (let e = 0; e < NE; e++) {
    { const ds = DSTATE[e]; assert.ok(j === ds.j && F2.eql(dx, ds.x) && F2.eql(dc, F2.sub(F2.mul(F2.add(ds.l, DLAMS[j]), ds.x), ds.c)), 'delta state'); }
    const fs = [], ts = [];
    let o = affDbl(T); fs.push(bline(o)); ts.push(o.t); T = o.T;
    fs.push(dline()); dstep(false);
    if (DIGITS[e]) { o = affAdd(T, DIGITS[e] < 0 ? Bneg : Bq); fs.push(bline(o)); ts.push(o.t); T = o.T; fs.push(dline()); dstep(true); }
    fs.push(tbl(0, N[0][e]), tbl(1, N[1][e]));
    events.push({fs, cSign: DIGITS[e], ts, T});
  }
  assert.equal(j, NE + NADD);
  // terminal: T + psi(B), T + (-psi^2(B)); delta Frobenius lines; Rconst
  const [p1x, p1y] = psiK(1, xB, yB), [p2x, p2y] = psiK(2, xB, yB), [p3x, p3y] = psiK(3, xB, yB);
  const term = [], tts = [];
  let o = affAdd(T, {x: p1x, y: p1y}); term.push(bline(o)); tts.push(o.t); T = o.T;
  o = affAdd(T, {x: p2x, y: F2.neg(p2y)}); term.push(bline(o)); tts.push(o.t); T = o.T;
  term.push(dline());
  term.push(linePoly(xC, yC, F2.ONE, F2.neg(VKC.frob2.lam), VKC.frob2.c));
  term.push(VKC.Rconst);
  const endpoint = F2.eql(T.x, p3x) && F2.eql(T.y, F2.neg(p3y));
  return {events, term, tts, endpoint, Tend: T};
}

// ---------------- prover ----------------
// The core witness (independent of the fillers): statement, streams, digests, quotient. Every identity is checked
// exactly (divisibility by M) before the challenge is derived.
export function proveCore({proof, publicInputs}, {es: esOverride} = {}) {
  const A = g1(proof.a), B = g2(proof.b), C = g1(proof.c);
  A.assertValidity(); B.assertValidity(); C.assertValidity();
  const ns = publicInputs.map(BigInt); ns.forEach((n) => assert.ok(n >= 0n && n < r));
  const es = esOverride ?? ns.map((n) => glsDecompose(n));
  es.forEach((e, k) => { assert.equal(mod(e.reduce((s, v, i) => s + v * PI[i], 0n), r), ns[k]); e.forEach((v) => assert.ok(v >= -GLS_OFFSET && v < GLS_OFFSET, 'sub-scalar range')); });
  const us = es.map((e) => e.map((v) => v + GLS_OFFSET));
  const N = us.map((u) => Array.from({length: NE}, (_, ev) => u.reduce((s, v, i) => s | (Number((v >> BigInt(GLS_BITS - 1 - ev)) & 1n) << i), 0)));
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const st = {xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y, N};
  const sched = factorSchedule(st);
  assert.ok(sched.endpoint, 'B endpoint');
  let raw = F12.ONE;
  for (const ev of sched.events) { raw = F12.sqr(raw); for (const f of ev.fs) raw = F12.mul(raw, fromPoly(f)); }
  for (const f of sched.term) raw = F12.mul(raw, fromPoly(f));
  assert.ok(F12.eql(F12.finalExponentiate(raw), F12.ONE), 'Groth16 equation fails');
  // Keep six c1..c6 words plus the shared tau as the sole serialized chart
  // owner. Every verifier polynomial reconstructs c0 and the full class.
  const {root: rootWords, states: stateWords, c, tau} = degree6Witnesses(raw, sched.events, BOUNDS);
  assert.equal(stateWords.length, NSTATES);
  const Sc = degree6Poly(rootWords, tau);
  const states = stateWords.map((words) => degree6Poly(words, tau));
  const cPoly = (sign) => (sign > 0 ? pneg(Sc) : Sc);
  const Sp = [pneg(Sc), ...states]; const ids = [];
  for (let k = 0; k < NSTATES; k++) {
    let P = Sp[k];
    for (let e = chunkStart(k); e < BOUNDS[k]; e++) { P = pmul(P, P); for (const f of sched.events[e].fs) P = pmul(P, f); if (sched.events[e].cSign) P = pmul(P, cPoly(sched.events[e].cSign)); }
    ids.push({P, W: Sp[k + 1]});
  }
  let Pfin = Sp[NSTATES]; for (const f of sched.term) Pfin = pmul(Pfin, f); Pfin = pmul(Pfin, psubst(Sc, ETA));
  const Fr1 = frob1Degree6(rootWords, tau); ids.push({P: Pfin, W: pmul(Fr1, psubst(Fr1, ETA))});
  for (const id of ids) {
    const Nn = pmul(id.P, pneg(id.W)); const D = psub(Nn, pneg(Nn)); const {q, r: rem} = pdivM(D);
    assert.ok(rem.every((x) => x === 0n), 'identity not divisible by M'); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'quotient not odd');
    id.Q = q;
  }
  // statement and streams
  const W = (x) => le32(mod(x));
  const STMT = Buffer.concat([...[Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y, ns[0], ns[1]].map((x) => le32(x)),
    Buffer.from(N[0]), Buffer.from(N[1]), W(tau), ...rootWords.map(W)]);
  assert.equal(STMT.length, STMT_SIZE);
  const S = ROLES.map(({a, chunks, i}) => {
    const out = [];
    for (const k of chunks) { for (let e = chunkStart(k); e < BOUNDS[k]; e++) out.push(...sched.events[e].ts.map(W)); out.push(...stateWords[k].map(W)); }
    if (i === NROLES - 1) out.push(...sched.tts.map(W));
    const buf = Buffer.concat(out); assert.equal(buf.length, ROLES[i].streamSize); return buf;
  });
  const D = Buffer.concat([sha(S[0]), sha(S[1]), sha(STMT, S[2])]); // d_i covers the committed items hosted in input i
  const h0 = sha(TAG, D), rhoRaw = sha(h0, Buffer.from('rho')), rho = toFp(rhoRaw);
  const bitsOf = (e) => [0, 1].reduce((s, k) => s + [0, 1, 2, 3].filter((i) => (N[k][e] >> i) & 1).length, 0);
  const nq = nqFor(bitsOf);
  const Qagg = Array(2 * nq).fill(0n);
  ids.forEach((id, k) => { const wgt = mod(rho ** BigInt(K_IDS - 1 - k)); id.Q.forEach((x, i) => { if (x) { assert.ok(i < 2 * nq, 'Q exceeds structural bound'); Qagg[i] = mod(Qagg[i] + wgt * x); } }); });
  const qOdd = Qagg.filter((_, i) => i % 2 === 1);
  assert.equal(qOdd.length, nq); assert.ok(nq <= NQ_MAX);
  while (qOdd.length > 1 && qOdd.at(-1) === 0n) qOdd.pop();
  assert.ok(qOdd.length === 1 || qOdd.at(-1) !== 0n);
  const WQ = Buffer.concat(qOdd.slice().reverse().map(W));
  return {STMT, S, D, WQ, nq: qOdd.length, es, ns, N, Sc, states, root: rootWords, stateWords, c, tau, rho, rhoRaw, h0, st, sched};
}

// ---------------- value-level mirror of the on-chain loop (per role, chained by the handovers) ----------------
const PhiAt = (a, t) => mod(a.c0 + a.c1 * t);
// evaluate events [a, b) from a start state; returns the state after event b - 1 (and after its boundary)
export function runRange(core, z, a, b, start) {
  const {st, Sc, states, sched, rho, tau} = core; const zm = mod(-z);
  let {Fp: Fp_, Fm: Fm_, R} = start; let k = BOUNDS.indexOf(a) + 1; if (a === 0) k = 0;
  const scP = Sc;
  for (let e = a; e < b; e++) {
    const ev = sched.events[e];
    Fp_ = mod(Fp_ * Fp_); Fm_ = mod(Fm_ * Fm_);
    for (const f of ev.fs) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
    if (ev.cSign) { const cp = ev.cSign > 0 ? pneg(scP) : scP; Fp_ = mod(Fp_ * peval(cp, z)); Fm_ = mod(Fm_ * peval(cp, zm)); }
    if (isBoundary(e)) { const Wn = states[k]; const Wp = peval(Wn, z), Wm = peval(Wn, zm); R = mod(R * rho + Fp_ * Wm - Fm_ * Wp); Fp_ = Wp; Fm_ = Wm; k++; }
  }
  const T = sched.events[b - 1].T;
  return {T, Fp: Fp_, Fm: Fm_, R};
}
export const startState = (core, z) => { const scP = core.Sc; return {Fp: peval(pneg(scP), z), Fm: peval(pneg(scP), mod(-z)), R: 0n}; };
export const encodeHand = ({T, Fp: a, Fm: b, R}) => Buffer.concat([T.x.c0, T.x.c1, T.y.c0, T.y.c1, a, b, R].map((v) => le32(mod(v))));
// the terminal and final identity, value level (returns R_final and the quotient check)
export function finish(core, z, s) {
  const {Sc, WQ, root, tau} = core; const zm = mod(-z); const scP = Sc;
  let {Fp: Fp_, Fm: Fm_, R} = s;
  for (const f of [...core.sched.term, psubst(scP, ETA)]) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
  const Fr1 = frob1Degree6(root, tau); const Wp = mod(peval(Fr1, z) * peval(Fr1, mod(ETA * z))), Wm = mod(peval(Fr1, zm) * peval(Fr1, mod(-ETA * z)));
  R = mod(R * core.rho + Fp_ * Wm - Fm_ * Wp);
  let acc = 0n; const z2 = mod(z * z); for (let i = 0; i < WQ.length; i += 32) acc = mod(acc * z2 + rdle(WQ, i));
  return {R, rhs: mod(z * acc * peval(M, z)), ok: R === mod(z * acc * peval(M, z))};
}
// z from the z-tail (the raw bytes of input 2's FILL and WQ pushes)
export const zOf = (core, ZT) => toFp(sha(core.h0, core.rhoRaw, ZT));
export const zTail = (fill2, WQ) => Buffer.concat([Buffer.from(encodeDataPush(new Uint8Array(fill2))), Buffer.from(encodeDataPush(WQ))]);
// handovers for a given z: HAND_i = state after event CUTS[i] - 1, i = 1..NROLES-1
export function handovers(core, z) {
  let s = startState(core, z); const H = [null];
  for (let i = 0; i < NROLES; i++) { s = runRange(core, z, CUTS[i], CUTS[i + 1], s); if (i < NROLES - 1) H.push(encodeHand(s)); }
  const fin = finish(core, z, s); assert.ok(fin.ok, 'value-level final identity');
  return {H, final: s};
}
