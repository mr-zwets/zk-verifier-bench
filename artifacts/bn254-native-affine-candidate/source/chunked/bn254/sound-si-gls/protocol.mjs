// SI-GLS protocol: witness layout, transcript, the honest prover, and a value-level reference
// verifier that mirrors the script step by step (used to test the protocol and to debug the script).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {bn254} from '@noble/curves/bn254.js';
import {p, r, mod, inv, F2, F12, Fp6, f2, g1, g2, BN_X, DIGITS, NE, NADD, PI, GLS_BITS, GLS_OFFSET, PI_SUM_OFFSET, glsDecompose, glsFactorPoly,
  VKC, B_TWIST, B3, psiK, ETA, FROB, frob1Affine, affinePoly, affineWitnesses, linePoly, Phi, fromPoly, toPoly, pmul, padd, psub, pneg, psubst, peval, pdivM, M, VK} from './math.mjs';

// ---------------- fixed layout ----------------
export const TAG = Buffer.from('SIGLS/AFFINE1');
export const CHUNK = 2;                                   // events per chunk
export const BOUNDS = (() => { const b = []; for (let e = CHUNK; e < NE; e += CHUNK) b.push(e); b.push(NE); return b; })(); // state k+1 after BOUNDS[k] events
export const NSTATES = BOUNDS.length;                     // 33
export const K_IDS = NSTATES + 1;                         // 33 chunk identities + terminal
export const isBoundary = (e) => BOUNDS.includes(e + 1);  // a state is committed after event e
export const WS_LAYOUT = {stmt: 0, n0: 256, n1: 288, N0: 320, N1: 385, sc: 450, states: 642};
export const WS_SIZE = 642 + NSTATES * 192;               // 6978
// ---------------- degree bookkeeping (structural, adversarial) ----------------
// per event: B/delta lines contribute 18; an addition also carries the affine
// c factor (degree 11); GLS contributes 6 per selected bit (<= 8).
export const eventDeg = (e, glsBits) => 18 + (DIGITS[e] ? 29 : 0) + 6 * glsBits;
export const chunkDegP = (k, bitsOf) => { let d = 11; for (let e = k ? BOUNDS[k - 1] : 0; e < BOUNDS[k]; e++) d = 2 * d + eventDeg(e, bitsOf(e)); return d; };
// D = P(X)S'(-X) - P(-X)S'(X) is odd: deg D <= largest odd <= deg P + 11; Q = D/M odd, n_q odd words
const nqOfDegD = (dD) => { const dq = (dD % 2 ? dD : dD - 1) - 12; return (dq + 1) / 2; };
export const NQ_MAX = Math.max(...Array.from({length: NSTATES}, (_, k) => nqOfDegD(chunkDegP(k, () => 8) + 11)), nqOfDegD(86));
export const nqFor = (bitsOf) => Math.max(...Array.from({length: NSTATES}, (_, k) => nqOfDegD(chunkDegP(k, bitsOf) + 11)), nqOfDegD(86));

// ---------------- encodings ----------------
export const le32 = (x) => { assert.ok(x >= 0n && x < 1n << 256n); const b = Buffer.alloc(32); let v = x; for (let i = 0; i < 32; i++) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
export const rdle = (b, o = 0, n = 32) => { let v = 0n; for (let i = n - 1; i >= 0; i--) v = v * 256n + BigInt(b[o + i]); return v; };
export const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
export const toFp = (h) => rdle(h) % p;                  // unsigned LE (BIN2NUM(h || 0x00)) mod p

// ---------------- on-chain B formulas (homogeneous projective over Fp2) ----------------
// doubling (scaled CLN): B=Y^2, C=Z^2, E=3b'C, F=3E, H=2YZ; X3=2XY(B-F), Y3=(B+F)^2-12E^2, Z3=4BH
// line (H, -3X^2, B-E) = 2YZ * (affine tangent line); Z3 = 8Y^3 Z (Z = 0 absorbing; Z3 != 0 => H != 0)
export const projDbl = ([X, Y, Z]) => {
  const B = F2.sqr(Y), C = F2.sqr(Z), E = F2.mul(B3, C), Fv = F2.mul(E, f2(3n, 0n)), H = F2.mul(F2.mul(Y, Z), f2(2n, 0n));
  const X3 = F2.mul(F2.mul(F2.mul(X, Y), f2(2n, 0n)), F2.sub(B, Fv));
  const Y3 = F2.sub(F2.sqr(F2.add(B, Fv)), F2.mul(F2.sqr(E), f2(12n, 0n)));
  const Z3 = F2.mul(F2.mul(B, H), f2(4n, 0n));
  return {T: [X3, Y3, Z3], line: [H, F2.neg(F2.mul(F2.sqr(X), f2(3n, 0n))), F2.sub(B, E)]};
};
// mixed addition with affine Q: theta=Y-yq Z, lam=X-xq Z, D=lam^2, E=lam D, Fv=Z theta^2, G=X D, H=E+Fv-2G;
// X3=lam H, Y3=theta(G-H)-Y E, Z3=Z E; line (lam, -theta, theta xq - lam yq) = lam * (affine chord line); Z3 = Z lam^3
export const projAdd = ([X, Y, Z], [xq, yq]) => {
  const th = F2.sub(Y, F2.mul(yq, Z)), la = F2.sub(X, F2.mul(xq, Z));
  const D = F2.sqr(la), E = F2.mul(la, D), Fv = F2.mul(Z, F2.sqr(th)), G = F2.mul(X, D), H = F2.sub(F2.add(E, Fv), F2.add(G, G));
  return {T: [F2.mul(la, H), F2.sub(F2.mul(th, F2.sub(G, H)), F2.mul(Y, E)), F2.mul(Z, E)],
    line: [la, F2.neg(th), F2.sub(F2.mul(th, xq), F2.mul(la, yq))]};
};

// ---------------- the event schedule as polynomials (shared by prover and tests) ----------------
// statement -> list of per-event factor polynomials (without the c factor) and terminal factors
export function factorSchedule(st) {
  const {xA, yA, xB, yB, xC, yC, N} = st; // N[k][e] nibble (bit i = bit 64-e of u_{k,i})
  const yP0 = mod(-yA);
  let T = [xB, yB, F2.ONE]; const Bq = [xB, yB], Bneg = [xB, F2.neg(yB)];
  // delta state
  let dx = VKC.deltaStart.x, dc = VKC.deltaStart.c; let j = 0; const lam = VKC.lams; const dAff = VKC.deltaAff;
  const dline = () => linePoly(xC, yC, F2.ONE, F2.neg(lam[j]), dc);
  const dstep = (isAdd) => { // x_{j+1} = lam_j^2 - x_j - s, c_{j+1} = (lam_j + lam_{j+1}) x_{j+1} - c_j
    const s = isAdd ? dAff.x : dx; const nx = F2.sub(F2.sub(F2.sqr(lam[j]), dx), s);
    dc = F2.sub(F2.mul(F2.add(lam[j], lam[j + 1]), nx), dc); dx = nx; j++;
  };
  const tbl = (k, n) => { let poly = [1n]; for (let i = 0; i < 4; i++) if ((n >> i) & 1) poly = pmul(poly, glsFactorPoly(k, i)); return poly; };
  const events = [];
  for (let e = 0; e < NE; e++) {
    const fs = [];
    let o = projDbl(T); fs.push(linePoly(xA, yP0, ...o.line)); T = o.T;
    fs.push(dline()); dstep(false);
    if (DIGITS[e]) {
      o = projAdd(T, DIGITS[e] < 0 ? Bneg : Bq); fs.push(linePoly(xA, yP0, ...o.line)); T = o.T;
      fs.push(dline()); dstep(true);
    }
    fs.push(tbl(0, N[0][e]), tbl(1, N[1][e]));
    events.push({fs, cSign: DIGITS[e]});
  }
  assert.equal(j, NE + NADD);
  // terminal: B + psi(B), + (-psi^2(B)); delta Frobenius lines (tracked line 1, baked line 2)
  const [p1x, p1y] = psiK(1, xB, yB), [p2x, p2y] = psiK(2, xB, yB), [p3x, p3y] = psiK(3, xB, yB);
  const term = [];
  let o = projAdd(T, [p1x, p1y]); term.push(linePoly(xA, yP0, ...o.line)); T = o.T;
  o = projAdd(T, [p2x, F2.neg(p2y)]); term.push(linePoly(xA, yP0, ...o.line)); T = o.T;
  term.push(dline());
  term.push(linePoly(xC, yC, F2.ONE, F2.neg(VKC.frob2.lam), VKC.frob2.c));
  term.push(VKC.Rconst);
  // endpoint: T == -psi^3(B) projectively, Z_T != 0
  const [X, Y, Z] = T;
  const endpoint = !F2.is0(Z) && F2.eql(X, F2.mul(p3x, Z)) && F2.eql(Y, F2.mul(F2.neg(p3y), Z));
  return {events, term, endpoint, Tend: T};
}

// ---------------- prover ----------------
const bitsOfE = (e) => (e < 0n ? -e : e);
// forge: build the most consistent witness possible for a statement that may be FALSE (red-team only):
// the Groth16, endpoint and divisibility assertions are skipped and the quotients are floor quotients.
export function prove({proof, publicInputs}, {es: esOverride, forge = false, rhoSigned = false} = {}) {
  const A = g1(proof.a), B = g2(proof.b), C = g1(proof.c);
  if (!forge) { A.assertValidity(); B.assertValidity(); C.assertValidity(); }
  const ns = publicInputs.map(BigInt); if (!forge) ns.forEach((n) => assert.ok(n >= 0n && n < r));
  const es = esOverride ?? ns.map((n) => glsDecompose(mod(n, r)));
  es.forEach((e, k) => { if (!forge) assert.equal(mod(e.reduce((s, v, i) => s + v * PI[i], 0n), r), ns[k]); e.forEach((v) => assert.ok(v >= -GLS_OFFSET && v < GLS_OFFSET, 'sub-scalar range')); });
  const us = es.map((e) => e.map((v) => v + GLS_OFFSET)); // offset encoding, u in [0, 2^65)
  const N = us.map((u) => Array.from({length: NE}, (_, ev) => u.reduce((s, v, i) => s | (Number((v >> BigInt(GLS_BITS - 1 - ev)) & 1n) << i), 0)));
  const Aa = A.toAffine(), Ba = B.toAffine(), Ca = C.toAffine();
  const st = {xA: Aa.x, yA: Aa.y, xB: Ba.x, yB: Ba.y, xC: Ca.x, yC: Ca.y, N};
  const sched = factorSchedule(st);
  if (!forge) assert.ok(sched.endpoint, 'B endpoint');
  // raw Miller product (no c): must have FE = 1 (valid Groth16 proof)
  let raw = F12.ONE;
  for (const ev of sched.events) { raw = F12.sqr(raw); for (const f of ev.fs) raw = F12.mul(raw, fromPoly(f)); }
  for (const f of sched.term) raw = F12.mul(raw, fromPoly(f));
  if (!forge) assert.ok(F12.eql(F12.finalExponentiate(raw), F12.ONE), 'Groth16 equation fails');
  // The affine chart owns the serialized six words.  Build every verifier
  // polynomial from those words; the six words are not a monic prefix.
  const {root: rootWords, states: stateWords, c} = affineWitnesses(raw, sched.events, BOUNDS);
  assert.equal(stateWords.length, NSTATES);
  const Sc = affinePoly(rootWords);
  const states = stateWords.map((words) => affinePoly(words));
  const cPoly = (sign) => (sign > 0 ? pneg(Sc) : Sc); // d = +1: c^-1; d = -1: c
  // identities
  const Sp = [pneg(Sc), ...states]; const ids = [];
  for (let k = 0; k < NSTATES; k++) {
    let P = Sp[k];
    for (let e = k ? BOUNDS[k - 1] : 0; e < BOUNDS[k]; e++) { P = pmul(P, P); for (const f of sched.events[e].fs) P = pmul(P, f); if (sched.events[e].cSign) P = pmul(P, cPoly(sched.events[e].cSign)); }
    ids.push({P, W: Sp[k + 1]});
  }
  let Pfin = Sp[NSTATES]; for (const f of sched.term) Pfin = pmul(Pfin, f); Pfin = pmul(Pfin, psubst(Sc, ETA));
  const Fr1 = frob1Affine(rootWords); ids.push({P: Pfin, W: pmul(Fr1, psubst(Fr1, ETA))});
  for (const id of ids) {
    const Nn = pmul(id.P, pneg(id.W)); const D = psub(Nn, pneg(Nn)); const {q, r: rem} = pdivM(D);
    if (!forge) { assert.ok(rem.every((x) => x === 0n), 'identity not divisible by M'); assert.ok(q.every((x, i) => i % 2 === 1 || x === 0n), 'quotient not odd'); }
    id.Q = q;
  }
  // transcript part 1
  const W = (x) => le32(mod(x));
  const stmt = Buffer.concat([Aa.x, Aa.y, Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Ca.x, Ca.y, ns[0], ns[1]].map((x) => le32(mod(x, 1n << 256n))));
  const nib = N.map((Nk) => Buffer.from(Nk));
  const WS = Buffer.concat([stmt, nib[0], nib[1], ...rootWords.map(W), ...stateWords.flatMap((s) => s.map(W))]);
  assert.equal(WS.length, WS_SIZE);
  const h0 = sha(TAG, WS), rhoRaw = sha(h0, Buffer.from('rho'));
  const rho = rhoSigned ? mod(((v) => (v >> 255n ? -(v - (1n << 255n)) : v))(rdle(rhoRaw))) : toFp(rhoRaw); // rhoSigned: a WRONG (signed) conversion, red-team only
  const bitsOf = (e) => [0, 1].reduce((s, k) => s + [0, 1, 2, 3].filter((i) => (N[k][e] >> i) & 1).length, 0);
  const nq = nqFor(bitsOf);
  const Qagg = Array(2 * nq).fill(0n);
  ids.forEach((id, k) => { const wgt = mod(rho ** BigInt(K_IDS - 1 - k)); id.Q.forEach((x, i) => { if (x) { assert.ok(i < 2 * nq, 'Q exceeds structural bound'); Qagg[i] = mod(Qagg[i] + wgt * x); } }); });
  const qOdd = Qagg.filter((_, i) => i % 2 === 1);
  assert.equal(qOdd.length, nq); assert.ok(nq <= NQ_MAX);
  while (qOdd.length > 1 && qOdd.at(-1) === 0n) qOdd.pop(); // canonical: leading word nonzero (trims only w.p. ~1/p)
  assert.ok(qOdd.length === 1 || qOdd.at(-1) !== 0n);
  const WQ = Buffer.concat(qOdd.slice().reverse().map(W)); // highest coefficient first
  return {WS, WQ, nq: qOdd.length, es, ns, Sc, states, root: rootWords, stateWords, c, debug: {sched, ids, rho}};
}

// ---------------- value-level reference verifier (mirrors the script) ----------------
const be = (b, o) => rdle(b, o);
export function verifyValues(WS, WQ, {trace} = {}) {
  const fail = (why) => ({ok: false, why});
  if (WS.length !== WS_SIZE) return fail('WS size');
  if (WQ.length % 32 || WQ.length === 0 || WQ.length > 32 * NQ_MAX) return fail('WQ size');
  const word = (o, lim = p) => { const v = be(WS, o); return v < lim ? v : null; };
  const st = Array.from({length: 8}, (_, i) => word(32 * i)); if (st.some((v) => v === null)) return fail('coordinate not canonical');
  const ns = [word(256, r), word(288, r)]; if (ns.some((v) => v === null)) return fail('public input not canonical');
  const [xA, yA, xB0, xB1, yB0, yB1, xC, yC] = st;
  const xB = f2(xB0, xB1), yB = f2(yB0, yB1);
  if (mod(yA * yA - xA ** 3n - 3n) !== 0n || mod(yC * yC - xC ** 3n - 3n) !== 0n) return fail('G1 curve');
  if (!F2.eql(F2.sqr(yB), F2.add(F2.mul(F2.sqr(xB), xB), B_TWIST))) return fail('twist curve');
  const nibs = [0, 1].map((k) => [...WS.subarray(320 + 65 * k, 385 + 65 * k)]); if (nibs.flat().some((b) => b > 15)) return fail('nibble range');
  const words = (o, n) => Array.from({length: n}, (_, i) => word(o + 32 * i));
  const sc = words(450, 6), stts = Array.from({length: NSTATES}, (_, k) => words(642 + 192 * k, 6));
  if ([...sc, ...stts.flat()].some((v) => v === null)) return fail('state word not canonical');
  const scP = affinePoly(sc), statePs = stts.map((words) => affinePoly(words));
  const qw = Array.from({length: WQ.length / 32}, (_, i) => rdle(WQ, 32 * i)); if (qw.some((v) => v >= p)) return fail('Q word not canonical');
  if (qw.length > 1 && qw[0] === 0n) return fail('Q leading word zero');
  const h0 = sha(TAG, WS), rhoRaw = sha(h0, Buffer.from('rho')), rho = toFp(rhoRaw), z = toFp(sha(h0, rhoRaw, WQ));
  // GLS binding (exact integers): acc_k = sum_e 2^(64-e) TB_k[N_k[e]] = sum_i u_{k,i} pi_i,  TB_k[n] = sum_{i in n} pi_i
  for (const k of [0, 1]) {
    let acc = 0n; for (let e = 0; e < NE; e++) { acc = 2n * acc; for (let i = 0; i < 4; i++) if ((nibs[k][e] >> i) & 1) acc += PI[i]; }
    if ((acc - PI_SUM_OFFSET - ns[k]) % r !== 0n) return fail('GLS binding ' + k);
  }
  // evaluations: run the schedule as values at +-z
  const sched = factorSchedule({xA, yA, xB, yB, xC, yC, N: nibs});
  const zm = mod(-z);
  let Fp_ = peval(pneg(scP), z), Fm_ = peval(pneg(scP), zm), R = 0n, k = 0;
  sched.events.forEach((ev, e) => {
    Fp_ = mod(Fp_ * Fp_); Fm_ = mod(Fm_ * Fm_);
    for (const f of ev.fs) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
    if (ev.cSign) { const cp = ev.cSign > 0 ? pneg(scP) : scP; Fp_ = mod(Fp_ * peval(cp, z)); Fm_ = mod(Fm_ * peval(cp, zm)); }
    if (isBoundary(e)) { const Wn = statePs[k]; const Wp = peval(Wn, z), Wm = peval(Wn, zm); R = mod(R * rho + Fp_ * Wm - Fm_ * Wp); Fp_ = Wp; Fm_ = Wm; k++; if (trace) trace({e, R, Fp: Fp_, Fm: Fm_}); }
  });
  if (!sched.endpoint) return fail('B endpoint');
  for (const f of [...sched.term, psubst(scP, ETA)]) { Fp_ = mod(Fp_ * peval(f, z)); Fm_ = mod(Fm_ * peval(f, zm)); }
  const Fr1 = frob1Affine(sc); const Wp = mod(peval(Fr1, z) * peval(Fr1, mod(ETA * z))), Wm = mod(peval(Fr1, zm) * peval(Fr1, mod(-ETA * z)));
  R = mod(R * rho + Fp_ * Wm - Fm_ * Wp);
  let acc = 0n; const z2 = mod(z * z); for (const q of qw) acc = mod(acc * z2 + q);
  const rhs = mod(z * acc * peval(M, z));
  return R === rhs ? {ok: true, z, rho, R} : fail('final identity');
}
