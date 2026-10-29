// Track 6 design: cost model of a CashVM PLONK/KZG verifier for gnark v0.16.4 BN254 proofs (SHA-256 transcript),
// built from our existing BN254 kernels. Pure arithmetic, no VM: kernel unit costs come from kernels.json (VM-measured
// here) and from the measured Groth16 sources (cited inline). Prints per-step costs, the MSM plan search, and the
// three regimes, and writes model-result.json.
//
//   node research/plonk-kzg/model.mjs [nPI=2] [log2n=16]
import {readFileSync, writeFileSync} from 'node:fs';

const NPI = Number(process.argv[2] ?? 2), LOG2N = Number(process.argv[3] ?? 16);
const K = Object.fromEntries(JSON.parse(readFileSync(new URL('./kernels.json', import.meta.url))).kernels.map((k) => [k.name, k]));
const op = (prefix) => { const k = Object.values(K).find((x) => x.name.startsWith(prefix)); if (!k) throw new Error(prefix); return k.opCost; };

// ---------------- unit costs (standard op-cost) ----------------
const U = {
  jdbl: op('G1 Jacobian doubling'), jmadd: op('G1 mixed addition'), jadd: op('G1 full addition'),
  adbl: op('G1 affine doubling'), aadd: op('G1 affine addition'), mm: op('modular multiply ('), mma: op('modular multiply-acc'),
  evDbl: op('KZG event, two fixed-G2 chains + F update (doubling'), evAdd: op('KZG event, two fixed-G2 chains + F update (addition'),
  dstep: op('SI delta step'),
};
const W = 32;                       // one field word / slope witness (bytes)
const INSITU = 1.05;                // loop + stream overhead on a standalone kernel: SI-GLS delta step 4.31M/88 = 49k in situ vs 46.7k here
const FRMM = 5000;                  // one Fr mul-mod in straight-line verifier code incl. stack shuffling (3.7k kernel + ~1.3k)
const ADD_OVH = 1500 + 400 + 3696 / 2; // per MSM addition: table lookup (SPLIT/BIN2NUM) + digit read + beta*x for the phi half (half the adds)
const AFF_GUARD = 600;              // affine witness mode: read the slope word, VERIFY chk == 0 (and ex != 0 for an add)
const sha = (len) => { const it = Math.floor((len + 8) / 64) + 1; return {it, op: 100 + 32 + it * 192 + len /* CATs building the preimage */}; };

// ---------------- 1. statement, transcript, Fr work (gnark verify.go, nbCommitments = 0) ----------------
const PROOF_PTS = 9;                // L, R, O, Z, H0, H1, H2, W_zeta (BatchedProof.H), W_zeta_omega (ZShiftedOpening.H)
const PROOF_FR = 6;                 // l, r, o, s1, s2 (BatchedProof.ClaimedValues[1..5]) and z(omega zeta); ClaimedValues[0] is recomputed on-chain
const proofBytes = PROOF_PTS * 64 + PROOF_FR * W, piBytes = NPI * W;
const decode = (PROOF_PTS * 2 + PROOF_FR + NPI) * 900;                 // REVERSEBYTES, CAT 00, BIN2NUM, < p (or < r) check
const curve = PROOF_PTS * (3 * U.mm + 2500);                            // y^2 == x^3 + 3 (cofactor 1: on-curve = in G1); x,y = 0 (infinity) rejected
const hashes = {
  gamma: sha(5 + 8 * 64 + NPI * 32 + 3 * 64), beta: sha(4 + 32), alpha: sha(5 + 32 + 64), zeta: sha(4 + 32 + 3 * 64),
  v: sha(5 + 32 + 6 * 64 + 6 * 32 + 32),             // kzg.FoldProof's "gamma": zeta, [Lambda],[L],[R],[O],[S1],[S2], 6 claimed values, z(omega zeta)
  u: sha(1 + 32 + 2 * 64),                           // ours (prover-independent): u from v_raw || W_zeta || W_zeta_omega
};
const transcriptOp = Object.values(hashes).reduce((a, h) => a + h.op, 0) + 4 * 3000; // + 5 challenge reductions (REVERSEBYTES, mod r)
// Fr multiplications, counted from verify.go: zeta^n (LOG2N squarings), L1 and PI (one batch inverse for zeta - omega^i, i < NPI),
// constLin (6), _s1 (5), _s2 (7), coeffZ, rl, zeta^(n+2) terms (4), v powers (4), folded evals (5), u terms (3),
// GLV split checks of every MSM scalar (counted in the MSM), plus the Lagrange terms.
const frMuls = LOG2N + 4 + 3 * Math.max(0, NPI - 1) + 1 + 4 * NPI + 6 + 5 + 7 + 2 + 4 + 4 + 5 + 3 + 6;
const frOp = frMuls * FRMM;
const frBytes = W;                  // one witnessed inverse of prod_i (zeta - omega^i), checked by one mul (fixed by an exact equation)

// ---------------- 2. MSM ----------------
// Scalars (gnark): P_left = Lambda + v L + v^2 R + v^3 O + v^4 S1 + v^5 S2 + u Z - (e + u z_w) G1 + zeta W_z + u zeta omega W_zw,
// Lambda = l Ql + r Qr + lr Qm + o Qo + Qk + s1' S3 + coeffZ Z + zh H0 + zh zeta^(n+2) H1 + zh zeta^(2n+4) H2;
// P_right = -(W_z + u W_zw). u = u1 + lambda_GLV u2 with u1, u2 < 2^64 (derived by us, 128 bits of entropy, 64 doublings).
// Lambda must be known in affine form before v (it is hashed into v): plan A computes it in its own chain; plan B witnesses
// Lambda and folds the check Lambda == MSM_lin into P_left with a fresh 128-bit t (one chain).
const PLANS = {
  A: [ // [bits, fixedFullScalars, varFullScalars, var64Halves, fixed64Halves, plainAdds, needsAffineOut]
    {name: 'Lambda', bits: 128, fixed: 5, vfull: 4, v64: 0, f64: 0, plain: 1, affineOut: true},
    {name: 'P_left rest', bits: 128, fixed: 3, vfull: 5, v64: 2, f64: 0, plain: 1, affineOut: false},
    {name: 'P_right', bits: 64, fixed: 0, vfull: 0, v64: 2, f64: 0, plain: 1, affineOut: false},
  ],
  B: [
    {name: 'P_left (t-folded Lambda check)', bits: 128, fixed: 8, vfull: 9, v64: 2, f64: 2, plain: 1, affineOut: false},
    {name: 'P_right', bits: 64, fixed: 0, vfull: 0, v64: 2, f64: 0, plain: 1, affineOut: false},
  ],
};
const varBases = {A: 9 + 0, B: 10};   // distinct variable bases needing an on-chain table: Z,H0,H1,H2,L,R,O,Wz,Wzw (+Lambda in B)
const fixedBases = {A: 8, B: 9};      // Ql,Qr,Qm,Qo,S1,S2,S3,G1 (+Qk in B)

// fA = fraction of the chain's bit positions run in affine-witness mode (the rest Jacobian); the switch costs one witnessed inverse
function chainCost(c, wf, wv, fA) {
  const halvesF = 2 * c.fixed, halvesV = 2 * c.vfull;
  const addsFull = (w) => Math.ceil(c.bits / w);
  const adds = halvesF * addsFull(wf) + halvesV * addsFull(wv) + c.v64 * Math.ceil(64 / wv) + c.f64 * Math.ceil(64 / wf) + c.plain + 1 /* offset correction */;
  const dbl = c.bits;
  const opJ = dbl * U.jdbl + adds * U.jmadd, opA = dbl * (U.adbl + AFF_GUARD) + adds * (U.aadd + AFF_GUARD);
  const bytesA = (dbl + adds) * W;
  let o = (1 - fA) * opJ + fA * opA + adds * ADD_OVH, b = fA * bytesA;
  if (fA > 0 && fA < 1) { o += 6 * U.mm; b += W; }          // Jacobian -> affine switch: witnessed Z^-1, X/Z^2, Y/Z^3
  if (c.affineOut && fA < 1) { o += 6 * U.mm; b += W; }    // Lambda to affine for the v hash
  const digits = halvesF * addsFull(wf) + halvesV * addsFull(wv) + c.v64 * Math.ceil(64 / wv) + c.f64 * Math.ceil(64 / wf);
  return {op: o, bytes: b + digits /* 1 B per signed window digit */, adds, dbl};
}
function msmCost(plan, wf, wv, fA) {
  let o = 0, b = 0; const parts = [];
  for (const c of PLANS[plan]) { const r = chainCost(c, wf, wv, fA); parts.push({chain: c.name, ...r}); o += r.op; b += r.bytes; }
  // tables: fixed bases baked (2^(wf-1) affine multiples, 64 B each; the phi table is beta * x at lookup)
  const tf = fixedBases[plan] * 2 ** (wf - 1) * 64;
  // variable bases: 2^(wv-1) multiples built in affine-witness mode (1 dbl + 2^(wv-1) - 2 adds, each with a 32 B slope)
  const tvOps = varBases[plan] * (2 ** (wv - 1) - 1);
  o += tvOps * (U.aadd + AFF_GUARD); b += tf + tvOps * W;
  // GLV split per full scalar (witnessed k1, k2 of <= 128 bits + sign bytes, checked k1 + lambda k2 == s mod r) and digit Horner rebuild
  const nFull = PLANS[plan].reduce((a, c) => a + c.fixed + c.vfull, 0);
  o += nFull * (2 * FRMM + 4000) + parts.reduce((a, p) => a + p.adds, 0) * 900; b += nFull * 34;
  return {op: o, bytes: b, parts, tableBytesFixed: tf, varTableOps: tvOps, nFull};
}

// ---------------- 3. pairing: SI machinery with two FIXED G2 arguments ([1]_2 at P_left, [x]_2 at P_right) ----------------
// 65 NAF events (21 additions) + 2 Frobenius lines per chain = 88 chain steps per chain, both chains share the F+- update.
// Degrees (as SI-GLS): a state is monic of degree 6; event factors are two lines (deg 9 each) = 18, plus on an addition
// event two addition lines and S_c (deg 6) = 42; a fixed base folded into GT by GT-GLS adds up to 4 monic R factors = 24.
// A chunk [a, a+L): deg P = 6 * 2^L + sum_e 2^(a+L-1-e) d_e; deg D = deg P + 6 (odd, so <= deg P + 5); NQ = (deg P - 6) / 2.
const BN_X = 4965661367192848881n;
const naf = (n) => { const d = []; while (n > 0n) { if (n & 1n) { const z = 2n - (n % 4n); d.push(Number(z)); n -= z; } else d.push(0); n >>= 1n; } return d.reverse(); };
const NAF = naf(6n * BN_X + 2n).slice(1);    // events after the leading 1: SI-GLS's d_0..d_64 schedule
if (NAF.length !== 65 || NAF.filter((x) => x).length !== 21) throw new Error('NAF schedule ' + NAF.length);
function chunking(L, mFold) {
  let maxDeg = 0, states = 0;
  for (let a = 0; a < 65; a += L) {
    const b = Math.min(65, a + L); let deg = 6 * 2 ** (b - a);
    for (let e = a; e < b; e++) deg += 2 ** (b - 1 - e) * (18 + (NAF[e] ? 24 : 0) + 24 * mFold);
    maxDeg = Math.max(maxDeg, deg); states++;
  }
  return {L, states, maxDeg, nq: (maxDeg - 6) / 2};
}
const GTGLS = {perBaseEvent: 1.32e6 / 2 / 65, perBaseTables: 0.358e6 / 2, perBaseBinding: 20000, perBaseBytes: 2 * 6 * W + 65}; // SI-GLS profile (2 bases)
function pairingCost(mFold, L) {
  const c = chunking(L, mFold);
  const ops = {
    events: 65 * U.evDbl * INSITU + 23 * U.evAdd * INSITU,    // 21 NAF additions + 2 Frobenius steps run the addition-shaped event
    boundaries: c.states * 46700,                             // SI-GLS profile: state boundaries 1.54M / 33
    quotient: c.nq * 6470,                                    // SI-GLS profile: 6.47k per quotient word (Horner)
    setup: 300000,                                            // z powers, c_j = Phi(gamma1^j)(z), S_c(+-z), S_c(+-eta z), Jacobian line env (Y, XZ, Z^3)
    terminal: 350000,                                         // Fr1 = Frob(S_c), W(+-z), final identity R == z q(z^2) M(z); no endpoint check (G2 fixed)
    siTranscript: sha(32 + 6 * W + c.states * 192).op + sha(40).op + sha(64 + c.nq * W).op,
    gtgls: mFold * (65 * GTGLS.perBaseEvent + GTGLS.perBaseTables + GTGLS.perBaseBinding),
  };
  const bytes = {slopes: 2 * 88 * 64, states: c.states * 192, residueRoot: 6 * W, quotient: c.nq * W, siConsts: 10 * W, gtgls: mFold * GTGLS.perBaseBytes};
  return {chunking: c, ops, op: Object.values(ops).reduce((a, b) => a + b, 0), bytesBy: bytes, bytes: Object.values(bytes).reduce((a, b) => a + b, 0)};
}
const pairing0 = pairingCost(0, 2);

// ---------------- 4. constants and code ----------------
const vkBytes = 8 * 64 /* S1,S2,S3,Ql,Qr,Qm,Qo,Qk raw (hashed into gamma as is) */ + 5 * W /* n^-1, omega, coset shift k1, k1^2, omega^NPI.. */;
const CODE = 6000;                  // estimate: KZG event kernels 0.75k, G1 kernels 0.2-0.3k, Straus loop 0.4k, transcript + Fr 1.5k, SI setup/terminal 1.5k, dispatch/layout 1.4k

// mFold fixed bases of plan B moved from the G1 MSM into GT (GT-GLS against [1]_2): Qk first, then the full-scalar ones
function total(plan, wf, wv, fA, mFold = 0, L = 2) {
  if (mFold && plan !== 'B') throw new Error('GT folding needs plan B (Lambda witnessed)');
  const saved = PLANS.B; if (mFold) PLANS.B = PLANS.B.map((c) => c.fixed === 8 ? {...c, f64: 0, fixed: 8 - Math.max(0, mFold - 1)} : c);
  const savedFB = fixedBases.B; if (mFold) fixedBases.B = 9 - mFold;
  const m = msmCost(plan, wf, wv, fA); PLANS.B = saved; fixedBases.B = savedFB;
  const pr = pairingCost(mFold, L);
  const opAll = decode + curve + transcriptOp + frOp + m.op + pr.op;
  const bytes = proofBytes + piBytes + frBytes + m.bytes + pr.bytes + vkBytes + CODE;
  return {plan, wf, wv, fA, mFold, L, op: opAll, bytes, msm: m, pairing: pr};
}

// ---------------- regimes ----------------
const TX1 = 63, LOCK = 35;          // single-input tx overhead and P2SH32 locking, as the bench scores SI-GLS (21,852 + 63)
function regimeSpec(t) { const L = Math.max(t.bytes + 70, Math.ceil(t.op / 800 - 10000)); return {unlocking: L, score: L + LOCK + TX1, pad: L - t.bytes - 70, bchnOp: t.op + CODE}; }
function regime100k(t) { const L = Math.max(t.bytes + 70, Math.ceil(t.op / 800 - 41)); return {unlocking: L, score: L + LOCK + TX1, pad: L - t.bytes - 70, fits: L + LOCK + TX1 <= 100000, bchnOp: t.op + CODE}; }
// today: k inputs, each unlocking <= 9,900 B (margin), budget (41 + L_i) 800; per input: 57 B redeem + push headers (~70 B),
// 0.5M setup (library load by SHA256, layout/graph pins, own digest, challenge recompute), 128 B handover; tx: 22 + k (35 + 43)
function regimeToday(t) {
  for (let k = 1; k < 40; k++) {
    const content = t.bytes + k * 70 + (k - 1) * 128;
    const op = t.op + k * 500000 + (k - 1) * 20000;
    const L = Math.max(content, Math.ceil(op / 800 - 41 * k));
    if (L <= k * 9900) return {inputs: k, unlocking: L, score: L + 22 + k * (LOCK + 43), pad: L - content, opWithSetup: op, bchnOp: op + k * CODE};
  }
}

const best = {}; const rows = [];
const SPACE = [];
for (const plan of ['A', 'B']) for (const wf of [3, 4, 5, 6, 7]) for (const wv of [3, 4, 5, 6]) for (let i = 0; i <= 10; i++) SPACE.push([plan, wf, wv, i / 10, 0, 2]);
for (const mFold of [1, 3, 5, 7, 9]) for (const L of [1, 2]) for (const wv of [3, 4, 5, 6]) for (let i = 0; i <= 10; i++) SPACE.push(['B', 4, wv, i / 10, mFold, L]);
const bestBy = {}; // best per (gt folding on/off) and regime
for (const args of SPACE) {
  const t = total(...args);
  const r = {spec: regimeSpec(t), k100: regime100k(t), today: regimeToday(t)};
  rows.push({t, r});
  for (const g of ['spec', 'k100', 'today']) {
    if (!best[g] || r[g].score < best[g].r[g].score) best[g] = {t, r};
    const key = g + (t.mFold ? '/gtfold' : '/g1only');
    if (!bestBy[key] || r[g].score < bestBy[key].r[g].score) bestBy[key] = {t, r};
  }
}
const pureJ = total('A', 4, 4, 0), pureA = total('A', 4, 4, 1);
const fmt = (x) => (x / 1e6).toFixed(2) + 'M';
console.log('units (standard op):', U);
console.log(`statement decode ${fmt(decode)}, curve checks ${fmt(curve)}, transcript ${fmt(transcriptOp)} (${Object.values(hashes).reduce((a, h) => a + h.it, 0)} SHA-256 blocks), Fr ${fmt(frOp)} (${frMuls} mul-mods)`);
console.log(`pairing (no GT folding, 2-event chunks) ${fmt(pairing0.op)}:`, Object.fromEntries(Object.entries(pairing0.ops).map(([k, v]) => [k, fmt(v)])), 'bytes', pairing0.bytesBy, pairing0.chunking);
for (const mFold of [0, 1, 3, 9]) for (const L of [1, 2, 3]) console.log(`  chunking L=${L}, ${mFold} GT-folded bases:`, JSON.stringify(chunking(L, mFold)));
for (const [n, t] of [['MSM plan A, w=4/4, all Jacobian', pureJ], ['MSM plan A, w=4/4, all affine-witness', pureA]])
  console.log(`${n}: MSM ${fmt(t.msm.op)} / ${t.msm.bytes} B; total ${fmt(t.op)} / ${t.bytes} B; spec ${regimeSpec(t).score}, 100k ${regime100k(t).score}, today ${JSON.stringify(regimeToday(t))}`);
for (const [key, {t, r}] of Object.entries(bestBy)) {
  const g = key.split('/')[0];
  console.log(`best ${key}: plan ${t.plan} wf=${t.wf} wv=${t.wv} fA=${t.fA} mFold=${t.mFold} L=${t.L}: op ${fmt(t.op)}, content ${Math.round(t.bytes)} B, MSM ${fmt(t.msm.op)} / ${Math.round(t.msm.bytes)} B, pairing ${fmt(t.pairing.op)} / ${t.pairing.bytes} B ->`, JSON.stringify(r[g]));
}
writeFileSync(new URL('./model-result.json', import.meta.url), JSON.stringify({nPI: NPI, log2n: LOG2N, units: U, constants: {INSITU, FRMM, ADD_OVH, AFF_GUARD, CODE, GTGLS},
  statement: {proofBytes, piBytes, decode, curve}, transcript: {hashes, op: transcriptOp}, fr: {muls: frMuls, op: frOp}, pairingNoFold: pairing0, naf: NAF,
  vkBytes, reference: {pureJacobian: {...pureJ, regimes: {spec: regimeSpec(pureJ), k100: regime100k(pureJ), today: regimeToday(pureJ)}},
    pureAffine: {...pureA, regimes: {spec: regimeSpec(pureA), k100: regime100k(pureA), today: regimeToday(pureA)}}},
  best: Object.fromEntries(Object.entries(bestBy).map(([key, {t, r}]) => [key, {plan: t.plan, wf: t.wf, wv: t.wv, fA: t.fA, mFold: t.mFold, L: t.L, op: t.op, bytes: t.bytes, msm: t.msm, pairing: t.pairing, regime: r[key.split('/')[0]]}]))}, null, 1));
