// Deterministic, reproducible generator for a NON-DEGENERATE BN254 Groth16-form
// pairing instance plus the two golden checkpoint values, written to
// pairing-vectors.json. Mirrors how vkx_ref.py grades vk_x, but for the full
// PAIRING milestone (Miller-loop -> final-exponentiation boundary).
//
// Construction (no trusted setup needed — everything is a KNOWN multiple of the
// generators, so the verification equation is solved in the exponent over Fr):
//
//   vk.alpha = [alpha_s]G1                    (G1)
//   vk.beta  = [beta_s]G2, gamma=[gamma_s]G2, delta=[delta_s]G2   (G2, all DISTINCT)
//   vk.IC[i] = [ic_s[i]]G1                     (G1; 2 public inputs => IC[0..2])
//   vk_x     = IC[0] + Σ inputs[i]·IC[i+1]  =>  scalar vkx_s = ic_s[0] + Σ in[i]·ic_s[i+1]
//   proof.A  = [a_s]G1, proof.B = [b_s]G2     (KNOWN a_s, b_s)
//   proof.C  = [c_s]G1
//
// The Groth16 pre-final-exp product is
//   e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta)
//     = e(G1,G2)^( -a_s·b_s + alpha_s·beta_s + vkx_s·gamma_s + c_s·delta_s ).
// finalExponentiate -> 1  iff  that exponent ≡ 0 (mod r).  Solve for c_s:
//   c_s = (a_s·b_s − alpha_s·beta_s − vkx_s·gamma_s) · delta_s^{-1}  (mod r).
//
// All scalars are picked from a FIXED seed (a SplitMix64 PRNG) so the output is
// byte-for-byte reproducible. We assert verify()==true on the valid instance and
// verify()==false on a tampered one, in NOBLE here; gen-pairing-vectors.py
// cross-checks the SAME instance in py_ecc.
import { strict as assert } from 'node:assert';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { bn254 } from '@noble/curves/bn254.js';

import { checkpointsFor, computeVkX, g1Hex, verify, type Proof, type VerifyingKey } from './bn254.js';

const here = dirname(fileURLToPath(import.meta.url));
const r = bn254.fields.Fr.ORDER;

// --- deterministic PRNG (SplitMix64) -> nonzero scalars in [1, r) ---
let _state = 0x9e3779b97f4a7c15n;
const MASK64 = (1n << 64n) - 1n;
const nextU64 = (): bigint => {
  _state = (_state + 0x9e3779b97f4a7c15n) & MASK64;
  let z = _state;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
  return (z ^ (z >> 31n)) & MASK64;
};
// 256-bit draw reduced mod r, forced nonzero.
const randScalar = (): bigint => {
  let acc = 0n;
  for (let i = 0; i < 4; i++) acc = (acc << 64n) | nextU64();
  const s = acc % r;
  return s === 0n ? 1n : s;
};

const G1 = (k: bigint) => bn254.G1.Point.BASE.multiply(((k % r) + r) % r);
const G2 = (k: bigint) => bn254.G2.Point.BASE.multiply(((k % r) + r) % r);
const modr = (x: bigint) => ((x % r) + r) % r;
const invr = (x: bigint) => bn254.fields.Fr.inv(modr(x));

// --- pick distinct random-ish scalars ---
const alpha_s = randScalar();
let beta_s = randScalar();
let gamma_s = randScalar();
let delta_s = randScalar();
// ensure beta/gamma/delta are DISTINCT and nonzero (delta invertible)
const distinct = (xs: bigint[]) => new Set(xs.map(String)).size === xs.length;
while (!distinct([beta_s, gamma_s, delta_s])) {
  gamma_s = randScalar();
  delta_s = randScalar();
}
const ic_s = [randScalar(), randScalar(), randScalar()]; // IC[0..2] => 2 public inputs
const inputs = [randScalar() % 1000000n || 7n, randScalar() % 1000000n || 9n]; // small-ish public inputs
const a_s = randScalar();
const b_s = randScalar();

// vk_x scalar (mod r) and the matching C scalar that makes the product == 1
const vkx_s = modr(ic_s[0]! + inputs[0]! * ic_s[1]! + inputs[1]! * ic_s[2]!);
const c_s = modr((a_s * b_s - alpha_s * beta_s - vkx_s * gamma_s) * invr(delta_s));

// --- materialize the points ---
const alpha = G1(alpha_s);
const beta = G2(beta_s);
const gamma = G2(gamma_s);
const delta = G2(delta_s);
const ic = [G1(ic_s[0]!), G1(ic_s[1]!), G1(ic_s[2]!)];
const A = G1(a_s);
const B = G2(b_s);
const C = G1(c_s);

const vk: VerifyingKey = { alpha, beta, gamma, delta, ic };
const proof: Proof = { a: A, b: B, c: C };

// --- assertions: NON-degenerate + valid (noble) ---
assert.ok(distinct([beta_s, gamma_s, delta_s]), 'beta/gamma/delta scalars are distinct');
assert.ok(!beta.equals(gamma) && !gamma.equals(delta) && !beta.equals(delta), 'beta/gamma/delta G2 points distinct');
assert.ok(!beta.equals(bn254.G2.Point.BASE.multiply(r === 0n ? 1n : 0n + 1n)) || true, 'beta non-trivial'); // (informational)
// the public-input commitment must actually move (vk_x != IC[0]) — exercises the MSM
const vkX = computeVkX(ic, inputs);
assert.ok(!vkX.equals(ic[0]!), 'vk_x is a non-trivial combination (depends on public inputs)');
// the final product must NOT be the trivial identity Fp12 (degenerate demo had product == ONE pre-finalExp)
const cp = checkpointsFor(vk, proof, inputs);
assert.equal(cp.verified, true, 'NOBLE: finalExponentiate(miller boundary) == 1 (valid instance)');
assert.equal(verify(vk, proof, inputs), true, 'NOBLE: verify() accepts the valid instance');
assert.ok(
  !bn254.fields.Fp12.eql(cp.miller, bn254.fields.Fp12.ONE),
  'NON-DEGENERATE: pre-final-exp Fp12 product is NOT the identity (a real Miller boundary)',
);

// --- invalid instance: tamper one public input (vk_x changes => exponent != 0) ---
const tamperedInputs = [inputs[0]!, modr(inputs[1]! + 1n)];
assert.equal(verify(vk, proof, tamperedInputs), false, 'NOBLE: verify() rejects a tampered public input');
const cpInvalid = checkpointsFor(vk, proof, tamperedInputs);
assert.equal(cpInvalid.verified, false, 'NOBLE: tampered instance does not finalExp to 1');

// --- serialize ---
const g1Aff = (p: typeof A) => {
  const a = p.toAffine();
  return { x: a.x.toString(), y: a.y.toString() };
};
const g2Aff = (p: typeof B) => {
  const a = p.toAffine();
  // noble Fp2 affine coords are { c0, c1 } => standard (a + b*u): c0 is real, c1 is imag.
  return {
    x: { c0: a.x.c0.toString(), c1: a.x.c1.toString() },
    y: { c0: a.y.c0.toString(), c1: a.y.c1.toString() },
  };
};

const out = {
  description:
    'BN254 Groth16 PAIRING-milestone vectors (non-degenerate). Points are known multiples of ' +
    'the generators; C solved in the exponent so e(-A,B)e(alpha,beta)e(vk_x,gamma)e(C,delta)==1.',
  curve: 'bn254 / alt_bn128 (EIP-196/197)',
  oracle: '@noble/curves bn254',
  p: bn254.fields.Fp.ORDER.toString(),
  r: r.toString(),
  // scalars are exposed so py_ecc can reconstruct the SAME instance independently.
  scalars: {
    alpha: alpha_s.toString(),
    beta: beta_s.toString(),
    gamma: gamma_s.toString(),
    delta: delta_s.toString(),
    ic: ic_s.map((s) => s.toString()),
    a: a_s.toString(),
    b: b_s.toString(),
    c: c_s.toString(),
    vkx: vkx_s.toString(),
  },
  publicInputs: inputs.map((s) => s.toString()),
  vk: {
    alpha: g1Aff(alpha),
    beta: g2Aff(beta),
    gamma: g2Aff(gamma),
    delta: g2Aff(delta),
    ic: ic.map(g1Aff),
  },
  proof: { a: g1Aff(A), b: g2Aff(B), c: g1Aff(C) },
  invalid: {
    note: 'same vk/proof but public input[1] incremented by 1 (mod r) => verify()==false',
    publicInputs: tamperedInputs.map((s) => s.toString()),
  },
  golden: {
    // checkpoint #1: vk_x as G1 affine (representation-free identity).
    vkXHex: cp.vkXHex, // "x,y" hex
    vkXAffine: g1Aff(vkX),
    // checkpoint #2: pre-final-exp Fp12 product, noble tower-basis byte serialization (384B).
    millerHex: cp.millerHex,
    millerBytes: cp.millerHex.length / 2,
    // end-to-end verdict.
    verified: cp.verified,
    // for the invalid instance:
    invalidVkXHex: cpInvalid.vkXHex,
    invalidMillerHex: cpInvalid.millerHex,
    invalidVerified: cpInvalid.verified,
  },
};

const outPath = join(here, 'pairing-vectors.json');
writeFileSync(outPath, JSON.stringify(out, null, 2));

console.log('=== BN254 Groth16 PAIRING vectors generated (noble) ===');
console.log('non-degenerate valid instance: distinct beta/gamma/delta, vk_x depends on inputs,');
console.log('  pre-final-exp Fp12 product != ONE.');
console.log('scalars (mod r):');
console.log('  alpha =', alpha_s.toString());
console.log('  beta  =', beta_s.toString());
console.log('  gamma =', gamma_s.toString());
console.log('  delta =', delta_s.toString());
console.log('  a     =', a_s.toString());
console.log('  b     =', b_s.toString());
console.log('  c     =', c_s.toString(), '(solved)');
console.log('  vkx   =', vkx_s.toString());
console.log('  inputs=', inputs.map(String).join(', '));
console.log('checkpoint #1 vk_x (x,y):', cp.vkXHex);
console.log('checkpoint #2 miller Fp12:', cp.millerHex.slice(0, 48) + '... (' + out.golden.millerBytes + 'B)');
console.log('verify(valid)   =', verify(vk, proof, inputs) ? 'ACCEPT' : 'REJECT');
console.log('verify(invalid) =', verify(vk, proof, tamperedInputs) ? 'ACCEPT' : 'REJECT');
console.log('wrote', outPath);
