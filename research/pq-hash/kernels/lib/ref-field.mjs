// Reference field arithmetic (JS BigInt), independent of the script code generators.
export const P = {
  gl: (1n << 64n) - (1n << 32n) + 1n,          // Goldilocks
  bb: (1n << 31n) - (1n << 27n) + 1n,          // BabyBear
  m31: (1n << 31n) - 1n,                       // Mersenne-31
  p128: (1n << 128n) - 159n,                   // a 128-bit prime
  p192: (1n << 192n) - (1n << 64n) - 1n,       // NIST P-192 prime (K19)
  bn254r: 21888242871839275222246405745257275088548364400416034343698204186575808495617n, // BN254 scalar field (context)
};
export const md = (a, p) => ((a % p) + p) % p;
export function powmod(b, e, p) { let r = 1n; b = md(b, p); while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; } return r; }

// binomial extension F_p[x]/(x^k - W): elements are arrays of k coefficients
export function binMul(a, b, W, p) {
  const k = a.length, c = Array(2 * k - 1).fill(0n);
  for (let i = 0; i < k; i++) for (let j = 0; j < k; j++) c[i + j] += a[i] * b[j];
  const r = c.slice(0, k);
  for (let i = k; i < 2 * k - 1; i++) r[i - k] += W * c[i];
  return r.map((x) => md(x, p));
}
// QM31 (Stwo): CM31 = M31[i]/(i^2 + 1), QM31 = CM31[u]/(u^2 - (2 + i)); basis (1, i, u, iu)
const cm = {
  mul: ([a, b], [c, d], p) => [md(a * c - b * d, p), md(a * d + b * c, p)],
  add: ([a, b], [c, d], p) => [md(a + c, p), md(b + d, p)],
};
export function qm31Mul(x, y, p = P.m31) {
  const a = [x[0], x[1]], b = [x[2], x[3]], c = [y[0], y[1]], d = [y[2], y[3]];
  const R = [2n, 1n];
  const lo = cm.add(cm.mul(a, c, p), cm.mul(R, cm.mul(b, d, p), p), p);
  const hi = cm.add(cm.mul(a, d, p), cm.mul(b, c, p), p);
  return [...lo, ...hi];
}
// structure constants T[j][l] = basis_j * basis_l as a coefficient vector (integers, unreduced), from a mul fn
export function structureConstants(k, mulFn, p) {
  const e = (i) => Array.from({length: k}, (_, j) => (i === j ? 1n : 0n));
  const signed = (v) => (v > p / 2n ? v - p : v);
  return Array.from({length: k}, (_, j) => Array.from({length: k}, (_, l) => mulFn(e(j), e(l)).map(signed)));
}
