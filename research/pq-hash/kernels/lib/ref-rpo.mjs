// RPO (Rescue Prime Optimized, Miden RPO256) reference permutation in JS, with constants parsed from Miden's
// test-vector generator (data/rpo-constants.json; provenance inside). Validated against the 19 expected hash
// vectors listed there (hash of [0], [0,1], ..., [0..18]) by selfTest().
import {readFileSync} from 'node:fs';
import {P, powmod} from './ref-field.mjs';

const C = JSON.parse(readFileSync(new URL('../data/rpo-constants.json', import.meta.url), 'utf8'));
export const p = P.gl;
export const MDS_ROW = C.MDS_ROW.map(BigInt);
export const ARK1 = C.ARK1.map((r) => r.map(BigInt));
export const ARK2 = C.ARK2.map((r) => r.map(BigInt));
export const INV_ALPHA = 10540996611094048183n;
export const W = 12, ROUNDS = 7;

export function mds(s) { return Array.from({length: W}, (_, i) => s.reduce((a, x, j) => a + x * MDS_ROW[(j - i + W) % W], 0n) % p); }
export function round(s, r, {half} = {}) {
  s = mds(s).map((x, i) => (x + ARK1[r][i]) % p).map((x) => powmod(x, 7n, p));
  if (half === 1) return s;
  s = mds(s).map((x, i) => (x + ARK2[r][i]) % p).map((x) => powmod(x, INV_ALPHA, p));
  return s;
}
export function permute(s) { for (let r = 0; r < ROUNDS; r++) s = round(s, r); return s; }
export function hashElements(el) {
  let s = Array(W).fill(0n); s[8] = BigInt(el.length % 8); let i = 0;
  for (const e of el) { s[i++] = e; if (i === 8) { s = permute(s); i = 0; } }
  if (i > 0) { while (i < 8) s[i++] = 0n; s = permute(s); }
  return s.slice(0, 4);
}
export function selfTest() {
  C.expected_hash_0_to_k.forEach((exp, k) => {
    const got = hashElements(Array.from({length: k + 1}, (_, i) => BigInt(i)));
    if (got.some((g, i) => g !== BigInt(exp[i]))) throw new Error(`RPO reference mismatch at k=${k}`);
  });
  if (powmod(powmod(123456789n, 7n, p), INV_ALPHA, p) !== 123456789n) throw new Error('INV_ALPHA');
  return C.expected_hash_0_to_k.length;
}
