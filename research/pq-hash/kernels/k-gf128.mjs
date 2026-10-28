// K15: GF(2^128) = F_2[x]/(x^128 + x^7 + x^2 + x + 1) multiplication emulated on CashVM (Magnetar's field size).
// External encoding: 16-byte big-endian integer, bit u = coefficient of x^u. Inputs X, Y; output X*Y.
// Variants:
//   (1) bit-serial: LSB-first over Y (Y as a VM number: 2 MOD / 1 RSHIFTNUM), Z ^= V if bit, V = V*x with
//       OP_LSHIFTBIN on a 17-byte V (the overflow lands in the leading byte) and a conditional XOR of 0x87.
//   (2) 4-bit windowed: table T[j] = j(x)*X (16 entries, built in-script) and the reduction table R[o] = o(x)*0x87,
//       both kept as separate stack items so a lookup is `<base> ADD PICK` (16 bytes copied, not a 256-byte blob).
//       MSB-first over Y's nibbles: Z = Z*x^4 (LSHIFTBIN 4 on 17 bytes, overflow nibble -> R lookup), Z ^= T[nib].
//   (3) integer multiplier with holes (BearSSL ghash_ctmul idea): split X and Y into 5 parts with bits u = k mod 5
//       (<= 26 bits each), multiply parts as integers (OP_MUL), XOR the 5 products of each class m = i+j mod 5
//       (carries only pollute non-class bits) and mask once per class; then reduce with shifts and XOR.
//       Correct because a column of one part product has at most 26 < 2^5 terms.
import {asm, Stk} from './lib/asm.mjs';

const MOD = (1n << 128n) | 0x87n;
export function clmul(a, b) { let r = 0n; for (let i = 0n; b >> i; i++) if ((b >> i) & 1n) r ^= a << i; return r; }
export function gfReduce(r) { for (let i = 255n; i >= 128n; i--) if ((r >> i) & 1n) r ^= MOD << (i - 128n); return r; }
export const gfMul = (a, b) => gfReduce(clmul(a, b));
const be = (v, n = 16) => { const b = new Uint8Array(n); for (let i = n - 1; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
const le = (v, n) => be(v, n).reverse();
const fromBe = (b) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
const Z16 = new Uint8Array(16), B0 = Uint8Array.of(0);
const R87 = be(0x87n);

const kernels = [];
const def = (id, group, name, build, notes = '', trials = 8, extra) => kernels.push({id, group, name, build, notes, trials, extra});
const rand = (rng) => rng.big(128);
const io = (rng, body) => { const x = rand(rng), y = rand(rng); return {inputs: [be(x), be(y)], body, outputs: [{bin: be(gfMul(x, y))}]}; };

// ---- (1) bit-serial ----
const bitSerial = asm(
  'REVERSEBYTES', B0, 'CAT', 'BIN2NUM',          // X Yn
  'SWAP', B0, 'SWAP', 'CAT', Z16, 'ROT', 'ROT', 'SWAP', // Z V17 Yn  (Z = 0)
  'BEGIN',
  'DUP', 2, 'MOD', 'SWAP', 1, 'RSHIFTNUM', 'SWAP', // Z V Y' b
  'IF', 'ROT', 2, 'PICK', 1, 'SPLIT', 'NIP', 'XOR', 'ROT', 'ROT', 'ENDIF', // Z^=V
  'SWAP', 1, 'LSHIFTBIN', 1, 'SPLIT', 'SWAP', 'IF', R87, 'XOR', 'ENDIF', B0, 'SWAP', 'CAT', 'SWAP', // V = V*x
  'DUP', 'NOT', 'UNTIL',
  '2DROP');
def('K15', 'gf128', 'GF(2^128) mul, bit-serial (LSB-first loop over Y, LSHIFTBIN + conditional XOR)', (rng) => io(rng, bitSerial),
  'loop runs until the remaining Y is 0 (about 128 iterations for random Y)');

// ---- (2) 4-bit windowed ----
function windowedBody({tableOnly = false} = {}) {
  const s = new Stk(['X', 'Y']);
  s.roll('Y'); s.emit('TOALTSTACK'); s.st.pop();
  for (let o = 15; o >= 0; o--) s.push(be(clmul(BigInt(o), 0x87n)), 'R' + o); // R15 .. R0 (R0 on top)
  const mulx = (src, dst) => { s.pick(src); s.emit(B0, 'SWAP', 'CAT', 1, 'LSHIFTBIN', 1, 'SPLIT', 'SWAP', 'IF', R87, 'XOR', 'ENDIF'); s.st[s.st.length - 1] = dst; };
  const xr = (a, b, dst) => { s.pick(a); s.pick(b); s.op('XOR', 2, dst); };
  s.rename('X', 'T1');
  mulx('T1', 'T2'); mulx('T2', 'T4'); mulx('T4', 'T8');
  xr('T2', 'T1', 'T3'); xr('T4', 'T1', 'T5'); xr('T4', 'T2', 'T6'); xr('T6', 'T1', 'T7'); xr('T8', 'T1', 'T9');
  xr('T8', 'T2', 'T10'); xr('T10', 'T1', 'T11'); xr('T8', 'T4', 'T12'); xr('T12', 'T1', 'T13'); xr('T12', 'T2', 'T14'); xr('T14', 'T1', 'T15');
  s.push(Z16, 'T0');
  const layout = [...Array.from({length: 16}, (_, i) => 'R' + (15 - i)), ...Array.from({length: 16}, (_, i) => 'T' + (15 - i))];
  s.arrange(layout);
  if (tableOnly) { s.emit('FROMALTSTACK', 'DROP'); for (let i = 0; i < 16; i++) s.emit('2DROP'); return s.bytes(); }
  // loop state: R.. T.. Yb Z17
  s.emit('FROMALTSTACK', B0, Z16, 'CAT');
  const nib = ['SWAP', 4, 'LSHIFTBIN', 1, 'SPLIT', 'SWAP', 'BIN2NUM', 18, 'ADD', 'PICK', 'XOR', 'SWAP', 1, 'ADD', 'PICK', 'XOR', B0, 'SWAP', 'CAT'];
  s.emit('BEGIN',
    'SWAP', 1, 'SPLIT', 'TOALTSTACK', B0, 'CAT', 'BIN2NUM', 'DUP', 16, 'MOD', 'TOALTSTACK', 16, 'DIV',
    nib, 'FROMALTSTACK', nib, 'FROMALTSTACK', 'SWAP',
    'OVER', 'SIZE', 'NIP', 'NOT', 'UNTIL',
    1, 'SPLIT', 'NIP', 'NIP', 'TOALTSTACK');
  for (let i = 0; i < 16; i++) s.emit('2DROP');
  s.emit('FROMALTSTACK');
  return s.bytes();
}
const wBody = windowedBody(), wTable = windowedBody({tableOnly: true});
def('K15', 'gf128', 'GF(2^128) mul, 4-bit windowed (table of 16 multiples built in-script, PICK lookups)', (rng) => io(rng, wBody),
  '16 byte-iterations x 2 nibbles; includes table build and cleanup');
def('K15', 'gf128', 'GF(2^128) 4-bit table build + cleanup only (subtract for the per-mul cost with a reused table)', (rng) => {
  const x = rand(rng), y = rand(rng); return {inputs: [be(x), be(y)], body: wTable, outputs: []};
});

// ---- (3) integer multiplier with holes ----
const S = 5;
const mask = (k, bits, n) => { let m = 0n; for (let u = k; u < bits; u += S) m |= 1n << BigInt(u); return le(m, n); };
function holesBody() {
  const s = new Stk(['X', 'Y']);
  for (const v of ['X', 'Y']) { s.roll(v); s.emit('REVERSEBYTES', B0, 'CAT'); } // 17-byte LE, nonneg
  // parts
  for (const v of ['X', 'Y']) for (let k = 0; k < S; k++) { s.pick(v); s.emit(mask(k, 128, 17), 'AND', 'BIN2NUM'); s.st[s.st.length - 1] = v + k; }
  s.drop('X'); s.drop('Y');
  const W = 33;
  for (let m = 0; m < S; m++) {
    const pairs = []; for (let i = 0; i < S; i++) for (let j = 0; j < S; j++) if ((i + j) % S === m) pairs.push([i, j]);
    pairs.forEach(([i, j], n) => {
      const last = m === S - 1; // the last class uses every part exactly once: move instead of copy
      s.get('X' + i, !last); s.get('Y' + j, !last); s.op('MUL', 2, 'p'); s.emit(W, 'NUM2BIN');
      if (n > 0) s.op('XOR', 2, 'acc'); else s.st[s.st.length - 1] = 'acc';
    });
    s.emit(mask(m, 255, W), 'AND'); s.st[s.st.length - 1] = 'C' + m;
  }
  s.op('XOR', 2, 'c'); s.op('XOR', 2, 'c'); s.op('XOR', 2, 'c'); s.op('XOR', 2, 'c'); // C0^..^C4 (33 B LE)
  // reduce: L = bytes 0..15, H = bytes 16..32 (as number)
  s.emit(16, 'SPLIT', 'BIN2NUM'); s.st.splice(-1, 1, 'L', 'H');
  // fold(v, nbytes): v ^ v<<1 ^ v<<2 ^ v<<7 as an nbytes LE binary
  const fold = (n) => ['DUP', n, 'NUM2BIN', 'OVER', 1, 'LSHIFTNUM', n, 'NUM2BIN', 'XOR', 'OVER', 2, 'LSHIFTNUM', n, 'NUM2BIN', 'XOR', 'SWAP', 7, 'LSHIFTNUM', n, 'NUM2BIN', 'XOR'];
  s.emit(fold(17), 16, 'SPLIT', B0, 'CAT', 'BIN2NUM', fold(16), 'XOR', 'XOR', 'REVERSEBYTES');
  return s.bytes();
}
const hBody = holesBody();
def('K15', 'gf128', 'GF(2^128) mul, integer multiplier with holes (5x5 OP_MUL of 26-bit-sparse parts, XOR per class, shift reduction)', (rng) => io(rng, hBody),
  'straight-line, data-independent');

export default kernels;
export {be, fromBe};
