// K16 (Blake2s): one Blake2s compression emulated on CashVM, as used for a 2-to-1 Merkle node (Stwo):
// Blake2s-256 of a 64-byte message (left || right) = one compression with t = 64 and the final flag set.
// Checked against node:crypto's blake2s256 on random inputs.
// Representation: the 'a' and 'c' words (v0..3, v8..11) are VM numbers (unreduced: they are only added);
// the 'b' and 'd' words (v4..7, v12..15) are 4-byte little-endian binaries (only XORed / rotated).
//   number -> binary (mod 2^32): 8 NUM2BIN 4 SPLIT DROP     binary -> number: 0x00 CAT BIN2NUM
//   rotr 16 / 8 on LE bytes: 2 (1) SPLIT SWAP CAT          rotr 12 / 7: REVERSEBYTES, BE shift-or, REVERSEBYTES
// Message words are parsed once into 16 numbers. Variants: fully unrolled; G as an OP_DEFINE function.
import {createHash} from 'node:crypto';
import {Stk, asm} from './lib/asm.mjs';

const IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19].map(BigInt);
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const M32 = 0xffffffffn;
const le4 = (v) => Uint8Array.of(Number(v & 255n), Number((v >> 8n) & 255n), Number((v >> 16n) & 255n), Number((v >> 24n) & 255n));
const H0 = [IV[0] ^ 0x01010020n, ...IV.slice(1)];
const V0 = [...H0, IV[0], IV[1], IV[2], IV[3], IV[4] ^ 64n, IV[5], IV[6] ^ M32, IV[7]];
const B0 = Uint8Array.of(0);
const isNum = (i) => i < 4 || (i >= 8 && i < 12);

const toBin = [8, 'NUM2BIN', 4, 'SPLIT', 'DROP'];
const toNum = [B0, 'CAT', 'BIN2NUM'];
const rot = (r) => (r === 16 ? [2, 'SPLIT', 'SWAP', 'CAT'] : r === 8 ? [1, 'SPLIT', 'SWAP', 'CAT']
  : ['REVERSEBYTES', 'DUP', 32 - r, 'LSHIFTBIN', 'SWAP', r, 'RSHIFTBIN', 'OR', 'REVERSEBYTES']);

// G on named items (a, c numbers; b, d binaries); returns the new names
function gInline(s, [a, b, c, d], mx, my, tag) {
  const half = (a, b, c, d, m, r1, r2, k) => {
    s.pick(b); s.emit(toNum); s.roll(a); s.op('ADD', 2, 'x'); s.pick(m); s.op('ADD', 2, `${a}${k}`); const a2 = s.top();
    s.pick(a2); s.emit(toBin); s.roll(d); s.op('XOR', 2, 'x'); s.emit(rot(r1)); s.rename(s.top(), `${d}${k}`); const d2 = s.top();
    s.pick(d2); s.emit(toNum); s.roll(c); s.op('ADD', 2, `${c}${k}`); const c2 = s.top();
    s.pick(c2); s.emit(toBin); s.roll(b); s.op('XOR', 2, 'x'); s.emit(rot(r2)); s.rename(s.top(), `${b}${k}`); const b2 = s.top();
    return [a2, b2, c2, d2];
  };
  const r1 = half(a, b, c, d, mx, 16, 12, tag + 'h');
  return half(...r1, my, 8, 7, tag + 'g');
}

// G as a function on the top six items [a b c d mx my] -> [a b c d]
function gFunctionBody() {
  const s = new Stk(['a', 'b', 'c', 'd', 'mx', 'my']);
  s.roll('my'); s.emit('TOALTSTACK'); s.st.pop();
  // first half with mx
  s.pick('b'); s.emit(toNum); s.roll('a'); s.op('ADD', 2, 'x'); s.roll('mx'); s.op('ADD', 2, 'a1');
  s.pick('a1'); s.emit(toBin); s.roll('d'); s.op('XOR', 2, 'x'); s.emit(rot(16)); s.rename('x', 'd1');
  s.pick('d1'); s.emit(toNum); s.roll('c'); s.op('ADD', 2, 'c1');
  s.pick('c1'); s.emit(toBin); s.roll('b'); s.op('XOR', 2, 'x'); s.emit(rot(12)); s.rename('x', 'b1');
  s.emit('FROMALTSTACK'); s.st.push('my');
  s.pick('b1'); s.emit(toNum); s.roll('a1'); s.op('ADD', 2, 'x'); s.roll('my'); s.op('ADD', 2, 'a2');
  s.pick('a2'); s.emit(toBin); s.roll('d1'); s.op('XOR', 2, 'x'); s.emit(rot(8)); s.rename('x', 'd2');
  s.pick('d2'); s.emit(toNum); s.roll('c1'); s.op('ADD', 2, 'c2');
  s.pick('c2'); s.emit(toBin); s.roll('b1'); s.op('XOR', 2, 'x'); s.emit(rot(7)); s.rename('x', 'b2');
  s.arrange(['a2', 'b2', 'c2', 'd2']);
  return s.bytes();
}

function compressionBody({asFunction}) {
  const s = new Stk(['msg']);
  // parse 16 message words (numbers); m0 at the bottom
  for (let i = 0; i < 15; i++) { s.emit(4, 'SPLIT', 'SWAP', toNum, 'SWAP'); s.st.splice(-1, 1, 'm' + i, 'msg'); }
  s.emit(toNum); s.rename('msg', 'm15');
  // initial state constants
  const v = V0.map((x, i) => { const n = 'v' + i; s.push(isNum(i) ? x : le4(x), n); return n; });
  const G = (i0, i1, i2, i3, mx, my, tag) => {
    const ids = [i0, i1, i2, i3];
    if (!asFunction) { const out = gInline(s, ids.map((i) => v[i]), 'm' + mx, 'm' + my, tag); ids.forEach((i, k) => { v[i] = out[k]; }); return; }
    ids.forEach((i) => s.roll(v[i])); s.pick('m' + mx); s.pick('m' + my);
    s.emit(1, 'INVOKE'); s.st.splice(-6, 6); ids.forEach((i) => { v[i] = `v${i}_${tag}`; s.st.push(v[i]); });
  };
  for (let r = 0; r < 10; r++) {
    const S = SIGMA[r];
    G(0, 4, 8, 12, S[0], S[1], `r${r}a`); G(1, 5, 9, 13, S[2], S[3], `r${r}b`); G(2, 6, 10, 14, S[4], S[5], `r${r}c`); G(3, 7, 11, 15, S[6], S[7], `r${r}d`);
    G(0, 5, 10, 15, S[8], S[9], `r${r}e`); G(1, 6, 11, 12, S[10], S[11], `r${r}f`); G(2, 7, 8, 13, S[12], S[13], `r${r}g`); G(3, 4, 9, 14, S[14], S[15], `r${r}h`);
  }
  for (let i = 0; i < 16; i++) s.drop('m' + i);
  // h'_i = h_i ^ v_i ^ v_{i+8}
  const outs = [];
  for (let i = 0; i < 8; i++) {
    s.roll(v[i]); if (isNum(i)) s.emit(toBin); s.roll(v[i + 8]); if (isNum(i + 8)) s.emit(toBin); s.op('XOR', 2, 'x');
    s.push(le4(H0[i]), 'h'); s.op('XOR', 2, 'o' + i); outs.push('o' + i);
  }
  s.arrange(outs);
  for (let i = 0; i < 7; i++) s.op('CAT', 2, 'd');
  return s.bytes();
}

const kernels = [];
const def = (id, group, name, build, notes = '', trials = 6, extra) => kernels.push({id, group, name, build, notes, trials, extra});
const blake = (m) => Uint8Array.from(createHash('blake2s256').update(m).digest());
const unrolled = compressionBody({asFunction: false});
const withFn = compressionBody({asFunction: true});
const gBody = gFunctionBody();
def('K16', 'blake2s', 'Blake2s-256 of 64 bytes (one compression, 2-to-1 node), fully unrolled', (rng) => {
  const m = rng.bytes(64); return {inputs: [m], body: unrolled, outputs: [{bin: blake(m)}]};
}, 'straight-line code, fits one P2SH redeem');
def('K16', 'blake2s', 'Blake2s-256 of 64 bytes, G as an OP_DEFINE function (80 calls)', (rng) => {
  const m = rng.bytes(64); return {inputs: [m], defs: [{id: 1, body: gBody}], body: withFn, outputs: [{bin: blake(m)}]};
});

export default kernels;
