// K16 (RPO): one full RPO permutation (Miden RPO256: Goldilocks, width 12, 7 rounds, x^7 and x^(1/7) S-boxes,
// circulant MDS), emulated on CashVM, checked against the JS reference (lib/ref-rpo.mjs, itself checked against
// Miden's 19 published hash vectors).
// Building blocks (OP_DEFINE functions):
//   MDS+ARK  : Kronecker-packed circulant: pack the 12 elements into one integer with 80-bit slots (11 x LSHIFTNUM/ADD),
//              one OP_MUL by the packed constant row, fold slots 12..22 onto 0..10 (wrap), add the packed round
//              constants, unpack 12 slots (SPLIT/BIN2NUM) and reduce each with OP_MOD.
//   S-box    : x^7 with 4 mulmods.
//   inverse  : (a) computed: x^(1/7) by Miden's 72-multiplication addition chain, squarings paired lazily (one OP_MOD
//              per two squarings); (b) witnessed: the prover supplies y = x^(1/7) and the verifier checks y^7 == x
//              (unique since x -> x^7 is a permutation of F_p); 84 hints = 672 bytes per permutation.
import {asm, Stk, numBytes} from './lib/asm.mjs';
import {p, MDS_ROW, ARK1, ARK2, INV_ALPHA, W, ROUNDS, mds, permute} from './lib/ref-rpo.mjs';
import {powmod} from './lib/ref-field.mjs';

const nb = (v) => numBytes(v);
const SL = 80, SLB = 10; // slot bits / bytes
const pack = (v) => v.reduce((a, x, i) => a + (x << BigInt(SL * i)), 0n);
// Q(X) = sum_k M[(-k) mod 12] X^k, so that coefficient n of S*Q is sum_j s_j M[(j - n) mod 12]
export const packedRow = (row) => pack(row.map((_, k) => row[(row.length - k) % row.length]));

// [s0 .. s_{w-1} ARK] -> [s0' .. s_{w-1}'] ; s' = (circulant(row) s + ARK) mod p
export function mdsArkCode(w, row, slb = SLB) {
  const sl = slb * 8;
  const Q = packedRow(row);
  return asm('TOALTSTACK',
    Array.from({length: w - 1}, () => [sl, 'LSHIFTNUM', 'ADD']), // Horner from the top: s_{w-2} + s_{w-1} X, ...
    Q, 'MUL',
    2 * w * slb, 'NUM2BIN', w * slb, 'SPLIT', 'BIN2NUM', 'SWAP', 'BIN2NUM', 'ADD', 'FROMALTSTACK', 'ADD', // wrap + ARK
    w * slb, 'NUM2BIN',
    Array.from({length: w - 1}, () => [slb, 'SPLIT', 'SWAP', 'BIN2NUM', p, 'MOD', 'SWAP']), 'BIN2NUM', p, 'MOD');
}
// note: the Horner packing above builds s_0 + s_1 X + ... only if the stack is [s0 .. s_{w-1}] and we fold from the top:
// [.. s_{w-2} s_{w-1}] -> s_{w-2} + s_{w-1} X ... -> s_0 + X(...) -- this is the order assumed by packedRow.

const sbox7 = asm('DUP', 'DUP', 'MUL', p, 'MOD', 'TUCK', 'MUL', p, 'MOD', 'SWAP', 'DUP', 'MUL', p, 'MOD', 'MUL', p, 'MOD');
// x^(1/7): Miden's chain. sq(k): k squarings, paired: DUP MUL DUP MUL p MOD.
function invSboxCode() {
  const s = new Stk(['x']);
  const sq = (k) => { for (let i = 0; i + 1 < k; i += 2) s.emit('DUP', 'MUL', 'DUP', 'MUL', p, 'MOD'); if (k % 2) s.emit('DUP', 'MUL', p, 'MOD'); };
  const mulBy = (n, keep) => { s.get(n, keep); s.emit('MUL', p, 'MOD'); s.st.pop(); };
  s.pick('x'); sq(1); s.rename(s.top(), 't1');          // x^2
  s.pick('t1'); sq(1); s.rename(s.top(), 't2');         // x^4
  s.pick('t2'); sq(3); mulBy('t2', true); s.rename(s.top(), 't3');
  s.pick('t3'); sq(6); mulBy('t3', true); s.rename(s.top(), 't4');
  s.pick('t4'); sq(12); mulBy('t4', false); s.rename(s.top(), 't5');
  sq(6); mulBy('t3', false); s.rename(s.top(), 't6');
  s.pick('t6'); sq(31); mulBy('t6', true); s.rename(s.top(), 't7');
  sq(1); mulBy('t6', false); sq(2); s.rename(s.top(), 'a');
  // b = t1 * t2 * x
  s.roll('t1'); s.roll('t2'); s.op('MUL', 2, 'u'); s.emit(p, 'MOD'); s.roll('x'); s.op('MUL', 2, 'b'); s.emit(p, 'MOD');
  s.op('MUL', 2, 'r'); s.emit(p, 'MOD');
  if (s.st.length !== 1) throw new Error('invSbox leftover ' + s.st);
  return s.bytes();
}
const inv = invSboxCode();
const invWitness = asm('FROMALTSTACK', 'DUP', {raw: sbox7}, 'ROT', 'NUMEQUALVERIFY'); // [x] (alt: y..) -> [y]
const layer = (fid) => asm(Array.from({length: W}, () => [fid, 'INVOKE', W - 1, 'ROLL']));

const F = {MDS: 1, SBOX: 2, INV: 3, LAYER: 4, INVLAYER: 5};
const defsFor = (invBody) => [
  {id: F.MDS, body: mdsArkCode(W, MDS_ROW)}, {id: F.SBOX, body: sbox7}, {id: F.INV, body: invBody},
  {id: F.LAYER, body: layer(F.SBOX)}, {id: F.INVLAYER, body: layer(F.INV)},
];
const permBody = (rounds = ROUNDS) => asm(Array.from({length: rounds}, (_, r) => [pack(ARK1[r]), F.MDS, 'INVOKE', F.LAYER, 'INVOKE', pack(ARK2[r]), F.MDS, 'INVOKE', F.INVLAYER, 'INVOKE']));

// witnesses for the inverse S-boxes, in the order they are consumed (round by round, element order of the layer)
function hintsFor(state, rounds = ROUNDS) {
  const hints = []; let s = state;
  for (let r = 0; r < rounds; r++) {
    s = mds(s).map((x, i) => (x + ARK1[r][i]) % p).map((x) => powmod(x, 7n, p));
    s = mds(s).map((x, i) => (x + ARK2[r][i]) % p);
    const order = [11, ...Array.from({length: W - 1}, (_, i) => i)]; // the layer visits the top (s11) first, then s0..s10
    for (const i of order) hints.push(powmod(s[i], INV_ALPHA, p));
    s = s.map((x) => powmod(x, INV_ALPHA, p));
  }
  return hints;
}

const kernels = [];
const def = (id, group, name, build, notes = '', trials = 4, extra) => kernels.push({id, group, name, build, notes, trials, extra});
const rstate = (rng) => Array.from({length: W}, () => rng.below(p));

def('K16', 'rpo', 'RPO permutation (Miden RPO256), inverse S-box computed (72-mul chain)', (rng) => {
  const s = rstate(rng);
  return {inputs: s.map(nb), defs: defsFor(inv), body: permBody(), outputs: permute(s).map((v) => ({num: v}))};
}, 'functions via OP_DEFINE; 1 permutation = one 2-to-1 RPO hash (4-element = 32-byte digest)');
def('K16', 'rpo', 'RPO permutation, inverse S-box witnessed (84 hints of 8 B moved to the altstack; y^7 == x checked)', (rng) => {
  const s = rstate(rng); const hints = hintsFor(s);
  // hints are pushed above the state in consumption order; TOALTSTACK x 84 leaves the first one on top of the altstack
  const body = asm(Array.from({length: hints.length}, () => ['TOALTSTACK']), {raw: permBody()});
  return {inputs: [...s.map(nb), ...hints.map(nb)], defs: defsFor(invWitness), body, outputs: permute(s).map((v) => ({num: v}))};
}, '+672 proof bytes per permutation (84 x 8 B)', 4, {hintBytes: 672});
// building blocks
def('K16', 'rpo', 'RPO building block: MDS + ARK (Kronecker-packed circulant, 1 OP_MUL, 12 OP_MOD)', (rng) => {
  const s = rstate(rng);
  return {inputs: [...s.map(nb), nb(pack(ARK1[0]))], body: mdsArkCode(W, MDS_ROW), outputs: mds(s).map((x, i) => ({num: (x + ARK1[0][i]) % p}))};
});
def('K16', 'rpo', 'RPO building block: S-box x^7 (one element)', (rng) => { const x = rng.below(p); return {inputs: [nb(x)], body: sbox7, outputs: [{num: powmod(x, 7n, p)}]}; });
def('K16', 'rpo', 'RPO building block: inverse S-box x^(1/7), 72-mul chain (one element)', (rng) => { const x = rng.below(p); return {inputs: [nb(x)], body: inv, outputs: [{num: powmod(x, INV_ALPHA, p)}]}; });
def('K4', 'field', 'Goldilocks exponentiation by a fixed 64-bit exponent (the x^(1/7) chain above: 63 squarings + 9 mul)', (rng) => { const x = rng.below(p); return {inputs: [nb(x)], body: inv, outputs: [{num: powmod(x, INV_ALPHA, p)}]}; }, 'same code as the inverse S-box; an F_p inversion x^(p-2) has the same shape');

export default kernels;
export {sbox7, pack};
