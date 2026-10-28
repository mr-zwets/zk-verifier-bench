// K16 (Tip5): one Tip5 permutation (Triton VM / Neptune: Goldilocks, width 16, 5 rounds; S-box layer = 4
// split-and-lookup S-boxes on the Montgomery bytes + 12 x^7; circulant MDS; round constants), emulated on CashVM.
// The JS reference below is checked against the permutation test vector in twenty-first (data/tip5-constants.json).
// Script building blocks:
//   lookup S-box: m = x*R mod p (R = 2^64 mod p), 8 bytes, each byte looked up in a 256-entry table kept as 256
//                 one-byte stack items (`0x00 CAT BIN2NUM <d> ADD PICK`), bytes concatenated, x' = m' * R^-1 mod p;
//   x^7          : as RPO;
//   MDS + ARK    : the Kronecker-packed circulant of k-rpo.mjs with 16 slots of 11 bytes (entries < 2^16).
// The table is pushed once per permutation (counted) and dropped at the end (counted).
import {readFileSync} from 'node:fs';
import {Stk, asm, numBytes} from './lib/asm.mjs';
import {P, powmod} from './lib/ref-field.mjs';
import {mdsArkCode, sbox7, pack} from './k-rpo.mjs';

const C = JSON.parse(readFileSync(new URL('./data/tip5-constants.json', import.meta.url), 'utf8'));
const p = P.gl, W = 16, ROUNDS = 5, NL = 4;
const LUT = C.LOOKUP_TABLE, RC = C.ROUND_CONSTANTS.map(BigInt), COL = C.MDS_MATRIX_FIRST_COLUMN.map(BigInt);
const R = (1n << 64n) % p, RINV = powmod(R, p - 2n, p);

// ---- reference ----
function lookup(x) {
  let m = x * R % p; let out = 0n;
  for (let i = 0; i < 8; i++) out |= BigInt(LUT[Number((m >> BigInt(8 * i)) & 255n)]) << BigInt(8 * i);
  return out * RINV % p;
}
function permute(s) {
  for (let r = 0; r < ROUNDS; r++) {
    s = s.map((x, i) => (i < NL ? lookup(x) : powmod(x, 7n, p)));
    s = Array.from({length: W}, (_, i) => (s.reduce((a, x, j) => a + COL[(i - j + W) % W] * x, 0n) + RC[r * W + i]) % p);
  }
  return s;
}
(function selfTest() {
  const out = permute(C.test_state.map(BigInt));
  if (out.some((v, i) => v !== BigInt(C.test_expected[i]))) throw new Error('Tip5 reference does not match the twenty-first test vector');
})();

// circulant row for mdsArkCode (which computes c_i = sum_j s_j row[(j - i) mod w]): row[k] = COL[(-k) mod 16]
const ROW = Array.from({length: W}, (_, k) => COL[(W - k) % W]);
const SLB = 11;
const B0 = Uint8Array.of(0);

// lookup S-box on the top element; `base` = depth of table entry 0 below the element when the code starts
function lookupCode(base) {
  const s = new Stk(['x']);
  s.emit(R, 'MUL', p, 'MOD', 9, 'NUM2BIN', 8, 'SPLIT', 'DROP'); // m as 8 LE bytes
  // per byte (from the low end): split it off, look it up, append to the output
  // stack: [rest] -> [out rest]
  for (let i = 0; i < 8; i++) {
    const last = i === 7;
    if (!last) s.emit(1, 'SPLIT', 'SWAP'); // [.. rest b]
    // depth of table entry 0 after the PICK index is popped: base + items above the table
    const above = (i === 0 ? 0 : 1) + (last ? 0 : 1); // out (if any) and rest (if any) sit above the table
    s.emit(B0, 'CAT', 'BIN2NUM', base + above, 'ADD', 'PICK'); // [.. rest t]  (out below rest)
    if (i > 0) { // append to out: [out rest t] -> [out' rest]
      if (last) s.emit('CAT'); else s.emit('ROT', 'SWAP', 'CAT', 'SWAP');
    } else if (!last) s.emit('SWAP'); // [t rest]
  }
  s.emit(B0, 'CAT', 'BIN2NUM', RINV, 'MUL', p, 'MOD');
  return s.bytes();
}
// layer: the 16 state items are on top of the table (s15 on top). Process elements s0..s3 with lookups and
// s4..s15 with x^7 by cycling: apply to the top, then bring the next one up with 15 ROLL. Visiting order:
// first the top (s15), then s0, s1, ..., s14. Table entry 0 sits right below s0, so for the element on top
// the table base depth is 15 (the other 15 state items are above the table).
function layerCode() {
  const parts = [];
  const visit = [15, ...Array.from({length: 15}, (_, i) => i)];
  for (const i of visit) {
    parts.push(i < NL ? [{raw: lookupCode(15)}] : [{raw: sbox7}]);
    parts.push(15, 'ROLL');
  }
  return asm(parts);
}
const F = {MDS: 1, LAYER: 2};
const defs = [{id: F.MDS, body: mdsArkCode(W, ROW, SLB)}, {id: F.LAYER, body: layerCode()}];
const tablePush = asm(Array.from({length: 256}, (_, k) => Uint8Array.of(LUT[255 - k]))); // entry 255 deepest, entry 0 on top
const tableDrop = asm(Array.from({length: 128}, () => '2DROP'));
// body: state on the stack -> move state to alt, push table, bring state back, rounds, move state out, drop table
const body = asm(Array.from({length: W}, () => 'TOALTSTACK'), {raw: tablePush}, Array.from({length: W}, () => 'FROMALTSTACK'),
  Array.from({length: ROUNDS}, (_, r) => [F.LAYER, 'INVOKE', pack(RC.slice(r * W, r * W + W).map((x) => x), SLB), F.MDS, 'INVOKE']),
  Array.from({length: W}, () => 'TOALTSTACK'), {raw: tableDrop}, Array.from({length: W}, () => 'FROMALTSTACK'));

const kernels = [];
const def = (id, group, name, build, notes = '', trials = 4, extra) => kernels.push({id, group, name, build, notes, trials, extra});
def('K16', 'tip5', 'Tip5 permutation (Triton VM), emulated: 4 lookup S-boxes + 12 x^7 + packed MDS per round, 5 rounds', (rng) => {
  const s = Array.from({length: W}, () => rng.below(p));
  return {inputs: s.map((v) => numBytes(v)), defs, body, outputs: permute(s).map((v) => ({num: v}))};
}, 'includes pushing and dropping the 256-entry table; 1 permutation = one 2-to-1 Tip5 hash (5-element = 40-byte digest)');
def('K16', 'tip5', 'Tip5 building block: one split-and-lookup S-box (table on the stack)', (rng) => {
  const x = rng.below(p);
  return {inputs: [numBytes(x)], body: asm('TOALTSTACK', {raw: tablePush}, 'FROMALTSTACK', {raw: lookupCode(0)}, 'TOALTSTACK', {raw: tableDrop}, 'FROMALTSTACK'), outputs: [{num: lookup(x)}]};
}, 'includes the table push/drop (about 40k); subtract the table kernel below');
def('K16', 'tip5', 'Tip5 building block: push + drop the 256-entry table', () => ({inputs: [], body: asm({raw: tablePush}, {raw: tableDrop}), outputs: []}), '', 1);
def('K16', 'tip5', 'Tip5 building block: MDS 16x16 + round constants (Kronecker-packed, 11-byte slots)', (rng) => {
  const s = Array.from({length: W}, () => rng.below(p));
  const exp = Array.from({length: W}, (_, i) => (s.reduce((a, x, j) => a + COL[(i - j + W) % W] * x, 0n) + RC[i]) % p);
  return {inputs: [...s.map((v) => numBytes(v)), numBytes(pack(RC.slice(0, W), SLB))], body: mdsArkCode(W, ROW, SLB), outputs: exp.map((v) => ({num: v}))};
});

export default kernels;
