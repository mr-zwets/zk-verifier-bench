// Minimal CashVM (BCH 2026) assembler for the pq-hash kernel measurements.
//
//   asm(...parts) -> Uint8Array. A part is
//     - an opcode name without the OP_ prefix ('ADD', 'SHA256', 'LSHIFTBIN', ...),
//     - a bigint or number: pushed as a minimally encoded VM number (OP_0, OP_1..OP_16, OP_1NEGATE or a data push),
//     - a Uint8Array: pushed as data (minimal push),
//     - { raw: Uint8Array | number[] }: spliced verbatim,
//     - an array of parts (flattened).
//
//   Stk: a symbolic stack. Every item has a name; pick/roll depths are computed from the names, so code stays
//   position-exact. It only tracks names; values are checked by running the code on the VM.
import {bigIntToVmNumber, encodeDataPush} from '@bitauth/libauth';

export const OP = {
  0: 0x00, FALSE: 0x00, PUSHDATA1: 0x4c, PUSHDATA2: 0x4d, '1NEGATE': 0x4f, 1: 0x51, TRUE: 0x51,
  NOP: 0x61, IF: 0x63, NOTIF: 0x64, BEGIN: 0x65, UNTIL: 0x66, ELSE: 0x67, ENDIF: 0x68, VERIFY: 0x69, RETURN: 0x6a,
  TOALTSTACK: 0x6b, FROMALTSTACK: 0x6c, '2DROP': 0x6d, '2DUP': 0x6e, '3DUP': 0x6f, '2OVER': 0x70, '2ROT': 0x71, '2SWAP': 0x72,
  IFDUP: 0x73, DEPTH: 0x74, DROP: 0x75, DUP: 0x76, NIP: 0x77, OVER: 0x78, PICK: 0x79, ROLL: 0x7a, ROT: 0x7b, SWAP: 0x7c, TUCK: 0x7d,
  CAT: 0x7e, SPLIT: 0x7f, NUM2BIN: 0x80, BIN2NUM: 0x81, SIZE: 0x82, INVERT: 0x83, AND: 0x84, OR: 0x85, XOR: 0x86,
  EQUAL: 0x87, EQUALVERIFY: 0x88, DEFINE: 0x89, INVOKE: 0x8a, '1ADD': 0x8b, '1SUB': 0x8c, LSHIFTNUM: 0x8d, RSHIFTNUM: 0x8e,
  NEGATE: 0x8f, ABS: 0x90, NOT: 0x91, '0NOTEQUAL': 0x92, ADD: 0x93, SUB: 0x94, MUL: 0x95, DIV: 0x96, MOD: 0x97,
  LSHIFTBIN: 0x98, RSHIFTBIN: 0x99, BOOLAND: 0x9a, BOOLOR: 0x9b, NUMEQUAL: 0x9c, NUMEQUALVERIFY: 0x9d, NUMNOTEQUAL: 0x9e,
  LESSTHAN: 0x9f, GREATERTHAN: 0xa0, LESSTHANOREQUAL: 0xa1, GREATERTHANOREQUAL: 0xa2, MIN: 0xa3, MAX: 0xa4, WITHIN: 0xa5,
  REVERSEBYTES: 0xbc, RIPEMD160: 0xa6, SHA1: 0xa7, SHA256: 0xa8, HASH160: 0xa9, HASH256: 0xaa,
  INPUTINDEX: 0xc0, ACTIVEBYTECODE: 0xc1, TXVERSION: 0xc2, TXINPUTCOUNT: 0xc3, TXOUTPUTCOUNT: 0xc4, TXLOCKTIME: 0xc5,
  UTXOVALUE: 0xc6, UTXOBYTECODE: 0xc7, OUTPOINTTXHASH: 0xc8, OUTPOINTINDEX: 0xc9, INPUTBYTECODE: 0xca,
};

export const numBytes = (n) => bigIntToVmNumber(BigInt(n));
export const pushNum = (n) => [...encodeDataPush(numBytes(n))];
export const pushData = (b) => [...encodeDataPush(Uint8Array.from(b))];

export function asm(...parts) {
  const out = [];
  const add = (p) => {
    if (Array.isArray(p)) { p.forEach(add); return; }
    if (p instanceof Uint8Array) { out.push(...pushData(p)); return; }
    if (typeof p === 'bigint' || typeof p === 'number') { out.push(...pushNum(p)); return; }
    if (typeof p === 'string') { const c = OP[p.replace(/^OP_/, '')]; if (c === undefined) throw new Error('unknown opcode ' + p); out.push(c); return; }
    if (p && p.raw) { out.push(...p.raw); return; }
    throw new Error('bad asm part ' + String(p));
  };
  parts.forEach(add);
  return Uint8Array.from(out);
}

let uid = 0;
export const fresh = (b = 't') => `${b}#${uid++}`;

export class Stk {
  constructor(names = []) { this.st = [...names]; this.code = []; }
  emit(...parts) { this.code.push(...asm(...parts)); return this; }
  has(n) { return this.st.lastIndexOf(n) >= 0; }
  depth(n) { const i = this.st.lastIndexOf(n); if (i < 0) throw new Error(`no item '${n}' (top: ${this.st.slice(-12).join(', ')})`); return this.st.length - 1 - i; }
  top(k = 0) { return this.st[this.st.length - 1 - k]; }
  // copy item n to the top (named `as`)
  pick(n, as) { const d = this.depth(n); if (d === 0) this.emit('DUP'); else if (d === 1) this.emit('OVER'); else this.emit(d, 'PICK'); this.st.push(as ?? fresh(n)); return this; }
  // move item n to the top
  roll(n) { const d = this.depth(n); if (d === 1) this.emit('SWAP'); else if (d === 2) this.emit('ROT'); else if (d > 2) this.emit(d, 'ROLL'); this.st.splice(this.st.length - 1 - d, 1); this.st.push(n); return this; }
  // bring n to the top: copy it (keep=true) or move it
  get(n, keep) { return keep ? this.pick(n) : this.roll(n); }
  drop(n) { if (n !== undefined && n !== this.top()) { if (this.depth(n) === 1) { this.emit('NIP'); this.st.splice(this.st.length - 2, 1); return this; } this.roll(n); } this.emit('DROP'); this.st.pop(); return this; }
  push(v, name) { this.emit(v); this.st.push(name ?? fresh('c')); return this; }
  rename(n, as) { this.st[this.st.length - 1 - this.depth(n)] = as; return this; }
  // raw opcode popping `pops` items and pushing named outputs
  op(code, pops, ...outs) { this.emit(code); for (let i = 0; i < pops; i++) this.st.pop(); this.st.push(...outs); return this; }
  // binary op on named items: brings a then b to the top (copy if keepA/keepB) and applies `code`
  bin(code, a, b, out, {ka = false, kb = false} = {}) {
    if (!ka && !kb && this.top() === b && this.top(1) === a) return this.op(code, 2, out);
    this.get(a, ka); const an = this.top();
    this.get(b, kb); this.st[this.st.length - 2] = an;
    return this.op(code, 2, out);
  }
  // move the whole stack into the order `layout` (same names)
  arrange(layout) {
    const sorted = (x) => [...x].sort();
    if (JSON.stringify(sorted(this.st)) !== JSON.stringify(sorted(layout))) throw new Error('arrange: different items ' + this.st + ' / ' + layout);
    let j = layout.length;
    for (; j >= 0; j--) { const mv = new Set(layout.slice(j)); const keep = this.st.filter((x) => !mv.has(x)); if (keep.every((x, i) => x === layout[i])) break; }
    for (let i = j; i < layout.length; i++) this.roll(layout[i]);
    return this;
  }
  bytes() { return Uint8Array.from(this.code); }
}

export const hex = (b) => Buffer.from(b).toString('hex');
export const fromHex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
