// Extract and analyse the sCrypt BSV Groth16 verifier from testnet tx
// eba3...09dd, output 0 (the ~27.5 MB nonstandard locking script). We parse the
// bytecode into instructions directly (no giant ASM string), build an opcode
// histogram + push-length distribution (to identify the curve), and check which
// opcodes exist on BCH 2026.
import { readFileSync, writeFileSync } from 'node:fs';
import { decodeTransactionBch, hexToBin, OpcodesBch } from '@bitauth/libauth';

const tx = decodeTransactionBch(hexToBin(readFileSync('data/scrypt/eba3.hex', 'utf8').trim()));
if (typeof tx === 'string') throw new Error(tx);
const locking = tx.outputs[0]!.lockingBytecode;

// number -> opcode name (first name wins)
const opName = new Map<number, string>();
for (const [name, code] of Object.entries(OpcodesBch)) {
  if (typeof code === 'number' && !opName.has(code)) opName.set(code, name);
}

const opCounts = new Map<string, number>();
const pushLen = new Map<number, number>();
const bump = (m: Map<string | number, number>, k: string | number) => m.set(k, (m.get(k) ?? 0) + 1);

let i = 0;
let totalOps = 0;
while (i < locking.length) {
  const op = locking[i]!;
  i += 1;
  let len = -1; // -1 = not a data push
  if (op >= 0x01 && op <= 0x4b) len = op;
  else if (op === 0x4c) { len = locking[i]!; i += 1; }
  else if (op === 0x4d) { len = locking[i]! | (locking[i + 1]! << 8); i += 2; }
  else if (op === 0x4e) { len = locking[i]! | (locking[i + 1]! << 8) | (locking[i + 2]! << 16) | (locking[i + 3]! << 24); i += 4; }
  if (len >= 0) {
    bump(opCounts, 'PUSH (data)');
    bump(pushLen, len);
    i += len;
  } else {
    bump(opCounts, opName.get(op) ?? `OP_UNKNOWN_0x${op.toString(16)}`);
  }
  totalOps += 1;
}

const sortedOps = [...opCounts.entries()].sort((a, b) => b[1] - a[1]);
const sortedLens = [...pushLen.entries()].sort((a, b) => b[1] - a[1]);
const distinctReal = sortedOps.filter(([o]) => o !== 'PUSH (data)').map(([o]) => o);
const missing = distinctReal.filter((o) => !(o in OpcodesBch));

console.log('sCrypt verifier locking script (eba3...09dd : vout 0)');
console.log('bytes:           ', locking.length.toLocaleString());
console.log('instructions:    ', totalOps.toLocaleString());
console.log('distinct opcodes:', opCounts.size);
console.log('\ntop opcodes:');
for (const [op, n] of sortedOps.slice(0, 22)) console.log(`  ${op.padEnd(22)} ${n.toLocaleString()}`);
console.log('\ntop push-data lengths (bytes -> count)  [48=BLS12-381 Fp, 32=BN254 Fp]:');
for (const [len, n] of sortedLens.slice(0, 12)) console.log(`  ${String(len).padStart(5)} bytes  ${n.toLocaleString()}`);
console.log('\nopcodes used but MISSING on BCH 2026:', missing.length ? missing.join(', ') : '(none)');

writeFileSync('data/scrypt/groth16-locking.hex', Buffer.from(locking).toString('hex'));
console.log('\nwrote data/scrypt/groth16-locking.hex');
