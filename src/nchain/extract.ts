// Extract the real nChain BSV Groth16 verifier opcodes from mainnet.
//
//   parent  tx 79a5...4940  vout[0]  -> the ~480 KB verifier LOCKING script
//   spending tx e4cd...514c  vin[0]   -> the ~40 KB proof/witness UNLOCKING script
//
// We decode both transactions, pull the two scripts, disassemble them to a
// readable opcode listing, and summarise which opcodes the program uses.
import { readFileSync, writeFileSync } from 'node:fs';
import {
  binToHex,
  decodeTransactionBch,
  disassembleBytecodeBch,
  hexToBin,
} from '@bitauth/libauth';

const readHex = (path: string): Uint8Array =>
  hexToBin(readFileSync(path, 'utf8').trim());

const decode = (label: string, path: string) => {
  const tx = decodeTransactionBch(readHex(path));
  if (typeof tx === 'string') throw new Error(`${label}: ${tx}`);
  return tx;
};

const parent = decode('parent', 'data/nchain/parent-tx.hex');
const spending = decode('spending', 'data/nchain/spending-tx.hex');

const lockingBytecode = parent.outputs[0]!.lockingBytecode;
const unlockingBytecode = spending.inputs[0]!.unlockingBytecode;

// Histogram of opcodes (push opcodes collapsed into a single PUSH bucket).
const histogram = (asm: string): Map<string, number> => {
  const counts = new Map<string, number>();
  for (const tok of asm.split(/\s+/)) {
    if (!tok.startsWith('OP_')) continue; // skip 0x.. data words
    const key = /^OP_(PUSHBYTES|PUSHDATA)/.test(tok) ? 'PUSH (data)' : tok;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
};

const report = (label: string, bytecode: Uint8Array, outPath: string) => {
  const asm = disassembleBytecodeBch(bytecode);
  writeFileSync(outPath, asm);
  const counts = histogram(asm);
  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  console.log(`\n=== ${label} ===`);
  console.log('bytes:           ', bytecode.length.toLocaleString());
  console.log('opcode tokens:   ', total.toLocaleString());
  console.log('distinct opcodes:', counts.size);
  console.log('written to:      ', outPath);
  console.log('top opcodes:');
  for (const [op, n] of sorted.slice(0, 25)) {
    console.log(`  ${op.padEnd(22)} ${n.toLocaleString()}`);
  }
  return { label, bytes: bytecode.length, total, distinct: counts.size, sorted };
};

console.log('parent  txid (locking source):', binToHex(parent.outputs[0]!.lockingBytecode).slice(0, 0) || '79a5...4940');
console.log('spending txid (unlocking)    :', 'e4cd...514c');

report(
  'BSV Groth16 LOCKING script (the verifier)',
  lockingBytecode,
  'data/nchain/groth16-locking.asm',
);
report(
  'BSV Groth16 UNLOCKING script (proof + witness)',
  unlockingBytecode,
  'data/nchain/groth16-unlocking.asm',
);
