// Is our scalarMult op-cost scalar-dependent? Our loop is fixed at 254 iterations
// (254 base-doublings always run; an add is gated on each set bit), so op-cost
// should be ~constant in the scalar VALUE, varying only with popcount (# of adds).
// We measure at several scalars (including scrypt-bn256's 113569) by swapping ONLY
// the unlocking push — same locking bytecode, no recompile. (For scalars other
// than the contract's baked-in 987654321 the final equality check fails, but the
// full scalarMult op-cost is still accrued before that check, which is what we
// measure.)
import { readFileSync } from 'node:fs';
import { bigIntToVmNumber, hexToBin } from '@bitauth/libauth';

import { createLoosenedVm, evaluatePair } from '../harness/vm.js';

const v = JSON.parse(readFileSync('src/bch/vkx-scalarmult-vectors.json', 'utf8')) as { lockingOK: string };
const lock = hexToBin(v.lockingOK);
const vm = createLoosenedVm();

const popcount = (n: bigint): number => { let c = 0; while (n > 0n) { c += Number(n & 1n); n >>= 1n; } return c; };
const pushScalar = (n: bigint): Uint8Array => { const d = bigIntToVmNumber(n); return Uint8Array.from([d.length, ...d]); };

const SCRYPT = 987654321n; // baked-in expected matches this one (will ACCEPT)
const scalars: { label: string; n: bigint }[] = [
  { label: 'high bit only', n: 1n << 253n },
  { label: 'scrypt-bn256 input', n: 113569n },
  { label: 'contract baked-in', n: SCRYPT },
  { label: 'all 254 bits set', n: (1n << 254n) - 1n },
];

console.log('our scalarMult op-cost vs scalar (fixed 254-iteration loop):\n');
console.log('scalar                  popcount   op-cost        accepted');
const results: { n: bigint; pc: number; op: number }[] = [];
for (const { label, n } of scalars) {
  const r = evaluatePair(vm, lock, pushScalar(n));
  const pc = popcount(n);
  results.push({ n, pc, op: r.operationCost });
  console.log(`${label.padEnd(22)} ${String(pc).padStart(4)}      ${r.operationCost.toLocaleString().padStart(12)}   ${r.accepted}`);
}

console.log('\n=> 254 base-doublings are fixed; op-cost ~= 37.9M + ~95K per set bit.');
console.log('   For realistic inputs (popcount ~1-17) it stays ~38-39M; only the pathological');
console.log('   all-254-bits case reaches 62M. So op-cost is ~scalar-VALUE-independent.\n');

const atScrypt = results.find((r) => r.n === 113569n)!.op;
const SCRYPT_VKX = 49_477_018; // scrypt-bn256 reaching vk_x at its input 113569 (pnpm scrypt-bn256:find-vkx)
console.log('normalized comparison at scrypt-bn256 scalar 113569 (same popcount, same work):');
console.log(`  ours:        ${atScrypt.toLocaleString()} op-cost`);
console.log(`  scrypt-bn256: ${SCRYPT_VKX.toLocaleString()} op-cost`);
console.log(`  ratio: ${(SCRYPT_VKX / atScrypt).toFixed(2)}x (scrypt-bn256 / ours)`);
