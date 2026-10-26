// Ordinary rejection runs for the genpow singletons (review notes, not shipped).
// Usage: tsx tools/genpow-reject.mts bn|bls [full]
import { readFileSync } from 'node:fs';
import { hexToBin, decodeAuthenticationInstructions, encodeDataPush, bigIntToVmNumber, vmNumberToBigInt, flattenBinArray } from '@bitauth/libauth';
import { createLoosenedVm, evaluatePair } from '../src/harness/vm.js';

const which = process.argv[2];
const full = process.argv[3] === 'full';
const file = which === 'bn' ? 'src/bch/groth16-singleton-genpow-vectors.json' : 'src/bch/groth16-bls12381-singleton-genpow-vectors.json';
const P = which === 'bn'
  ? 21888242871839275222246405745257275088696311157297823662689037894645226208583n
  : 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const R = which === 'bn'
  ? 21888242871839275222246405745257275088548364400416034343698204186575808495617n
  : 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const v = JSON.parse(readFileSync(file, 'utf8'));
const locking = hexToBin(v.lockingOK);
const ins = decodeAuthenticationInstructions(hexToBin(v.unlocking)) as any[];
const nums = ins.map((i) => (i.data ? (vmNumberToBigInt(i.data, { maximumVmNumberByteLength: 10000n, requireMinimalEncoding: true }) as bigint) : BigInt(i.opcode === 0 ? 0 : i.opcode - 0x50)));
console.log('pushes (index:value bits):', nums.map((n, i) => `${i}:${n.toString(2).length}${n < 4n ? '=' + n : ''}`).join(' '));
const enc = (xs: bigint[]) => flattenBinArray(xs.map((x) => encodeDataPush(bigIntToVmNumber(x))));
const vm = createLoosenedVm();
const run = (label: string, xs: bigint[]) => {
  const t = Date.now();
  const o: any = evaluatePair(vm, locking, enc(xs));
  console.log(`${o.accepted ? 'ACCEPT' : 'reject'}  ${label}  (${o.error ?? ''}) opCost=${o.opCost ?? o.operationCost ?? '?'} ${Date.now() - t}ms`);
  return o.accepted;
};
const cases: [string, bigint[]][] = [];
const mut = (i: number, x: bigint) => { const c = nums.slice(); c[i] = x; return c; };
nums.forEach((n, i) => {
  if (i <= 1) { cases.push([`push${i} (public input) + r`, mut(i, n + R)]); cases.push([`push${i} (public input) = -1`, mut(i, -1n)]); return; }
  if (n < 4n) { cases.push([`push${i} small ${n} -> 2`, mut(i, 2n)]); cases.push([`push${i} small ${n} -> 3`, mut(i, 3n)]); cases.push([`push${i} small ${n} -> -1`, mut(i, -1n)]); }
  else { cases.push([`push${i} coord + p`, mut(i, n + P)]); cases.push([`push${i} coord - p (negative)`, mut(i, n - P)]); }
});
if (full && which === 'bn') {
  // neutral encodings with the honest remainder: the equation must then fail
  const small = nums.map((n, i) => (i > 1 && n < 4n ? i : -1)).filter((i) => i >= 0);
  const big = nums.map((n, i) => (i > 1 && n >= 4n ? i : -1)).filter((i) => i >= 0);
  console.log('parity pushes', small, 'coord pushes', big);
  cases.length = 0;
  cases.push(['honest (sanity)', nums.slice()]);
  // A/C neutral: parity push -> 2 and its x push -> 0 (x is the next push in the encoding)
  for (const s of small) { const c = nums.slice(); c[s] = 2n; c[s + 1] = 0n; cases.push([`G1 neutral at push${s},${s + 1}`, c]); }
  const fourB = big.filter((i) => !small.some((s) => s + 1 === i));
  { const c = nums.slice(); for (const i of fourB) c[i] = 0n; cases.push([`G2 neutral B = four zero limbs at ${fourB}`, c]); }
}
let bad = 0;
for (const [l, c] of cases) if (run(l, c) && l !== 'honest (sanity)') bad++;
console.log(bad ? `FAIL: ${bad} mutated case(s) accepted` : 'all mutated cases rejected');
