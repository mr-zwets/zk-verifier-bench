// Locate the vk_x milestone inside the monolithic scrypt-bn256 verifier and
// measure the cumulative op-cost / instructions to reach it.
//
// 1. Recover the VK's G1 points (alpha + IC) and the public input from the
//    bytecode (on-curve test fixes the byte encoding = little-endian).
// 2. Compute every candidate vk_x = IC_i + input·IC_j (all ordered pairs of the
//    on-curve G1 points, both input encodings) — we don't need to know a priori
//    which point is which; the execution disambiguates.
// 3. Run the verifier with a traced per-op hook that watches the stack for any
//    candidate (and for the proof point A as a detection sanity-check), recording
//    the cumulative operationCost + evaluatedInstructionCount at first sight.
import { readFileSync } from 'node:fs';
import {
  bigIntToVmNumber,
  binToHex,
  ConsensusBch2025,
  createInstructionSetBch2026,
  createTestAuthenticationProgramBch,
  createVirtualMachine,
  decodeTransactionBch,
  hexToBin,
  ripemd160,
  secp256k1,
  sha1,
  sha256,
} from '@bitauth/libauth';
import { bn254 } from '@noble/curves/bn254.js';

import { loosenedConsensusBch2026 } from '../harness/vm.js';

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const G1 = bn254.G1.Point;

const decode = (path: string) => {
  const tx = decodeTransactionBch(hexToBin(readFileSync(path, 'utf8').trim()));
  if (typeof tx === 'string') throw new Error(tx);
  return tx;
};
const leBig = (d: Uint8Array): bigint => [...d].reverse().reduce((a, b) => (a << 8n) | BigInt(b), 0n);
const beBig = (d: Uint8Array): bigint => d.reduce((a, b) => (a << 8n) | BigInt(b), 0n);
const onCurve = (x: bigint, y: bigint): boolean =>
  x > 0n && x < P && y > 0n && y < P && ((y * y - (x * x * x + 3n)) % P + P) % P === 0n;

const leadingPushes = (s: Uint8Array, max = 100000): Uint8Array[] => {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < s.length && out.length < max) {
    const op = s[i]!;
    i += 1;
    if (op === 0x00) { out.push(new Uint8Array()); continue; }
    if (op === 0x4f) { out.push(Uint8Array.of(0x81)); continue; }
    if (op >= 0x51 && op <= 0x60) { out.push(Uint8Array.of(op - 0x50)); continue; }
    let len = -1;
    if (op >= 0x01 && op <= 0x4b) len = op;
    else if (op === 0x4c) { len = s[i]!; i += 1; }
    else if (op === 0x4d) { len = s[i]! | (s[i + 1]! << 8); i += 2; }
    else if (op === 0x4e) { len = s[i]! | (s[i + 1]! << 8) | (s[i + 2]! << 16) | (s[i + 3]! << 24); i += 4; }
    else break;
    out.push(s.slice(i, i + len));
    i += len;
  }
  return out;
};

const lock = decode('data/scrypt-bn256/parent-tx.hex').outputs[0]!.lockingBytecode;
const unlock = decode('data/scrypt-bn256/spending-tx.hex').inputs[0]!.unlockingBytecode;
const vkPushes = leadingPushes(lock);
const proofPushes = leadingPushes(unlock);

// on-curve G1 points (LE) in the VK
const g1s: { x: bigint; y: bigint }[] = [];
for (let i = 0; i + 1 < vkPushes.length; i++) {
  const x = leBig(vkPushes[i]!);
  const y = leBig(vkPushes[i + 1]!);
  if (onCurve(x, y)) g1s.push({ x, y });
}
console.log(`on-curve G1 points in VK: ${g1s.length}`);

const inputs = [leBig(proofPushes[0]!), beBig(proofPushes[0]!)];

// candidate vk_x = g[i] + input·g[j] for all ordered pairs and both input encodings.
// Map each candidate's x and y (as VM-number hex) -> human label.
const targets = new Map<string, string>();
const addCoord = (hex: string, label: string) => { if (!targets.has(hex)) targets.set(hex, label); };
const enc = (n: bigint) => binToHex(bigIntToVmNumber(n));
for (let i = 0; i < g1s.length; i++) {
  for (let j = 0; j < g1s.length; j++) {
    if (i === j) continue;
    for (const input of inputs) {
      const vkx = G1.fromAffine(g1s[i]!).add(G1.fromAffine(g1s[j]!).multiply(input)).toAffine();
      addCoord(enc(vkx.x), `vk_x.x (IC0=#${i},IC1=#${j},input=${input})`);
      addCoord(enc(vkx.y), `vk_x.y (IC0=#${i},IC1=#${j},input=${input})`);
    }
  }
}
// sanity: proof point A.x is pushed by the unlocking, should be seen almost immediately
addCoord(enc(leBig(proofPushes[1]!)), 'SANITY proof A.x');
console.log(`watching ${targets.size} target values (vk_x candidates + 1 sanity)`);

// traced VM: detect first appearance of any target on the stack top.
const base = createInstructionSetBch2026(false, {
  consensus: loosenedConsensusBch2026,
  ripemd160, secp256k1, sha1, sha256,
});
const hits: { label: string; opCost: number; instr: number }[] = [];
const seen = new Set<string>();
const traced = {
  ...base,
  every: (state: Parameters<NonNullable<typeof base.every>>[0]) => {
    const s = base.every!(state);
    if (s.error === undefined) {
      const top = s.stack[s.stack.length - 1];
      const top2 = s.stack[s.stack.length - 2];
      for (const item of [top, top2]) {
        if (item === undefined || item.length < 24 || item.length > 33) continue;
        const hex = binToHex(item);
        const label = targets.get(hex);
        if (label !== undefined && !seen.has(label)) {
          seen.add(label);
          hits.push({ label, opCost: s.metrics.operationCost, instr: s.metrics.evaluatedInstructionCount });
        }
      }
    }
    return s;
  },
};

const vm = createVirtualMachine(traced);
const program = createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: unlock, valueSatoshis: 1000n });
console.log('evaluating verifier with milestone tracing (this is heavy)...\n');
const t0 = process.hrtime.bigint();
const state = vm.evaluate(program);
const ms = Number(process.hrtime.bigint() - t0) / 1e6;

const total = state.metrics.operationCost;
const totalInstr = state.metrics.evaluatedInstructionCount;
console.log(`total: ${total.toLocaleString()} op-cost, ${totalInstr.toLocaleString()} instructions (${ms.toFixed(0)} ms)\n`);
console.log('milestones detected on the stack (cumulative to reach):');
for (const h of hits.sort((a, b) => a.instr - b.instr)) {
  console.log(`  ${h.label}`);
  console.log(`      op-cost ${h.opCost.toLocaleString()} (${((h.opCost / total) * 100).toFixed(1)}% of total), instr ${h.instr.toLocaleString()} (${((h.instr / totalInstr) * 100).toFixed(1)}%)`);
}
if (hits.length === 0) console.log('  (no candidate matched — vk_x may be held in projective form; would need (X,Y,Z) matching)');
