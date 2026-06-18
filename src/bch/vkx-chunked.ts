// Groth16 verifier CHECKPOINT #1 -- vk_x -- as a MULTI-TRANSACTION chain whose
// every chunk fits ONE standard BCH input.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// The monolithic single-tx vk_x (src/bch/vkx.ts) is ~76M op-cost (~10 inputs).
// Here it is split into K=32-iteration double-and-add windows; each window is a
// CashScript contract that verifies its hash256-committed incoming state, runs
// its K iterations (Fp ops as OP_DEFINE/OP_INVOKE), and commits the outgoing
// state -- chunk i's outgoing == chunk i+1's incoming. The final chunk does the
// single Fermat inverse -> affine and asserts equality with the py_ecc vk_x.
//
// PADDING: each chunk's unlocking = the 9 incoming coords (reverse declaration
// order, minimal pushes) + one big zero-PUSH padding the unlocking to ~10,000
// bytes; the locking has a single OP_DROP prepended to consume that pad push.
// That buys real-VM budget (41 + 10000) * 800 = 8,032,800 per input.
//
// This script re-evaluates each chunk's PADDED (locking, unlocking) on the
// loosened VM (math correctness) and the real BCH 2026 VM (consensus verdict),
// prints per-chunk op-cost / bytes / fits-one-input, confirms the chain is
// continuous, reproduces the py_ecc vk_x, and that a tampered chunk is rejected.
//
// Regenerate vectors:
//   (groth16_contract)        python vkx_ref.py
//   (groth16_contract/chunked) K=32 python gen_chunks.py
//   (groth16_contract/chunked) node build_vectors.mjs   -> writes vkx-chunked-vectors.json
// Run:  pnpm tsx src/bch/vkx-chunked.ts
import { hexToBin } from '@bitauth/libauth';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createLoosenedVm, createRealVm, evaluatePair, standardInputBudget } from '../harness/vm.js';

const here = dirname(fileURLToPath(import.meta.url));
interface Chunk {
  idx: number;
  term: number;
  lo: number;
  hi: number;
  fold: boolean;
  final: boolean;
  incoming: string;
  outgoing: string | null;
  locking: string;
  unlocking: string;
  lockingBytes: number;
  unlockingBytes: number;
}
const vectors = JSON.parse(readFileSync(join(here, 'vkx-chunked-vectors.json'), 'utf8')) as {
  K: number;
  numChunks: number;
  input0: number;
  input1: number;
  expected: [string, string];
  budgetPerInput: number;
  chunks: Chunk[];
};

// Read the py_ecc reference's expected point as STRINGS (these 254-bit integers
// exceed Number precision, so JSON.parse-to-number would round them). Match the
// two big integer literals after the "expected" key in the raw JSON text.
const refText = readFileSync('C:/Users/mathi/Desktop/groth16_contract/vkx_vectors.json', 'utf8');
const refMatch = refText.match(/"expected"\s*:\s*\[\s*(\d+)\s*,\s*(\d+)\s*\]/);
const ref = { expected: [refMatch![1]!, refMatch![2]!] as [string, string] };

const loosened = createLoosenedVm();
const real = createRealVm();
const BUDGET = standardInputBudget();

console.log('=== Groth16 checkpoint #1: vk_x = IC0 + input0*IC1 + input1*IC2 (CHUNKED, multi-tx) ===');
console.log(`input0 = ${vectors.input0}  input1 = ${vectors.input1}`);
console.log(`K = ${vectors.K} iterations/chunk,  ${vectors.numChunks} chunks`);
console.log('expected vk_x (affine, py_ecc.bn128):');
console.log('  x =', vectors.expected[0]);
console.log('  y =', vectors.expected[1]);
console.log('standard input op-cost budget (unlock=10000B):', BUDGET.toLocaleString());
console.log();

let totalOp = 0;
let maxOp = 0;
let allFit = true;
let allLoose = true;
let allReal = true;
let maxLock = 0;
let maxUnlock = 0;

console.log('idx term  iters        lock    unlock  loose real     op-cost   fits');
for (const c of vectors.chunks) {
  const locking = hexToBin(c.locking);
  const unlocking = hexToBin(c.unlocking);
  const loose = evaluatePair(loosened, locking, unlocking);
  const realR = evaluatePair(real, locking, unlocking);
  const fits =
    locking.length <= 10_000 &&
    unlocking.length <= 10_000 &&
    realR.operationCost <= BUDGET &&
    realR.accepted;

  totalOp += realR.operationCost;
  maxOp = Math.max(maxOp, realR.operationCost);
  maxLock = Math.max(maxLock, locking.length);
  maxUnlock = Math.max(maxUnlock, unlocking.length);
  if (!fits) allFit = false;
  if (!loose.accepted) allLoose = false;
  if (!realR.accepted) allReal = false;

  console.log(
    `${String(c.idx).padStart(3)}  ${c.term === 0 ? 'IC1' : 'IC2'}  ` +
      `[${String(c.lo).padStart(3)},${String(c.hi).padStart(3)})  ` +
      `${String(locking.length).padStart(5)}B  ${String(unlocking.length).padStart(5)}B  ` +
      `${loose.accepted ? 'OK ' : 'X  '}  ${realR.accepted ? 'OK ' : 'X  '}  ` +
      `${realR.operationCost.toLocaleString().padStart(11)}  ${fits ? 'Y' : 'N'}` +
      `${c.final ? '  <- inverse->affine, assert vk_x' : c.fold ? '  <- fold acc+=R' : ''}` +
      `${realR.error ? '  realerr:' + realR.error : ''}`,
  );
}

console.log();
console.log('--- chain checks ---');
let continuity = true;
for (let i = 0; i < vectors.chunks.length - 1; i++) {
  if (vectors.chunks[i]!.outgoing !== vectors.chunks[i + 1]!.incoming) {
    continuity = false;
    console.log(`  CONTINUITY BREAK at chunk ${i} -> ${i + 1}`);
  }
}
console.log('  outgoing[i] == incoming[i+1] (state carried forward):', continuity);
const finalOutgoing = vectors.chunks[vectors.chunks.length - 1]!.outgoing;
console.log('  final chunk has no outgoing commitment (does inverse instead):', finalOutgoing === null);
const matchesPyEcc =
  BigInt(vectors.expected[0]) === BigInt(ref.expected[0]) &&
  BigInt(vectors.expected[1]) === BigInt(ref.expected[1]);
console.log('  final expected vk_x == py_ecc reference:', matchesPyEcc);

// tamper: perturb one byte of a middle chunk's arg region -> wrong incoming state.
const tIdx = Math.floor(vectors.chunks.length / 2);
const tch = vectors.chunks[tIdx]!;
const tLock = hexToBin(tch.locking);
const tUnlock = Uint8Array.from(hexToBin(tch.unlocking));
tUnlock[1] = tUnlock[1]! ^ 0x01; // flip a bit inside the first coord push payload
const tampered = evaluatePair(real, tLock, tUnlock);
console.log(`  tampered chunk ${tIdx} rejected on real VM:`, !tampered.accepted, `(err: ${tampered.error ?? 'none'})`);

console.log();
console.log('--- summary ---');
console.log(`chunks                : ${vectors.numChunks} (K=${vectors.K})`);
console.log(`max lock / unlock     : ${maxLock}B / ${maxUnlock}B (both <= 10,000)`);
console.log(`max step op-cost      : ${maxOp.toLocaleString()}  (budget ${BUDGET.toLocaleString()})`);
console.log(`total op-cost (chain) : ${totalOp.toLocaleString()}  (singleton vk_x ~76,004,958)`);
console.log(`every chunk loose-OK  : ${allLoose}`);
console.log(`every chunk real-OK   : ${allReal}`);
console.log(`EVERY chunk fits ONE input (op-cost <= budget AND real-VM-valid): ${allFit}`);
console.log(`chain continuous      : ${continuity}`);
console.log(`reproduces py_ecc vk_x: ${matchesPyEcc}`);
