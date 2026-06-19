// Compile every chunk*.cash in groth16_contract/chunked, build per-chunk
// (locking, unlocking) vectors, and measure op-cost + size on the real &
// loosened BCH 2026 VMs. Writes src/bch/vkx-chunked-shamir-vectors.json for the
// bch-vkx-chunked benchmark entry.
//
// Unlocking = the 9 incoming-state coords pushed in REVERSE declaration order
// (cashc function-arg convention): spend() declares
// (accX,accY,accZ,bX,bY,bZ,rX,rY,rZ) so the spender pushes
// rZ,rY,rX,bZ,bY,bX,accZ,accY,accX.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { hexToBin, binToHex, bigIntToVmNumber } from '@bitauth/libauth';
import { createLoosenedVm, createRealVm, evaluatePair, standardInputBudget } from '../harness/vm.js';

const CHUNKDIR = 'C:/Users/mathi/Desktop/groth16_contract/chunked/shamir';
const CASHC = 'C:/Users/mathi/Desktop/cashscript/packages/cashc/dist/cashc-cli.js';
const manifest = JSON.parse(readFileSync(`${CHUNKDIR}/manifest.json`, 'utf8')) as {
  K: number; numChunks: number; input0: number; input1: number; expected: [string, string];
  chunks: Array<{
    idx: number; file: string; term: number; lo: number; hi: number;
    fold: boolean; final: boolean; incoming: string; outgoing: string | null;
    incoming_state: string[];
  }>;
};

const looseVm = createLoosenedVm();
const realVm = createRealVm();
const BUDGET = standardInputBudget();

const pushData = (d: Uint8Array): Uint8Array => {
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  throw new Error('push too big');
};
const pushInt = (n: bigint): Uint8Array => pushData(bigIntToVmNumber(n));

const out = {
  K: manifest.K, numChunks: manifest.numChunks, input0: manifest.input0,
  input1: manifest.input1, expected: manifest.expected,
  chunks: [] as Array<Record<string, unknown>>,
};
let totalOp = 0, maxOp = 0, maxLock = 0, maxUnlock = 0;
let allAccept = true, allFit = true;

for (const ch of manifest.chunks) {
  const lockHex = execFileSync('node', [CASHC, `${CHUNKDIR}/${ch.file}`, '-h'], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }).trim();
  const locking = hexToBin(lockHex);
  const coords = ch.incoming_state.map((s) => BigInt(s)); // [accX..rZ]
  const reversed = [...coords].reverse(); // rZ..accX
  const unlocking = Uint8Array.from(reversed.flatMap((c) => [...pushInt(c)]));

  const loose = evaluatePair(looseVm, locking, unlocking);
  const real = evaluatePair(realVm, locking, unlocking);
  const fits = locking.length <= 10000 && unlocking.length <= 10000 && real.operationCost <= BUDGET && real.accepted;
  totalOp += real.operationCost; maxOp = Math.max(maxOp, real.operationCost);
  maxLock = Math.max(maxLock, locking.length); maxUnlock = Math.max(maxUnlock, unlocking.length);
  if (!fits) allFit = false;
  if (!loose.accepted || !real.accepted) allAccept = false;

  console.log(
    `chunk ${String(ch.idx).padStart(2)} term${ch.term} [${ch.lo},${ch.hi}) ` +
    `fold=${ch.fold ? 1 : 0} fin=${ch.final ? 1 : 0} | lock ${String(locking.length).padStart(5)}B ` +
    `unlock ${unlocking.length}B | loose=${loose.accepted ? 'OK' : 'X'} real=${real.accepted ? 'OK' : 'X'} ` +
    `op-cost ${real.operationCost.toLocaleString().padStart(11)} fits=${fits ? 'Y' : 'N'} ` +
    `${loose.error ?? ''}${real.error ? ' realerr:' + real.error : ''}`,
  );

  out.chunks.push({
    idx: ch.idx, file: ch.file, term: ch.term, lo: ch.lo, hi: ch.hi,
    fold: ch.fold, final: ch.final, incoming: ch.incoming, outgoing: ch.outgoing,
    locking: lockHex, unlocking: binToHex(unlocking),
    lockingBytes: locking.length, unlockingBytes: unlocking.length,
    operationCost: real.operationCost, accepted: real.accepted,
  });
}

console.log('---');
console.log(`chunks=${manifest.numChunks} K=${manifest.K} | total op-cost ${totalOp.toLocaleString()} | max/step ${maxOp.toLocaleString()} (budget ${BUDGET.toLocaleString()})`);
console.log(`max lock ${maxLock}B max unlock ${maxUnlock}B | allAccept=${allAccept} allFit=${allFit}`);

writeFileSync('src/bch/vkx-chunked-shamir-vectors.json', JSON.stringify(out, null, 2));
console.log('wrote src/bch/vkx-chunked-shamir-vectors.json');
