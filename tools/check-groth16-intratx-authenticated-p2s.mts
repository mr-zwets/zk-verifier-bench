// Checker for src/bch/groth16-intratx-authenticated-p2s-vectors.json.
//
// Asserts STRUCTURE (byte totals are computed and printed, not hardcoded):
//   - every valid run has the same step count as the primary run (invalid fixtures may
//     intentionally isolate a shorter stage graph);
//   - every locking is the 44-byte bare dispatcher
//     76aa20<hash256(body)>8802e7038902e7038a;
//   - every run's every stage body (final push of the unlocking) hashes to the
//     digest committed by that input's dispatcher — EXCEPT the tampered steps of
//     the modified-body / wrong-stage-body invalid runs, which must MISMATCH;
//   - no stage body defines the dispatcher's reserved function identifier 999;
//   - computed primary script bytes match the json's totalBytes metadata.
//
// Run: pnpm exec tsx tools/check-groth16-intratx-authenticated-p2s.mts
import { readFileSync } from 'node:fs';

import {
  binToHex,
  decodeAuthenticationInstructions,
  hash256,
  hexToBin,
} from '@bitauth/libauth';

type RawStep = { label: string; locking: string; unlocking: string; checkpoint?: string };
type Vectors = {
  totalBytes: number;
  steps: RawStep[];
  extraValidProofs: RawStep[][];
  worstCaseProof: RawStep[];
  invalid: RawStep[][];
};

const vectors = JSON.parse(
  readFileSync('src/bch/groth16-intratx-authenticated-p2s-vectors.json', 'utf8'),
) as Vectors;

const stepCount = vectors.steps.length;

const runs = [
  { name: 'steps', steps: vectors.steps, fullLength: true },
  ...vectors.extraValidProofs.map((steps, i) => ({ name: `extraValidProofs[${i}]`, steps, fullLength: true })),
  { name: 'worstCaseProof', steps: vectors.worstCaseProof, fullLength: true },
  ...vectors.invalid.map((steps, i) => ({ name: `invalid[${i}]`, steps, fullLength: false })),
];

const bodyOf = (unlockingHex: string, where: string): Uint8Array => {
  const last = decodeAuthenticationInstructions(hexToBin(unlockingHex)).at(-1);
  if (last === undefined || !('data' in last)) throw new Error(`${where}: final instruction is not a data push`);
  return last.data as Uint8Array;
};

let checkedBodies = 0;
let expectedMismatches = 0;
let lockingBytes = 0;
let unlockingBytes = 0;
let maxUnlockingBytes = 0;

for (const run of runs) {
  if (run.fullLength && run.steps.length !== stepCount)
    throw new Error(`${run.name}: expected ${stepCount} steps, found ${run.steps.length}`);
  if (run.steps.length === 0) throw new Error(`${run.name}: empty run`);

  run.steps.forEach((step, index) => {
    const where = `${run.name}[${index}]`;
    if (
      step.locking.length !== 88 ||
      !step.locking.startsWith('76aa20') ||
      !step.locking.endsWith('8802e7038902e7038a')
    )
      throw new Error(`${where}: locking is not the 44-byte authenticated P2S dispatcher`);

    const committed = step.locking.slice(6, 70);
    const body = bodyOf(step.unlocking, where);
    const actual = binToHex(hash256(body));

    // Tampered steps of the two body-tamper invalid runs are the only allowed mismatches.
    const tampered = run.name.startsWith('invalid') && step.label.includes('(invalid:');
    if (tampered) {
      if (actual === committed) throw new Error(`${where}: tampered body unexpectedly matches digest`);
      expectedMismatches += 1;
    } else if (actual !== committed) {
      throw new Error(`${where}: body hash mismatch\nexpected: ${committed}\nactual:   ${actual}`);
    }

    // Reserved dispatcher identifier: no body may define 999 (push e703 + OP_DEFINE).
    const ins = decodeAuthenticationInstructions(body);
    for (let i = 1; i < ins.length; i++) {
      const prev = ins[i - 1]!;
      if (ins[i]!.opcode === 0x89 && 'data' in prev && binToHex(prev.data) === 'e703')
        throw new Error(`${where}: body defines reserved function identifier 999`);
    }

    if (run.name === 'steps') {
      lockingBytes += step.locking.length / 2;
      unlockingBytes += step.unlocking.length / 2;
      maxUnlockingBytes = Math.max(maxUnlockingBytes, step.unlocking.length / 2);
    }
    checkedBodies += 1;
  });
}

if (expectedMismatches !== 3)
  throw new Error(`expected 3 tampered bodies (1 modified + 2 swapped), found ${expectedMismatches}`);

const scriptBytes = lockingBytes + unlockingBytes;
if (scriptBytes !== vectors.totalBytes)
  throw new Error(`script bytes ${scriptBytes} != vectors.totalBytes ${vectors.totalBytes}`);

// Serialized intra-tx overhead, mirroring the harness model (benchmark.ts stepTxOverhead):
// shared envelope + varints + OP_RETURN verdict output on input 0; outpoint + sequence +
// unlocking-length varint per input.
const varintLen = (n: number): number => (n < 0xfd ? 1 : n <= 0xffff ? 3 : 5);
const txOverhead =
  8 + varintLen(stepCount) + varintLen(1) + (8 + varintLen(1) + 1) +
  vectors.steps.reduce((t, s) => t + 36 + 4 + varintLen(s.unlocking.length / 2), 0);

console.log(JSON.stringify({
  runCount: runs.length,
  stepCount,
  checkedBodies,
  tamperedBodiesRejectedByDigest: expectedMismatches,
  lockingBytes,
  unlockingBytes,
  maxUnlockingBytes,
  scriptBytes,
  txOverheadBytes: txOverhead,
  score: scriptBytes + txOverhead,
  allStageBodiesAuthenticated: true,
}, null, 2));
