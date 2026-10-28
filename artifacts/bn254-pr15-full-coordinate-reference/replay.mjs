import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const [benchmarkRepo, reportPath] = process.argv.slice(2);
if (!benchmarkRepo || !reportPath) {
  throw new Error('usage: node replay.mjs <benchmark-repo> <new-report>');
}

const require = createRequire(resolve(benchmarkRepo, 'package.json'));
const {
  ConsensusBch2025,
  createInstructionSetBch2026,
  createTestAuthenticationProgramBch,
  createVirtualMachine,
  createVirtualMachineBch2026,
  ripemd160,
  secp256k1,
  sha1,
  sha256,
} = await import(require.resolve('@bitauth/libauth'));

const here = new URL('.', import.meta.url);
const read = name => readFileSync(new URL(name, here));
const sha = value => createHash('sha256').update(value).digest('hex');
const bytes = hex => Uint8Array.from(Buffer.from(hex.trim(), 'hex'));
const hex = value => Buffer.from(value).toString('hex');
const accepted = state => state.error === undefined && state.stack.length === 1 && state.stack[0]?.length === 1 && state.stack[0][0] === 1;
const huge = Number.MAX_SAFE_INTEGER;

const program = read('verifier-4681.hex');
assert.equal(program.length, 9363, 'program hex file length');
const locking = bytes(program.toString('utf8'));
assert.equal(locking.length, 4681, 'locking byte length');
assert.equal(sha(locking), 'dc2b929c5645d3baaac4fb544ba7565bf54c34156532a715053432d4f9913782', 'locking SHA-256');

const fixture = JSON.parse(read('four-positive-unlockings.json'));
assert.equal(fixture.cases.length, 4, 'exactly four archived positive unlockings');
const seen = new Set();
for (const item of fixture.cases) {
  assert.match(item.name, /^(primary|extra-[0-2])$/);
  assert(!seen.has(item.name), `duplicate fixture ${item.name}`);
  seen.add(item.name);
}

const loosenedConsensus = {
  ...ConsensusBch2025,
  baseInstructionCost: 100,
  maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: huge,
  maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: huge,
  maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: huge,
  maximumStackItemLength: huge,
  maximumVmNumberByteLength: huge,
  maximumStackDepth: huge,
  maximumControlStackDepth: huge,
  maximumBytecodeLength: huge,
  maximumOperationCount: huge,
};
const vms = {
  officialArithmeticOracle: createVirtualMachine(createInstructionSetBch2026(false, {
    consensus: loosenedConsensus,
    ripemd160,
    secp256k1,
    sha1,
    sha256,
  })),
  declaredBch2026Consensus: createVirtualMachineBch2026(false),
  declaredBch2026Standard: createVirtualMachineBch2026(true),
};

const evaluate = (vm, unlocking) => {
  const state = vm.evaluate(createTestAuthenticationProgramBch({
    lockingBytecode: locking,
    unlockingBytecode: unlocking,
    valueSatoshis: 1000n,
  }));
  return {
    accepted: accepted(state),
    error: state.error?.toString?.() ?? null,
    operationCost: state.metrics?.operationCost ?? null,
    instructionCount: state.metrics?.evaluatedInstructionCount ?? null,
  };
};

const results = [];
for (const item of fixture.cases) {
  const unlocking = bytes(item.unlocking);
  const witnessSha256 = sha(unlocking);
  for (const [mode, vm] of Object.entries(vms)) {
    results.push({
      fixture: item.name,
      mode,
      witnessSha256,
      witnessBytes: unlocking.length,
      contextSha256: sha(Buffer.concat([Buffer.from(locking), Buffer.from(unlocking)])),
      ...evaluate(vm, unlocking),
    });
  }
}

const arithmetic = results.filter(result => result.mode === 'officialArithmeticOracle');
const consensus = results.filter(result => result.mode === 'declaredBch2026Consensus');
const standard = results.filter(result => result.mode === 'declaredBch2026Standard');
const report = {
  schema: 'source15-benchmark32-full-coordinate-positive-replay/v1',
  status: arithmetic.every(result => result.accepted)
    ? 'PASS_FOUR_UNCHANGED_POSITIVES_ARITHMETIC_ORACLE_NATIVE_HOLD'
    : 'FAIL_UNCHANGED_POSITIVE_ARITHMETIC_REPLAY',
  historicalAttribution: {
    sourcePr: '15',
    benchmarkPr: '32',
    sourceHead: '1e7c52ab3b6af132c3f3f87effd38821828c874d',
    benchmarkHead: 'aede1967237b3d7e28f9ca74ab52232e7e6d5421',
    fixtureSelection: 'primary plus the three uncommitted multiproof positives from the archived PR32 fixture set',
  },
  artifact: {
    path: 'verifier-4681.hex',
    bytes: locking.length,
    sha256: sha(locking),
  },
  vm: {
    implementation: '@bitauth/libauth direct BCH2026 VM constructors resolved through benchmark-repo/package.json',
    packageVersion: '3.1.0-next.8',
    packageSha256: '6b4e3b7f062b80782c62cb7732ed01571c5f163fd786af877c0ae5fdc33ec65e',
    entrySha256: 'c5dd3af1177e6f0457e80ee5984a315617856e39bf9e72987b0f91c76ff91a0d',
  },
  results,
  summary: {
    fixtureCount: fixture.cases.length,
    arithmeticOracle: { accepted: arithmetic.filter(result => result.accepted).length, total: arithmetic.length },
    declaredBch2026Consensus: { accepted: consensus.filter(result => result.accepted).length, total: consensus.length },
    declaredBch2026Standard: { accepted: standard.filter(result => result.accepted).length, total: standard.length },
  },
  restrictions: [
    'existing positive unlockings only',
    'no invalid or negative cases',
    'no proof generation, mutation, auxiliary reencoding, or optimization',
    'arithmetic oracle acceptance is mathematical execution evidence only',
    'native BCH2026 resource admission remains HOLD',
  ],
};
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
console.log(JSON.stringify({ status: report.status, summary: report.summary }, null, 2));
