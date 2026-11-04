import fs from 'node:fs';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

const [artifactDir, contextPath, libauthPath, outputPath] = process.argv.slice(2);
if (!artifactDir || !contextPath || !libauthPath || !outputPath) {
  throw new Error('usage: node replay.mjs ARTIFACT_DIR CONTEXT LIBAUTH_ENTRY OUTPUT');
}
const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const artifact = (name) => `${artifactDir}/${name}`;
const context = readJson(contextPath);
const catalog = readJson(artifact('compiled-catalog.json'));
const entryBytes = fs.readFileSync(libauthPath);
const entrySha256 = crypto.createHash('sha256').update(entryBytes).digest('hex');
if (entrySha256 !== catalog.vm.libauthEntrySha256) throw new Error(`libauth entry hash mismatch: ${entrySha256}`);
const libauth = await import(pathToFileURL(libauthPath).href);
const {
  ConsensusBch2025,
  createInstructionSetBch2026,
  createVirtualMachine,
  createVirtualMachineBch2026,
  hexToBin,
  ripemd160,
  secp256k1,
  sha1,
  sha256,
} = libauth;
const profile = catalog.profiles[context.curve];
if (!profile || profile.count !== context.stages || profile.programs.length !== context.stages) throw new Error('catalog/context stage count mismatch');
const programs = profile.programs.slice().sort((a, b) => a.input - b.input);
const HUGE = Number.MAX_SAFE_INTEGER;
const loosenedConsensusBch2026 = {
  ...ConsensusBch2025,
  baseInstructionCost: 100,
  maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE,
  maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE,
  maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE,
  maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE,
  maximumOperationCount: HUGE,
};
const createLoosenedVm = () => createVirtualMachine(createInstructionSetBch2026(false, {
  consensus: loosenedConsensusBch2026, ripemd160, secp256k1, sha1, sha256,
}));
const pushHex = (hex) => {
  const bytes = hex.length / 2;
  if (bytes <= 75) return bytes.toString(16).padStart(2, '0') + hex;
  if (bytes <= 0xffff) return `4d${bytes.toString(16).padStart(4, '0').match(/../g).reverse().join('')}${hex}`;
  throw new Error(`program too large: ${bytes}`);
};
const doubleSha256Hex = (hex) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(Buffer.from(hex, 'hex')).digest()).digest('hex');
const evaluatePair = (vm, lockingBytecode, unlockingBytecode, c) => {
  const token = (capability, commitment) => ({ amount: 0n, category: c.category, nft: { capability, commitment } });
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode, valueSatoshis: 1000n, token: token(c.capability, c.inCommitment) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode }],
      outputs: [{ lockingBytecode: c.outLockingBytecode, valueSatoshis: 1000n, token: token(c.capability, c.outCommitment) }],
      locktime: 0,
    },
  };
  const state = vm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top?.length === 1 && top[0] === 1;
  return { accepted, error: state.error ?? null, operationCost: state.metrics.operationCost, instructionCount: state.metrics.evaluatedInstructionCount };
};
const modes = [['loosened', createLoosenedVm], ['consensus', () => createVirtualMachineBch2026(false)], ['standard', () => createVirtualMachineBch2026(true)]];
const rows = [];
for (const run of context.runs) {
  if (run.steps.length !== programs.length) throw new Error(`run ${run.name} stage count mismatch`);
  for (const [mode, makeVm] of modes) {
    const vm = makeVm();
    run.steps.forEach((step, index) => {
      const p = programs[index];
      const bodySha = crypto.createHash('sha256').update(Buffer.from(p.programHex, 'hex')).digest('hex');
      if (bodySha !== p.programSha256) throw new Error(`program hash mismatch ${context.curve}:${index}`);
      if (!p.locking.startsWith('aa20') || !p.locking.endsWith('87') || doubleSha256Hex(p.programHex) !== p.locking.slice(4, -2)) throw new Error(`P2SH hash mismatch ${context.curve}:${index}`);
      const unlockingHex = `${step.paddingPushHex}${step.argumentScriptHex}${pushHex(p.programHex)}`;
      const next = programs[index + 1] ?? p;
      const outcome = evaluatePair(vm, hexToBin(p.locking), hexToBin(unlockingHex), {
        category: hexToBin(step.category), capability: step.capability,
        inCommitment: hexToBin(step.incoming.commitment), outCommitment: hexToBin(step.outgoing.commitment),
        outLockingBytecode: hexToBin(next.locking),
      });
      rows.push({ run: run.name, mode, index, label: step.label, accepted: outcome.accepted, error: outcome.error, operationCost: outcome.operationCost, instructionCount: outcome.instructionCount, unlockingBytes: unlockingHex.length / 2, programBytes: p.programBytes });
    });
  }
}
const summary = modes.map(([mode]) => {
  const rs = rows.filter((r) => r.mode === mode); const failed = rs.filter((r) => !r.accepted);
  return { mode, evaluated: rs.length, accepted: rs.length - failed.length, failed: failed.length, firstFailure: failed[0] ?? null };
});
const policyError = /maximum bytecode length|operation cost|maximum stack|maximum memory|maximum operation count/i;
const policyFailures = rows.filter((r) => r.mode !== 'loosened' && !r.accepted);
const loosenedPass = rows.filter((r) => r.mode === 'loosened').every((r) => r.accepted);
const result = {
  schema: 'source4-positive-candidate-replay/v2',
  status: loosenedPass && policyFailures.every((r) => policyError.test(r.error ?? '')) ? 'PASS_LOOSENED_EXISTING_POSITIVES_WITH_POLICY_HOLDS' : 'FAIL_CANDIDATE_POSITIVE_REQUIRES_DIAGNOSIS',
  scope: `${context.curve} historical ${context.stages}-stage existing positive graphs only`,
  constraints: { existingFixtureOnly: true, negativeCases: 0, newProofs: 0, cybersecurityTesting: false, byteOptimization: false },
  libauth: { entry: 'external caller-pinned entry', entrySha256 },
  fixtureProvenance: context.fixtureProvenance,
  candidate: { context: contextPath.split('/').pop(), runs: context.runs.length, compiledGraphPrograms: programs.length },
  summary,
  rows,
  qualification: 'Positive evidence for the corrected finite compiled graph and supplied covenant contexts. Consensus/standard failures matching explicit resource-hold patterns are policy qualifications, not mathematical failures. This does not establish neutral/infinity domains, unrestricted keys, setup/ZK, or mainnet admission.',
};
fs.writeFileSync(outputPath, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ status: result.status, summary }));
