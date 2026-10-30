#!/usr/bin/env node
// Standalone positive-only replay. It consumes packaged program bodies and the
// one retained positive context. The context stores only the original argument
// and padding prefix, not a duplicate old redeem body.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [artifactDir, contextPath, libauthModulePath, outputPath] = process.argv.slice(2);
if (!artifactDir || !contextPath || !libauthModulePath || !outputPath) {
  throw new Error('usage: replay-pinned-libauth-v1.mjs ARTIFACT_DIR EXISTING_CONTEXT LIBAUTH_MODULE OUTPUT');
}
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const hashFile = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const hexToBin = (hex) => Uint8Array.from(Buffer.from((hex || '').replace(/^0x/, ''), 'hex'));
const binToHex = (bin) => Buffer.from(bin).toString('hex');
const pin = readJson(join(artifactDir, 'libauth-pin.json'));
if (hashFile(libauthModulePath) !== pin.moduleSha256) throw new Error('caller-pinned libauth hash mismatch');
const L = await import(pathToFileURL(libauthModulePath));
const context = readJson(contextPath);
const bodies = readJson(join(artifactDir, 'program-bodies.json'));
if (context.numSteps !== 14 || context.steps.length !== 14 || bodies.programs.length !== 14) throw new Error('expected exactly 14 existing stages');

const programs = bodies.programs.map((program) => {
  const body = hexToBin(program.bodyHex);
  if (hashFileFromBytes(body) !== program.programSha256 || body.length !== program.programBytes) throw new Error(`compiled body mismatch at ${program.input}`);
  const locking = L.encodeLockingBytecodeP2sh32(L.hash256(body));
  if (binToHex(locking) !== program.locking) throw new Error(`P2SH locking mismatch at ${program.input}`);
  return { ...program, body, locking: binToHex(locking) };
});

function hashFileFromBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
function token(category, capability, commitment) {
  return { amount: 0n, category, nft: { capability, commitment } };
}
function accepted(state) {
  return state.error === undefined && state.stack.length === 1 && state.stack[0]?.length === 1 && state.stack[0][0] === 1;
}
function errorSummary(error) { return error === undefined || error === null ? null : String(error); }

const standardVm = L.createVirtualMachineBch2026(true);
const consensusVm = L.createVirtualMachineBch2026(false);
const rows = context.steps.map((step, index) => {
  const program = programs[index];
  if (!step.unlockingPrefix) throw new Error('missing packaged unlocking prefix at ' + index);
  const prefix = hexToBin(step.unlockingPrefix);
  const unlocking = Uint8Array.from([...prefix, ...L.encodeDataPush(program.body)]);
  const category = hexToBin(step.covenant.category);
  const inCommitment = hexToBin(step.covenant.inCommitment || '');
  const outCommitment = hexToBin(step.covenant.outCommitment || '');
  const nextLocking = hexToBin(index < 13 ? programs[index + 1].locking : program.locking);
  const outputs = index === 0
    ? [
        { lockingBytecode: nextLocking, valueSatoshis: 1000n, token: token(category, 'mutable', outCommitment) },
        { lockingBytecode: hexToBin(program.locking), valueSatoshis: 1000n, token: token(category, 'minting', new Uint8Array(0)) },
      ]
    : [{ lockingBytecode: nextLocking, valueSatoshis: 1000n, token: token(category, step.covenant.capability, outCommitment) }];
  const vmProgram = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: hexToBin(program.locking), valueSatoshis: index === 0 ? 3000n : 1000n, token: token(category, index === 0 ? 'minting' : 'mutable', inCommitment) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs,
      locktime: 0,
    },
  };
  const standard = standardVm.evaluate(vmProgram);
  const consensus = consensusVm.evaluate(vmProgram);
  return {
    index,
    label: step.label,
    programSha256: program.programSha256,
    repairedLocking: program.locking,
    repairedSuccessorLocking: index < 13 ? programs[index + 1].locking : program.locking,
    originalPrefixBytes: prefix.length,
    repairedUnlockingBytes: unlocking.length,
    standard: { accepted: accepted(standard), error: errorSummary(standard.error), stackDepth: standard.stack.length },
    consensus: { accepted: accepted(consensus), error: errorSummary(consensus.error), stackDepth: consensus.stack.length, operationCost: consensus.metrics?.operationCost ?? null },
  };
});
const allStandardAccepted = rows.every((row) => row.standard.accepted);
const allConsensusAccepted = rows.every((row) => row.consensus.accepted);
const result = {
  schema: 'source6-raw14-standalone-pinned-libauth-replay/v2',
  status: allStandardAccepted && allConsensusAccepted ? 'PASS_ALL14_STANDARD_AND_CONSENSUS' : 'FAIL_ALL14_STANDARD_AND_CONSENSUS',
  policy: { existingContextOnly: true, contextPrefixOnly: true, producerExecuted: false, proverExecuted: false, compilerExecuted: false, generatorImported: false, negativeCases: false, newProofGenerated: false, optimization: false },
  pins: {
    // Keep the receipt portable: these are package-relative logical owners,
    // never the caller's checkout path.
    artifactDirectory: 'public-artifact',
    context: 'public-artifact/existing-positive-context.json',
    contextSha256: hashFile(contextPath),
    libauthModule: pin.moduleFilename,
    libauthModuleSha256: pin.moduleSha256,
  },
  rows,
  qualification: {
    standardVmAll14Accepted: allStandardAccepted,
    consensusVmAll14Accepted: allConsensusAccepted,
    full14PositiveReplay: allStandardAccepted && allConsensusAccepted,
    theoremTransfer: 'This receipt validates execution of the packaged repaired graph on the retained positive context; the separate conditional equation and ledger/domain premises remain required.',
  },
};
writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
