// Executes only the five unchanged archived positive singleton unlockings.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const [benchmark,output]=process.argv.slice(2);
assert(benchmark&&output&&process.argv.length===4,'usage: node replay.mjs benchmark-repo new-report.json');
const entry=createRequire(resolve(benchmark,'package.json')).resolve('@bitauth/libauth');
const lib=await import(pathToFileURL(entry).href);
const {ConsensusBch2025,createInstructionSetBch2026,createVirtualMachine,createVirtualMachineBch2026,createTestAuthenticationProgramBch,ripemd160,secp256k1,sha1,sha256}=lib;
const read=name=>readFileSync(new URL(name,import.meta.url));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

const packet=JSON.parse(read('./positive-reencoded.json')); packet.cases=packet.records.map(row=>({name:row.label,unlocking:row.unlocking}));
for(const row of packet.records){assert.equal(row.argumentCount,45);assert(row.removedWValues.length===6&&row.removedWValues.every(x=>x==='0'));assert(row.proofBytesPreserved&&row.publicInputBytesPreserved&&row.allRetainedBytesPreserved);}
const locking=Buffer.from(read('./program.hex').toString('utf8').trim(),'hex');
assert.equal(sha(locking),'42ca73a63775c062898e97ecde2b9a3d57b5f292d11677341a9fe5d6063ae0d3');assert.equal(packet.cases.length,5);
const HUGE=Number.MAX_SAFE_INTEGER;
const oracle=createVirtualMachine(createInstructionSetBch2026(false,{consensus:{...ConsensusBch2025,baseInstructionCost:100,maximumFunctionIdentifierLength:7,maximumMemorySlots:HUGE,maximumStandardLockingBytecodeLength:-1,maximumStandardUnlockingBytecodeLength:HUGE,maximumTokenCommitmentLength:128,operationCostBudgetPerByte:HUGE,maximumStackItemLength:HUGE,maximumVmNumberByteLength:HUGE,maximumStackDepth:HUGE,maximumControlStackDepth:HUGE,maximumBytecodeLength:HUGE,maximumOperationCount:HUGE},ripemd160,secp256k1,sha1,sha256}));
const modes=[['oracle',oracle],['consensus',createVirtualMachineBch2026(false)],['standard',createVirtualMachineBch2026(true)]];
const results=[];
for(const fixture of packet.cases){
  const unlocking=Buffer.from(fixture.unlocking,'hex');
  const program=createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:unlocking,valueSatoshis:1000n});
  const outcomes=[];
  for(const [mode,vm] of modes){
    const state=vm.evaluate(program);
    const accepted=!state.error&&state.stack.length===1&&Buffer.from(state.stack[0]).equals(Buffer.from([1]));
    outcomes.push({mode,accepted,error:state.error??null,operationCost:state.metrics.operationCost,finalStackItems:state.stack.length});
    if(mode==='oracle')assert(accepted,state.error??'false arithmetic verdict');
  }
  results.push({name:fixture.name,unlockingSha256:sha(unlocking),outcomes});
  console.log(JSON.stringify({name:fixture.name,outcomes}));
}
const report={schema:'bls-source5-minop45-positive-replay/v1',status:'PASS_EXISTING_POSITIVES_ARITHMETIC',node:process.version,vmPackageEntrySha256:sha(readFileSync(entry)),guardedSha256:sha(locking),positivePacketSha256:sha(read('./positive-reencoded.json')),replayToolSha256:sha(read('./replay.mjs')),results,existingPositiveProofs:results.length,oracleAccepted:results.filter(x=>x.outcomes.find(y=>y.mode==='oracle').accepted).length,consensusAccepted:results.filter(x=>x.outcomes.find(y=>y.mode==='consensus').accepted).length,standardAccepted:results.filter(x=>x.outcomes.find(y=>y.mode==='standard').accepted).length,scope:'Saved exact 45-argument BLS minop artifact. Five existing proof/public-input payloads, with only six proven-zero auxiliary limbs removed from the 51-argument transport. Resource-loosened oracle evidence and per-input native admission observations; no negative/new proof cases, whole-transaction/relay, producer, setup, or optimization claim.'};
writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({status:report.status,oracleAccepted:report.oracleAccepted,consensusAccepted:report.consensusAccepted,standardAccepted:report.standardAccepted}));
