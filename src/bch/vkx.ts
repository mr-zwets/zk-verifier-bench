// Groth16 verifier CHECKPOINT #1 -- vk_x public-input aggregation -- on the BCH VM.
//
//   vk_x = IC0 + input0*IC1 + input1*IC2   (G1 points on BN254/alt_bn128)
//
// The contract (groth16_contract/vkx.cash) is compiled by the local cashc
// `feat/reusable-functions` build: the scalar Fp ops (addFp/subFp/mulFp/negFp/
// sqrFp/inverseFp) are user-defined functions lowered to OP_DEFINE/OP_INVOKE,
// while the Jacobian-projective point doubling/addition and the double-and-add
// scalar multiply are inlined in the spending function (one final modular
// inverse converts the result back to affine). VK IC points are hardcoded; the
// spender supplies input0/input1 and the claimed expected affine point.
//
// This script evaluates the accept (correct expected) and reject (wrong
// expected) cases on libauth's BCH 2026 VM -- loosened for correctness, real
// for the consensus verdict -- and reports operation cost, byte sizes, and how
// many BCH inputs the op-cost requires (the headline step count).
//
// Regenerate the locking/unlocking bytecode + py_ecc reference with:
//   (groth16_contract) python vkx_ref.py
//   (cashscript)       node vkx_gen.mjs   ->  writes src/bch/vkx-vectors.json
import { hexToBin } from '@bitauth/libauth';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  createLoosenedVm,
  createRealVm,
  evaluatePair,
  realOpCostBudget,
  standardInputBudget,
  STANDARD_UNLOCKING_CAP,
} from '../harness/vm.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, 'vkx-vectors.json'), 'utf8')) as {
  lockingOK: string;
  lockingBAD: string;
  unlocking: string;
  bytesize: number;
  opcount: number;
  input0: number;
  input1: number;
  expected: [string, string];
};

const lockOK = hexToBin(vectors.lockingOK);
const lockBAD = hexToBin(vectors.lockingBAD);
const unlock = hexToBin(vectors.unlocking);

console.log('=== Groth16 checkpoint #1: vk_x = IC0 + input0*IC1 + input1*IC2 ===');
console.log('input0 =', vectors.input0, ' input1 =', vectors.input1);
console.log('expected vk_x (affine, from py_ecc.bn128):');
console.log('  x =', String(vectors.expected[0]));
console.log('  y =', String(vectors.expected[1]));
console.log('locking bytecode bytes  :', lockOK.length);
console.log('unlocking bytecode bytes:', unlock.length);
console.log();

// --- correctness on the loosened VM (limits removed, just measures math) ---
const loosened = createLoosenedVm();
const accept = evaluatePair(loosened, lockOK, unlock);
const reject = evaluatePair(loosened, lockBAD, unlock);

console.log('--- loosened BCH 2026 VM (correctness vs py_ecc) ---');
console.log('ACCEPT (correct expected): accepted =', accept.accepted, ' error =', accept.error ?? '(none)');
console.log('REJECT (wrong  expected): accepted =', reject.accepted, ' error =', reject.error ?? '(none)');
console.log('operationCost   :', accept.operationCost.toLocaleString());
console.log('instructionCount:', accept.instructionCount.toLocaleString());
console.log('arithmeticCost  :', accept.arithmeticCost.toLocaleString());
console.log('stackPushedBytes:', accept.stackPushedBytes.toLocaleString());
console.log();

// --- real BCH 2026 consensus verdict (single input) ---
const real = createRealVm();
const realAccept = evaluatePair(real, lockOK, unlock);
console.log('--- real BCH 2026 VM (consensus limits, single input) ---');
console.log('accepted =', realAccept.accepted, ' error =', realAccept.error ?? '(none)');
console.log('operationCost =', realAccept.operationCost.toLocaleString());
console.log();

// --- op-cost budget reasoning: how many BCH inputs does vk_x need? ---
const opCost = accept.operationCost;
const budgetThisInput = realOpCostBudget(unlock.length);
const budgetMaxInput = standardInputBudget();
const inputsNeeded = Math.ceil(opCost / budgetMaxInput);

console.log('--- BCH op-cost budget analysis ---');
console.log('measured vk_x op-cost            :', opCost.toLocaleString());
console.log('budget of THIS input (unlock=' + unlock.length + 'B):', budgetThisInput.toLocaleString());
console.log('budget at standard unlock cap (' + STANDARD_UNLOCKING_CAP + 'B):', budgetMaxInput.toLocaleString());
console.log('locking script <= 10,000 bytes   :', lockOK.length <= 10_000, `(${lockOK.length} B)`);
console.log('op-cost fits ONE input           :', opCost <= budgetMaxInput);
console.log('>>> inputsNeeded = ceil(opCost / budgetPerInput) =', inputsNeeded);
