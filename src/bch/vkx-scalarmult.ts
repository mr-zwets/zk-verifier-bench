// Per-scalar-multiplication checkpoint for the Groth16 vk_x aggregation: ONE
// double-and-add scalar multiply (input * IC, 254-bit) followed by ONE general
// Jacobian point addition into a Z != 1 accumulator, then the affine
// conversion. This is the natural sub-step of vk_x (vk_x needs two of them) and
// the unit a chunked, multi-input verifier would carry between inputs.
//
// Unlike the full single-tx vk_x contract (which trips a cashc
// feat/reusable-functions stack-cleanup codegen bug when two such loops are
// composed in one function), this isolated checkpoint compiles and runs
// correctly: it ACCEPTS the py_ecc-correct result and REJECTS a wrong one on
// libauth's BCH 2026 VM. Used to (a) prove the math end-to-end on the VM and
// (b) measure the op-cost of one scalarMult, from which the full vk_x cost and
// the chunk count follow.
import { hexToBin } from '@bitauth/libauth';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createLoosenedVm, createRealVm, evaluatePair, standardInputBudget } from '../harness/vm.js';

const here = dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(readFileSync(join(here, 'vkx-scalarmult-vectors.json'), 'utf8'));
const lockOK = hexToBin(v.lockingOK);
const lockBAD = hexToBin(v.lockingBAD);
const unlock = hexToBin(v.unlocking);

console.log('=== vk_x sub-checkpoint: one scalarMult + one Jacobian add ===');
console.log('locking bytes:', lockOK.length, ' unlocking bytes:', unlock.length);

const loose = createLoosenedVm();
const accept = evaluatePair(loose, lockOK, unlock);
const reject = evaluatePair(loose, lockBAD, unlock);
console.log('ACCEPT (py_ecc-correct):', accept.accepted, accept.error ?? '');
console.log('REJECT (wrong)         :', reject.accepted, reject.error ?? '');
console.log('operationCost  :', accept.operationCost.toLocaleString());
console.log('arithmeticCost :', accept.arithmeticCost.toLocaleString());

const real = createRealVm();
const r = evaluatePair(real, lockOK, unlock);
console.log('real BCH 2026 single-input accepted:', r.accepted, '| op-cost', r.operationCost.toLocaleString());
console.log('budget at standard unlock cap:', standardInputBudget().toLocaleString());
console.log('one scalarMult fits one input:', accept.operationCost <= standardInputBudget());
