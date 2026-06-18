// Validate the checkpoint library and print the two golden values. Uses a
// constructed BN254 instance (algebraic, not a real SNARK proof) so the checkpoint
// computations are exercised end-to-end without a trusted setup: we pick the VK/
// proof points so the Groth16 product collapses to the identity exactly when the
// public inputs are the intended ones.
import { strict as assert } from 'node:assert';
import { bn254 } from '@noble/curves/bn254.js';

import { checkpointsFor, computeVkX, g1Hex, verify, type Proof, type VerifyingKey } from './bn254.js';

const g1 = (k: bigint) => bn254.G1.Point.BASE.multiply(k);
const g2 = (k: bigint) => bn254.G2.Point.BASE.multiply(k);

// ---- checkpoint #1: vk_x = IC[0] + Σ inputs[i]·IC[i+1] ----
const ic = [g1(11n), g1(22n), g1(33n)]; // IC[0..2] => 2 public inputs
const inputs = [7n, 9n];
const vkX = computeVkX(ic, inputs);
const manual = ic[0]!.add(ic[1]!.multiply(inputs[0]!)).add(ic[2]!.multiply(inputs[1]!));
assert.equal(g1Hex(vkX), g1Hex(manual), 'checkpoint #1: vk_x MSM matches manual');

// ---- constructed passing Groth16-form instance ----
// With beta = gamma = delta = Q, the product is e(-A + alpha + vk_x + C, Q); pick A
// so that (-A + alpha + vk_x + C) = O, making the product the Fp12 identity (verify=true).
const Q = g2(5n);
const alpha = g1(3n);
const C = g1(4n);
const A = alpha.add(vkX).add(C); // -A + alpha + vk_x + C = O
const vk: VerifyingKey = { alpha, beta: Q, gamma: Q, delta: Q, ic };
const proof: Proof = { a: A, b: Q, c: C };

const cp = checkpointsFor(vk, proof, inputs);
assert.equal(cp.verified, true, 'finalExponentiate(miller boundary) == 1');
assert.equal(verify(vk, proof, inputs), true, 'verify() accepts the valid instance');
assert.equal(verify(vk, proof, [7n, 10n]), false, 'verify() rejects a tampered public input');

console.log('BN254 Groth16 checkpoints (constructed instance):\n');
console.log('checkpoint #1  vk_x (G1 affine x,y):');
console.log('  ' + cp.vkXHex);
console.log('checkpoint #2  Miller -> finalExp boundary (Fp12, 384B hex):');
console.log('  ' + cp.millerHex.slice(0, 64) + '… (' + cp.millerHex.length / 2 + ' bytes)');
console.log('\nverify (valid proof):      ', verify(vk, proof, inputs) ? 'ACCEPT' : 'REJECT');
console.log('verify (tampered input):   ', verify(vk, proof, [7n, 10n]) ? 'ACCEPT' : 'REJECT');
console.log('finalExp(checkpoint #2)==1:', cp.verified);
console.log('\nall checkpoint assertions passed.');
