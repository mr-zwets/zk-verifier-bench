// Verification harness for the real sCrypt BN256 Groth16 verifier (BSV mainnet):
// feed it the genuine on-chain proof and tampered proofs, and show it accepts the
// first and rejects the rest, on libauth's BCH 2026 VM (limits loosened).
//
// Caveat: this verifier ends in a reachable OP_RETURN. On BSV (post-Genesis)
// OP_RETURN terminates the script as SUCCESS; on BCH OP_RETURN is a hard failure.
// The verification logic itself runs identically (no introspection,
// signatureCheckCount=0): for a VALID proof every OP_*VERIFY check passes and the
// script reaches OP_RETURN with TRUE on the stack; for an INVALID proof an
// OP_*VERIFY fails earlier. We judge acceptance by BSV semantics (reached the
// OP_RETURN terminator with a truthy top) and also show that stripping the
// trailing OP_RETURN makes the verifier accept cleanly on the BCH VM too.
import { readFileSync } from 'node:fs';
import { createTestAuthenticationProgramBch, decodeTransactionBch, hexToBin, OpcodesBch } from '@bitauth/libauth';

import { createLoosenedVm } from '../harness/vm.js';
import { tamperProof } from '../harness/tamper.js';

const decode = (path: string) => {
  const tx = decodeTransactionBch(hexToBin(readFileSync(path, 'utf8').trim()));
  if (typeof tx === 'string') throw new Error(`decode ${path}: ${tx}`);
  return tx;
};

const verifier = decode('data/scrypt-bn256/parent-tx.hex').outputs[0]!.lockingBytecode;
const realProof = decode('data/scrypt-bn256/spending-tx.hex').inputs[0]!.unlockingBytecode;

const OP_RETURN_ERR = 'Program called an OP_RETURN operation.';
const vm = createLoosenedVm();

// Bitcoin "truthy": non-empty and not all-zero (last byte 0x80 = negative zero is false).
const isTruthy = (v: Uint8Array | undefined): boolean =>
  v !== undefined && v.length > 0 && !v.every((b, i) => b === 0 || (i === v.length - 1 && b === 0x80));

const evalScript = (locking: Uint8Array, unlocking: Uint8Array) => {
  const state = vm.evaluate(
    createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }),
  );
  const top = state.stack[state.stack.length - 1];
  return {
    error: state.error,
    single: state.stack.length === 1,
    topTruthy: isTruthy(top),
    opCost: state.metrics.operationCost,
  };
};

// BSV post-Genesis OP_RETURN rule: success iff a SINGLE non-zero stack item,
// reached by clean exit or by halting at OP_RETURN.
const accepts = (locking: Uint8Array, unlocking: Uint8Array) => {
  const r = evalScript(locking, unlocking);
  const ok = r.single && r.topTruthy && (r.error === undefined || r.error === OP_RETURN_ERR);
  return { ...r, ok };
};

const check = (label: string, unlocking: Uint8Array) => {
  const r = accepts(verifier, unlocking);
  console.log(`${r.ok ? 'ACCEPT' : 'REJECT'}  ${label}`);
  console.log(`        op-cost ${r.opCost.toLocaleString()}, halt: ${r.error ?? 'clean exit'}`);
  return r.ok;
};

console.log('sCrypt BN256 Groth16 verifier (BSV mainnet), real proof vs tampered proofs:\n');
check('genuine mainnet proof', realProof);
check('proof, 1 bit flipped in largest push', tamperProof(realProof, 0));
check('proof, 1 bit flipped in 2nd-largest push', tamperProof(realProof, 1));
check('proof, 1 bit flipped in 3rd-largest push', tamperProof(realProof, 2));

// Show the verification logic also accepts cleanly on BCH once the trailing
// BSV OP_RETURN terminator is removed (if the script ends in OP_RETURN).
const endsInOpReturn = verifier[verifier.length - 1] === OpcodesBch.OP_RETURN;
console.log(`\nverifier ends in OP_RETURN: ${endsInOpReturn}`);
if (endsInOpReturn) {
  const stripped = verifier.slice(0, verifier.length - 1);
  const r = evalScript(stripped, realProof);
  console.log(
    `with trailing OP_RETURN stripped -> ${r.error === undefined && r.topTruthy ? 'clean ACCEPT on BCH VM' : `error: ${r.error}`}`,
  );
}
