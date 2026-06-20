import { readFileSync } from 'node:fs';
import { decodeTransactionBch, hexToBin } from '@bitauth/libauth';

import type { Implementation } from '../harness/types.js';

const decode = (path: string) => {
  const tx = decodeTransactionBch(hexToBin(readFileSync(path, 'utf8').trim()));
  if (typeof tx === 'string') throw new Error(`decode ${path}: ${tx}`);
  return tx;
};

// Real sCrypt Groth16 verifier from BSV mainnet (see data/scrypt-bn256/SOURCE.md).
// This is sCrypt's FIRST Groth16 verifier (Jul 2022), over BN256 / alt_bn128 /
// BN254 -- the same curve as the groth16_contract repo's BN256.cash -- distinct
// from their later BLS12-381 testnet line (data/scrypt). Verifier = parent tx
// vout[0] (the ~11.7 MB nonstandard locking script); proof = spending tx vin[0]
// (510 B). Run `pnpm fetch:scrypt-bn256` first if the .hex files are missing.
// Single-tx: the whole verify is one script.
export const scryptBn256: Implementation = {
  id: 'scrypt-bn256',
  name: 'sCrypt zkSNARK (Groth16)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  // proof (510 B) supplied push-only in the spending tx's unlocking script; the
  // locking verifier is fixed -> runtime-general (see data/scrypt-bn256/SOURCE.md).
  proofBinding: 'runtime',
  source: 'BSV mainnet tx 24e8...bf24 (proof) spending 320b...725f:0 (verifier)',
  load: async () => ({
    valid: [
      {
        label: 'verify',
        lockingBytecode: decode('data/scrypt-bn256/parent-tx.hex').outputs[0]!.lockingBytecode,
        unlockingBytecode: decode('data/scrypt-bn256/spending-tx.hex').inputs[0]!.unlockingBytecode,
      },
    ],
    tamperable: true,
    // The verifier ends in a reachable OP_RETURN (BSV post-Genesis success
    // terminator). Judge correctness by that rule; BCH compatibility stays strict.
    bsvOpReturnTerminator: true,
  }),
};
