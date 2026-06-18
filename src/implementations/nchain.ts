import { readFileSync } from 'node:fs';
import { decodeTransactionBch, hexToBin } from '@bitauth/libauth';

import type { Implementation } from '../harness/types.js';

const decode = (path: string) => {
  const tx = decodeTransactionBch(hexToBin(readFileSync(path, 'utf8').trim()));
  if (typeof tx === 'string') throw new Error(`decode ${path}: ${tx}`);
  return tx;
};

// Real nChain Groth16 verifier from BSV mainnet (see data/nchain/SOURCE.md).
// Verifier = parent tx vout[0]; proof = spending tx vin[0]. Run `pnpm fetch:nchain`
// first if the .hex files are missing. Single-tx: the whole verify is one script.
export const nchain: Implementation = {
  id: 'nchain',
  name: 'nChain zkScript (Groth16)',
  proofSystem: 'Groth16',
  field: 'BLS12-381',
  structure: 'single-tx',
  source: 'BSV mainnet tx e4cd...514c (proof) spending 79a5...4940:0 (verifier)',
  load: async () => ({
    valid: [
      {
        label: 'verify',
        lockingBytecode: decode('data/nchain/parent-tx.hex').outputs[0]!.lockingBytecode,
        unlockingBytecode: decode('data/nchain/spending-tx.hex').inputs[0]!.unlockingBytecode,
      },
    ],
    tamperable: true,
  }),
};
