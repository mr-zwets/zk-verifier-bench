// Fetch the raw transaction hex artifacts from WhatsOnChain on demand, so the
// large .hex blobs do not need to live in git. After fetching, regenerate the
// derived listings with `pnpm nchain:extract` / `pnpm scrypt:extract`.
//
//   pnpm fetch          # everything
//   pnpm fetch:nchain   # just the nChain mainnet txs
//   pnpm fetch:scrypt   # just the sCrypt testnet tx (~55 MB)
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

type Tx = { group: string; net: 'main' | 'test'; txid: string; out: string; note: string };

const TXS: Tx[] = [
  {
    group: 'nchain',
    net: 'main',
    txid: '79a5281c9ea718c2a6be4e8d0e48b27855969d780c50393c01ad6267a9e24940',
    out: 'data/nchain/parent-tx.hex',
    note: 'nChain verifier (locking script, vout 0)',
  },
  {
    group: 'nchain',
    net: 'main',
    txid: 'e4cd00c1fa7dd6931dd1e45034e9d9f732e6d7d38f7826341715f488a146514c',
    out: 'data/nchain/spending-tx.hex',
    note: 'nChain proof (unlocking script, vin 0)',
  },
  {
    group: 'scrypt',
    net: 'test',
    txid: 'eba34263bbede27fd1e08a84459066fba7eb10510a3bb1d92d735c067b8309dd',
    out: 'data/scrypt/eba3.hex',
    note: 'sCrypt BLS12-381 verifier tx (~55 MB hex)',
  },
  {
    group: 'scrypt-bn256',
    net: 'main',
    txid: '320ba9fb3826c0bc66beed51edf2463e958b7274921563c5c90be62deabb725f',
    out: 'data/scrypt-bn256/parent-tx.hex',
    note: 'sCrypt BN256 verifier (locking script, vout 0; ~11.7 MB tx)',
  },
  {
    group: 'scrypt-bn256',
    net: 'main',
    txid: '24e8159c931ed1e64c8477c55d74dc6a4f8fe727888f8ad57ac2483db054bf24',
    out: 'data/scrypt-bn256/spending-tx.hex',
    note: 'sCrypt BN256 proof (unlocking script, vin 0)',
  },
];

const filter = process.argv[2];
const selected = filter ? TXS.filter((t) => t.group === filter) : TXS;
if (selected.length === 0) {
  console.error(`no txs match group "${filter}" (known groups: nchain, scrypt, scrypt-bn256)`);
  process.exit(1);
}

for (const tx of selected) {
  const url = `https://api.whatsonchain.com/v1/bsv/${tx.net}/tx/${tx.txid}/hex`;
  process.stdout.write(`fetching ${tx.group}: ${tx.note} ... `);
  const res = await fetch(url);
  if (!res.ok) {
    console.log(`FAILED (${res.status})`);
    process.exitCode = 1;
    continue;
  }
  const hex = await res.text();
  mkdirSync(dirname(tx.out), { recursive: true });
  writeFileSync(tx.out, hex.trim());
  console.log(`${(hex.length / 2).toLocaleString()} bytes -> ${tx.out}`);
}
