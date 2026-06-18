# sCrypt BSV Groth16 verifier (BLS12-381) — provenance

sCrypt's Groth16 verifier, from BSV **testnet**. This is sCrypt's **BLS12-381**
line (Dec 2022), an early/unoptimised version, NOT their first Aug 2022 BN256
verifier. Curve confirmed empirically: the locking script is dominated by
48/49-byte data pushes (48-byte BLS12-381 Fp elements, +1 sign byte when the top
bit is set); BN254 would show 32/33-byte pushes.

## Transaction (WhatsOnChain, BSV TESTNET)

- **Verifier (locking script)** — tx
  `eba34263bbede27fd1e08a84459066fba7eb10510a3bb1d92d735c067b8309dd`, **output 0**
  (~27.5 MB nonstandard locking script; the verifier, with proof/VK embedded).
  The tx's two inputs are trivial P2PKH spends of parent
  `2c35b1e674dc7de6df6cc5ec2a34169cf8d2063c035afeb55bb50f864853de0d`, so the
  verifier lives in this tx's output (deploy pattern), unlike nChain where it is
  in the parent output and verified at spend time.

## Measured profile

- 27,549,371 bytes, 22,940,451 instructions, 55 distinct opcodes.
- All 55 distinct opcodes exist on BCH 2026 (0 missing).
- Heavy stack juggling (`OP_PICK` 2.78M, `OP_ROLL` 2.42M, alt-stack ~0.88M each),
  field arithmetic (`OP_MUL` 489k, `OP_MOD` 276k, `OP_ADD`/`OP_SUB`), range checks
  (`OP_GREATERTHANOREQUAL`/`OP_LESSTHAN`), and `OP_VERIFY` 788k.

## Files

| file | what |
|------|------|
| `eba3.hex` | raw 27.5 MB tx hex (gitignored; re-fetch below) |
| `eba3.meta.json` / `parent.meta.json` | WhatsOnChain metadata (scripts truncated by API) |
| `groth16-locking.hex` | extracted vout[0] locking script hex (gitignored) |

Re-fetch and re-analyse:

```
curl -s "https://api.whatsonchain.com/v1/bsv/test/tx/eba34263bbede27fd1e08a84459066fba7eb10510a3bb1d92d735c067b8309dd/hex" -o eba3.hex
pnpm scrypt:extract
```
