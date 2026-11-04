# Limits sensitivity table: what each verifier needs from BCH's size limits

Status: research data, 2026-11-04. Nothing here changes the site, REGISTRY, results.json or score-history.json. No
security claim is made: these are byte, input and op-cost fits. The soundness status of each layout is the one stated
in its own report.

**Audience:** people who set BCH limits (CHIP authors, node developers). The question is what each measured verifier
needs (number of transactions, inputs, total bytes) under a grid of per-input and per-transaction limits.

## The limits, from BCHN source

Source: BCHN master `3d13ce8` (2026-10-30), local clone `~/git-clones/bitcoin-cash-node`. The node-check runs used the
v29.1.0 binary; the clone has no v29.1.0 tag, and the files below last changed in `abd433a`, the commit node-check
already cited (`research/node-check/README.md`, note 4).

| limit | value | kind | where |
|---|--:|---|---|
| max transaction size | 1,000,000 B | **consensus** | `src/consensus/consensus.h:15` `MAX_TX_SIZE = ONE_MEGABYTE`; checked in `src/consensus/tx_check.cpp:24` |
| max standard transaction size | 100,000 B | **policy (relay)**, a compile-time constant with no config option | `src/policy/policy.h:49` `MAX_STANDARD_TX_SIZE`; `src/policy/policy.cpp:76-79` (`tx-size`) |
| max script size (unlocking bytecode, function bodies) | 10,000 B | **consensus** | `src/script/vm_limits.h:19` `MAX_SCRIPT_SIZE`; `src/script/interpreter.cpp:330,371` (`SCRIPT_SIZE`). The policy scriptSig cap after May 2026 is the same constant (`policy.cpp:84-91`) |
| max stack item | 10,000 B | **consensus** | `vm_limits.h:33` `may2025::MAX_SCRIPT_ELEMENT_SIZE = MAX_SCRIPT_SIZE` (the two are tied) |
| op-cost budget per input | (41 + unlocking) × 800 | consensus | `vm_limits.h:49,55,65-69` `GetInputOpCostLimit`. Standard transactions pay 3× per hash block (`HASH_COST_PENALTY_FOR_STD_TXNS`) |
| stack + altstack + function table | 1,000 items | consensus | `vm_limits.h:22` `MAX_STACK_SIZE` |

libauth 3.1.0-next.8 has the same values: `maximumTransactionLengthBytes: 1_000_000` and
`maximumStandardTransactionSize: 100_000` (`bch-2023-consensus.js:49,58`), and `maximumStackItemLength: 10_000`
(`bch-2025-consensus.js:7`).

**This matters for reading the grid.** The two axes are different kinds of change:
- **Raising the tx size limit up to 1 MB is a policy change.** Consensus already allows 1 MB. Such a transaction is valid today if a miner includes it directly.
- **Raising the per-input limit above 10,000 B is a consensus change** (libauth's bch-spec VM raises it). `MAX_SCRIPT_SIZE` is enforced in the interpreter.

The repo's `r100`/`r150` comments (groth16_cashscript `vm.mjs`, `vmn.mjs`, `grade-b2.mjs`) call these "relay/standardness
limits raised". For the unlocking, bytecode and stack-item limits that is not what BCHN does: there they are consensus.

## Grid and method

- **Per-input limit U** ∈ {10,000 (today), 100,000, 150,000}. This is the unlocking, bytecode and stack-item limit, raised together, as BCHN ties them.
- **Tx limit X** ∈ {100,000 (today), 200,000, 400,000}, plus **1,000,000 consensus-only**: a non-standard tx that needs a cooperating miner.
- The op-cost budget stays (41 + unlocking) × 800 per input. Density base, hash and stack limits are unchanged. The P2S locking limit stays 201 B.
- Op-cost is "BCHN-adjusted" everywhere: libauth plus the OP_DEFINE body bytes per input. node-check showed this is exact on BCHN 29.1.0. In the standard cells it is max(standard, consensus); in the 1 MB cells it is consensus only.

**Tags**
- **MEASURED**: a generator was run with libauth at these exact limits (`raw/`).
- **MEASURED\***: taken from a committed results file, measured under a regime that is stricter on every limit that changes here. Every limit in the grid is an upper bound and the op-cost budget formula does not change. So a tx that passes the stricter regime passes this cell, with the same layout and bytes.
- **MODELLED**: layout arithmetic from measured per-input sizes and op-costs (`table.mjs`). The layout is not built.

**Binding constraint:** the limit that stops the next-smaller count. For "txs", that is the fewer-txs plan the search
rejected. For "inputs", it is what fixes the per-input packing.
- **tx size**: the transaction byte limit.
- **input size**: the per-input unlocking limit.
- **op-cost**: the per-input budget.
- **stack slots**: the 1,000-item limit. It is not on the brief's list, but it binds the per-sibling Merkle layout at 4 queries per input.

### How the Track 10 cells were measured

`scratch-gen/grade-lim.mjs` is a copy of groth16_cashscript `grade-a2.mjs` (db1860d), parameterised:
- `--unl U`: per-input limit used by the plan search and the code-blob packer (`LIMITS_UNL`).
- `--tx X`: tx limit used by the plan search.
- A new regime `L<U>_<X>`, in a scratch copy of `vm.mjs` only. It is BCH 2026 with U on unlocking, bytecode and stack item, and X on standard tx size.
- The R0 first-tx query cap `n0` goes from 12 to 64 so the search can fill one large transaction (search only; at
  U = 10,000, X = 100,000 it still reproduces the published 355,817 B).
- `--pers 3,2,1`: queries per QRY input. It keeps the plan with the fewest txs, then the fewest bytes.
- Every candidate plan is validated in full before it is taken: every input std (except at 1 MB) and cons, within the BCHN-adjusted budget, and whole-tx verify. grade-a2 only checked bytes, which is enough at U = 10,000. At U = 100,000 a 4-query input passed the byte check and then failed on stack slots.

The full diff against the repo files is in `scratch-gen/scratch-vs-groth16-db1860d.diff`. The repo was not edited.

Checks:
- **Reproduces the published result.** At U = 10,000, X = 100,000 it gives 4 txs / 57 inputs / 355,817 B, byte for byte (`raw/g2-opt-u10000-t100000.log`).
- **Second vector agrees.** g2-1 gives the same counts and bytes at X = 100,000 and X = 400,000 (`raw/x-*-vec1.*`).
- **Run conditions.** All runs used vector `tw2x18x16-g2-0` cap 0 (`work/t10-gates/cache/g2/vec0`), `--nc 3`, pad target 0.93, `nice -n 19`, one job at a time.

## The table

Bytes are total transaction bytes, summed over all transactions.

### Groth16 BN254 sound-native (`bch-groth16-bn254-sound-native`)

| U | X | txs | inputs | bytes | tag | binding |
|--:|---|--:|--:|--:|---|---|
| 10,000 | 100,000 (today) | 1 | 3 | 27,624 | MEASURED\* (results.json; BCHN-checked in node-check nc1 and t12) | inputs: op-cost (each input about 94% of its budget) and input size (9.3 KB inputs) |
| 10,000 | 200k / 400k / 1 MB | 1 | 3 | 27,624 | MEASURED\* | same; tx size not binding (72 KB headroom) |
| 100k / 150k | any | 1 | 3 as built; **1 modelled** | 27,624 (≤ 27.5 KB as 1 input) | MEASURED\* / MODELLED | 1 input needs U ≥ 27,426; op-cost 20.81M of 21.97M = 94.7% (worst-case proof) |

### PLONK/KZG (Track 7, Ignition SRS; mul2, merkle16, range64, merkle16rc)

| U | X | txs | inputs | bytes | tag | binding |
|--:|---|--:|--:|--:|---|---|
| 10,000 | 100,000 (today) | 1 | 10 | 82,888–89,514 (tx) | MEASURED\* (`plonk-kzg/REPORT.md` §T7.5; BCHN node-check) | inputs: input size + op-cost (FILL-padded, 0.00–0.80% margin); tx size margin 10.5 KB |
| 10,000 | 200k / 400k / 1 MB | 1 | 10 | same | MEASURED\* | input size |
| 100k / 150k | any | 1 | 1 | 63,241–69,518 (tx) | MEASURED\* (REPORT §T7.5 "100 KB input" regime = same limits) | op-cost (padded to 0.09–0.10% margin) |

### Track 8 STARK M1 (Z128, 24 transaction-bound statements)

| U | X | layout | txs | inputs | bytes | tag | binding |
|--:|---|---|--:|--:|--:|---|---|
| 10,000 | 100,000 (today) | a′ | 1 | 12 | 98,690 | MEASURED\* (`pq-stark-batch/onchain/results/grade-a.json`; BCHN node-check nc4) | **tx size** (1,310 B margin); inputs: input size; QRY op-cost 91% |
| 10,000 | 200k / 400k / 1 MB | a′ | 1 | 12 | 98,690 | MEASURED\* | input size, op-cost |
| 100,000 | 100,000 | b | 1 | 1 | 91,477–95,057 | MEASURED\* (`grade-b.json`, r100) | **input size** (unlocking up to 94,968 of 100,000); op-cost only 47–49% |
| 100,000 | 100,000 | b2 | 1 | 2 | 96,153–98,321 | MEASURED\* (`grade-b2.json`, r100) | tx size |
| 150,000 | any | b | 1 | 1 | 91,477–95,057 | MEASURED\* | none |

For reference, M2 (not in the brief) is in the same `grade-b2.json`: b2, 2 inputs, 156,384–159,749 B. It needs U = 100,000
and X ≥ 160 KB, and does not fit today.

### Track 10 G2 bridge stand-in (ZisK-sized STARK, 43 queries, proof 224,814 B)

The best measured layout per cell is in bold. Opt is `--opt sib,lad,state,cap=3`.

| U | X | layout | txs | inputs | bytes | tag | binding (txs; inputs) |
|--:|---|---|--:|--:|--:|---|---|
| 10,000 | **100,000 (today)** | baseline a′ | 7 | 78 | 639,351 | MEASURED | tx size; input size (1 q/input) |
| 10,000 | 100,000 (today) | **opt a′** | **4** | 57 | 355,817 | MEASURED | **tx size** (any layout needs ≥ 3: the proof alone is 224.8 KB); input size; QRY op-cost 91.6% |
| 10,000 | 200,000 | baseline | 3 | 58 | 482,424 | MEASURED | tx size |
| 10,000 | 200,000 | **opt** | **2** | 51 | 313,785 | MEASURED | **tx size** (≥ 2 for any layout); input size |
| 10,000 | 400,000 | baseline | 2 | 53 | 444,705 | MEASURED | tx size (its 1-tx plan is 407,290 B) |
| 10,000 | 400,000 | **opt** | **1** | 48 | 293,514 | MEASURED | none for txs; inputs: input size (QRY 5,855 B, op 92.8%) |
| 10,000 | 1 MB, consensus only | opt / baseline | 1 / 1 | 48 / 48 | 293,514 / 407,290 | MEASURED | none; needs a miner |
| 100,000 | 100,000 | baseline | 5 | 40 | 464,659 | MEASURED | tx size |
| 100,000 | 100,000 | **opt** | **4** | 29 | 353,713 | MEASURED | **tx size**; inputs: **stack slots** (4 q/input exceeds 1,000 items) |
| 100,000 | 200,000 | baseline / **opt** | 2 / **2** | 25 / 23 | 351,185 / 312,209 | MEASURED | tx size; stack slots |
| 100,000 | 400,000 and 1 MB | baseline / **opt** | 1 / **1** | 20 / 20 | 314,268 / 291,940 | MEASURED | none for txs; stack slots (opt), op-cost 91.7% |
| 100,000 | 400,000 and 1 MB | b3 (3 inputs) | 1 | 3 | about 260,500 | **MODELLED** | inputs: input size (input 0 98.4 KB, the library and 12 queries); op ≤ 65–83% |
| 150,000 | 100,000 / 200,000 | baseline, opt | as U = 100,000 (5/4 and 2/2) | | identical bytes | MEASURED | tx size; per-input limit above 100k changes nothing for a′ |
| 150,000 | 400,000 and 1 MB | opt a′ | 1 | 20 | 291,940 | MEASURED | |
| 150,000 | 400,000 and 1 MB | **b2** | **1** | **2** | **260,355–260,784** | MEASURED\* (`results/g2/grade-b2.json`, r150t = U 150k, X 300k, std and cons) | inputs: input size (input 0 134,965 B); op ≤ 51.7% |

**Boundary checks** (MEASURED, `raw/x-*`), at U = 10,000 with opt:

| X | result |
|--:|---|
| 293,514 | 1 tx |
| 293,513 | 2 txs, 288,103 + 25,681 B |
| 300,000 | 1 tx |

So the threshold for one transaction at today's per-input limit is exactly the 1-tx plan's size.

## Where the tx counts jump

- **Groth16, PLONK, M1:** no jumps; already 1 standard tx today. Raising U only collapses inputs:
  - Groth16: 3 → 1, modelled;
  - PLONK: 10 → 1;
  - M1: 12 → 1 (layout b), and the bytes fall from 98.7 KB to 91.5–95.1 KB.
- **G2 is driven by X alone.** The counts are the same at U = 10k, 100k and 150k. Only the inputs and bytes change.

| X | G2 opt txs | jump | note |
|--:|---|---|---|
| 100,000 | 4 | | |
| 200,000 | 2 | 4 → 2 | |
| 293,514 | 1 | 2 → 1 | at today's U |
| 260,784 | 1 | | only with U ≥ 135 KB (b2), or about 260.5 KB with U = 100k (b3, modelled) |

- **Raising U to 100k or 150k at X = 100,000 saves 2 KB and 28 inputs, but zero transactions** (4 → 4).
- **The optimizations matter less as X grows:**

| X | baseline | opt |
|--:|---|---|
| 100,000 | 7 txs | 4 txs |
| 400,000 | 2 txs | 1 tx |
| 1 MB | 1 tx | 1 tx |

## Smallest single change to one standard transaction

| verifier | smallest single change | result |
|---|---|---|
| Groth16 sound-native | none | already 1 standard tx (27,624 B) |
| PLONK/KZG | none | already 1 standard tx (82.9–89.5 KB) |
| Track 8 M1 | none | already 1 standard tx (98,690 B, 1.3 KB margin) |
| Track 10 G2 | raise `MAX_STANDARD_TX_SIZE` from 100,000 to **≥ 293,514 B** (policy only), U unchanged | 1 tx, 48 inputs, 293,514 B (MEASURED, libauth). A per-input raise alone does nothing: 4 txs at U = 150k. The fewest bytes (260 KB, 2 inputs) need two changes: U ≥ 135k (consensus) and X ≥ 261k (policy) |

The same 293,514 B transaction is consensus-valid today as a non-standard transaction (the 1 MB column, MEASURED in
libauth consensus mode). It needs a cooperating miner and no rule change.

The 1-transaction plan has no NFT thread between transactions; see the Track 10 report for the multi-transaction
ordering gap. This is a fit table, not a security argument.

## Caveats

- The new G2 cells were measured in libauth 3.1.0-next.8 with the BCHN DEFINE adjustment, not on a BCHN node. No node implements X > 100,000 standard or U > 10,000. The 1 MB cells could be run on stock BCHN with `acceptnonstdtxn=1` or `submitblock`; that has not been done.
- The G2 opt layout has not been reviewed for soundness (pq-wrap REPORT). This table is a fit table, not a security claim.
- The G2 plan search tried 1–3 queries per QRY input:
  - With `sib`, 4 queries fail on stack slots (`raw/x-g2-opt-u100000-t400000-per4.log`).
  - The baseline (no `sib`) at U ≥ 100k was not tried above 3 queries. That could cut inputs but not transactions, since X binds.
  - `--nc` (CODE inputs) was held at 3.
- The modelled b3 is not a built layout:
  - It assumes b2's loader pattern extends to a second loader input.
  - Its op-cost bound reuses b2's measured per-input op-cost. An input with fewer queries runs fewer query loops of the same code.
- The modelled 1-input Groth16 over-counts bytes (it keeps the hand-overs) and uses the bench's 3-input worst-case op-cost plus the whole code once as DEFINE bytes.
- Tx sizes use v2 serialization, as the generators do.

## Files

- `table.mjs`: prints the G2 grid from `raw/g2-*.json` and the MODELLED cells. Output: `raw/table-output.md`.
- `raw/g2-{opt,base}-u<U>-t<X>.{json,log}`: the 24 grid runs. `raw/x-*`: boundary, per-4 and second-vector runs. `raw/grid.log`, `raw/extra.log`: run logs.
- `raw/src-*.json`: copies of the source results files that `table.mjs` reads. Both are from groth16_cashscript db1860d:
  - `src-bn-native-sound-build.json` = `chunked/bn254/bn-native-sound/build.json`;
  - `src-g2-grade-b2.json` = `research/pq-wrap/onchain/results/g2/grade-b2.json`.
- `scratch-gen/`:
  - `grade-lim.mjs` and the two run scripts;
  - `scratch-vs-groth16-db1860d.diff`, the scratch changes to `vm.mjs`, `gena.mjs` and `grade-a2.mjs`.

  To rerun, copy groth16_cashscript `research/{pq-wrap,pq-stark}` at db1860d into a scratch directory, apply the diff, put
  `grade-lim.mjs` next to `grade-a2.mjs`, and link a `node_modules` with libauth 3.1.0-next.8.

**Sources** (MEASURED\* cells):
- this repo's `results.json` (`bch-groth16-bn254-sound-native`);
- `research/plonk-kzg/REPORT.md` §T7.5;
- groth16_cashscript db1860d `research/pq-stark-batch/onchain/results/{grade-a,grade-b,grade-b2}.json` and `research/pq-wrap/onchain/README.md`;
- `research/pq-wrap/REPORT.md`;
- `research/node-check/README.md`.
