# Node check: research verifiers on stock BCHN 29.1.0 (Track 8a, draft)

Branch `wip/node-check`. Date 2026-10-30. Research, not a leaderboard change.

This closes the "no BCHN node run" caveat of the PLONK/KZG report (research/plonk-kzg/REPORT.md, "No BCHN node run")
and the STARK report (research/pq-stark/REPORT.md §8, "No BCHN timing was measured"), for today's consensus rules only:
every input ≤ 10,000 B unlocking, every tx ≤ 100,000 B.

## Method

- **Engine.** Stock BCHN v29.1.0 (`~/BCH-infra/bitcoin-cash-node-29.1.0/bin`), regtest, a fresh datadir per run under
  `work/node-check/bchn-<NAME>`, localhost only (`rpcbind`/`rpcallowip` 127.0.0.1, `listen=0`, `connect=0`). Node
  pinned to CPU 9, driver to CPU 7, `nice`, `GOMAXPROCS=4`, one job at a time. Every node was stopped afterwards.
- **Rig.** Track 1's BCHN rig (`research/opcost-timing/bchn/rig.ts`, imported unchanged): the rig builds every block,
  K copies of a workload tx go into one block, `validateblocktemplate` runs 11 times and the "Verify N txins" bench
  line is parsed, then `submitblock`. `node.sh` here is a copy of Track 1's with one addition, `POLICY=1`, which sets
  `acceptnonstdtxn=0`. Track 1's files are not modified.
- **Extensions (`nc.ts`).**
  - Workloads may carry CashTokens. An NFT faucet is a minting baton created by a genesis that spends
    coinbase(height 1):0, so the category is known before the node starts. The STARK redeems are rebuilt with that
    category. It has the same length, so the plans, sizes and pads are identical to REPORT §6.
  - Op-cost per input is recorded in both libauth modes (consensus: hash iteration cost 64; standard: 192), plus the
    exporter's OP_DEFINE body bytes.
  - **Policy mode:** a separate fresh node with `acceptnonstdtxn=0` and the default relay policy. The source outputs
    are funded in a mined block, then `testmempoolaccept` runs on each workload tx. Multi-tx STARK plans are replayed
    as the real chain: tx k ≥ 1 spends the thread NFT that the mined tx0 created. Each tx is mined after the test, so
    every parent was confirmed. Acceptance with unconfirmed parents (a mempool chain) is tested separately, see
    "Unconfirmed chains" below.
- **Workloads.**
  - `export-plonk.mjs` (groth16_cashscript main 3af2ad8, `research/plonk-kzg/verifier`, chain.mjs/chaintest.mjs
    logic): per circuit, the 5 valid proofs, 8 tampered proofs spread over the list, 12 chain manipulations, and 4
    OP_DEFINE probes.
  - `export-stark.mjs` (`research/pq-stark/verifier`, gradeA logic): every tx of the plan, plus 12–15 rejection
    cases: prover tamper cases, witness manipulations and thread cases.
  - Reference: `builtin:sound-native` from bench main, i.e. the BN254 leader for today's rules and the BLS12-381
    sound-native chain.
- Runs:
  - `raw/nc1-*`: full timing run (195 workloads) and policy run (57).
  - `raw/nc3-m2-*`: unconfirmed-chain run (mempool mode), see "Unconfirmed chains".
  - `raw/nc2-*`: a second fresh timing node, the valid workloads (41 txs) plus 4 `manip:extra foreign input` rejects, 45 in all. **Run 2 is the timing reference**, because
    run 1's merkle16 reps were noisy (spread up to 52%). Run 2 / run 1 per-tx medians: 0.87–1.01. The verdicts are
    identical. Run 2 was started by hand on node `nc2-t` with the same workload files as run 1 (not via `run.sh`), so
    `raw/nc2-env.txt` holds only the node line and load averages.

Reproduce: run `export-*.mjs` into `work/node-check/data` (category: `npx tsx nc.ts category`), then
`run.sh NAME 9 7 11`, then `node summarize.mjs raw/NAME-timing.jsonl raw/NAME-policy.jsonl`.

## Results

| workload | valid accepted BCHN / libauth | rejections BCHN / libauth | tx B | BCHN Verify ms per tx (run 2) | ns / op-cost | worst input op/budget: libauth cons / + DEFINE / libauth std + DEFINE | testmempoolaccept (acceptnonstdtxn=0) |
|---|---|---|--:|--:|--:|---|---|
| PLONK mul2 (10 in, 1 tx) | 5/5 / 5/5 | 20/20 / 20/20 | 82,888–83,171 | 10.65–10.72 | 0.169 | 98.05 / 98.58 / 99.20% | 5/5 allowed |
| PLONK merkle16 | 5/5 / 5/5 | 20/20 / 20/20 | 85,019–85,187 | 10.88–10.96 | 0.168 | 98.91 / 99.41 / **100.00%** | 5/5 allowed |
| PLONK range64 (BSB22) | 5/5 / 5/5 | 20/20 / 20/20 | 88,909–89,150 | 11.59–11.68 | 0.168 | 98.59 / 99.09 / 99.59% | 5/5 allowed |
| PLONK merkle16rc (BSB22) | 5/5 / 5/5 | 20/20 / 20/20 | 89,181–89,514 | 11.61–11.70 | 0.168 | 98.28 / 98.79 / 99.31% | 5/5 allowed |
| STARK mimc-S128-0 (2 tx, 9+8 in) | 2/2 / 2/2 | 14/14 / 14/14 | 65,350 + 58,102 | 8.21 + 7.10 = 15.3 | 0.238 | 84.79 / 85.10 / 86.53% | 2/2 allowed (tx1 chained) |
| STARK mimc-S100b-0 (1 tx, 12 in) | 1/1 / 1/1 | 12/12 / 12/12 | 83,515 | 11.40 | 0.241 | 92.04 / 92.48 / 94.00% | 1/1 allowed |
| STARK fib-S100z-zkmin-0 (2 tx, 13+12 in) | 2/2 / 2/2 | 15/15 / 15/15 | 71,142 + 65,414 | 12.61 + 11.42 = 24.0 | 0.300 | 91.90 / 92.44 / 94.00% | 2/2 allowed (tx1 chained) |
| STARK fib-S128z-zkmin-0 (3 tx, 12+12+11 in) | 3/3 / 3/3 | 15/15 / 15/15 | 80,591 + 80,331 + 73,631 | 12.05 + 11.99 + 10.66 = 34.7 | 0.263 | 92.05 / 92.50 / 94.00% | 3/3 allowed (tx1, tx2 chained) |
| Reference: BN254 sound-native (3 in) | 5/5 / 5/5 | 1/1 / 1/1 | 27,026–28,082 | 3.42–3.51 | 0.169–0.173 | 93.54 / 93.54 / 94.00% | min relay fee not met as built (1,000-sat inputs); 5/5 allowed at 2 sat/B |
| Reference: BLS12-381 sound-native (4 in) | 8/8 / 8/8 | 1/1 / 1/1 | 34,041–37,497 | 2.98–3.14 | 0.121–0.125 | ≤ 93.58 / same / ≤ 93.82% | same: fee only; 8/8 allowed at 2 sat/B |

Notes:
- Ranges are over the valid proofs; "worst input" is the maximum over all inputs of all valid txs.
- Rejections: the BCHN column is the block verdict (`blk-bad-inputs`); `testmempoolaccept` on the timing node gave
  the script error (OP_VERIFY, OP_NUMEQUALVERIFY, ...). The reference rejections show only the fee error, because the
  fee check runs first.
- PLONK verification costs about 3.0–3.4× the BN254 leader on BCHN: 10.7–11.7 ms against 3.5 ms. It sits at the same
  0.17 ns per op-cost unit. STARK runs at 0.24–0.30 ns per op-cost unit, and its whole proof costs 11.4 ms (S100b) to
  34.7 ms (fib-S128z, 3 txs).

### OP_DEFINE accounting (the PLONK report's open question)

- BCHN charges the OP_DEFINE body bytes: block validation counts them on top of consensus op-cost, and mempool
  validation counts them on top of standard op-cost.
- Every PLONK input fits under that accounting:
  - every valid chain is accepted by BCHN block validation;
  - every valid chain is allowed by the policy node, which charges standard op-cost (hash iterations at 192) plus the
    DEFINE bytes.
- merkle16 valid4 has 0.00% margin on that basis, but it fits.
- The four probes per circuit use valid proof 0 with input 9's FILL shrunk, so that the input's budget sits one byte
  (800 op-cost) under, or at, op-cost + DEFINE bytes:

| probe (budget vs libauth op + DEFINE) | libauth consensus | BCHN block | BCHN policy mempool |
|---|---|---|---|
| consensus basis, 1 B under | accept (all 4 circuits) | **reject** (all 4) | reject: VM cost limit exceeded |
| consensus basis, at/over | accept | accept | reject: VM cost limit (standard basis is higher) |
| standard basis, 1 B under | accept | accept | **reject**: VM cost limit exceeded |
| standard basis, at/over | accept | accept | **allowed** |

So BCHN's op-cost equals libauth's plus the executed OP_DEFINE body bytes. It is exact to within one unlocking byte
(800 op-cost) on both bases, in all four circuits. libauth 3.1.0-next.8 alone would accept txs that BCHN rejects. The
reports' "BCHN-adjusted" model is right and necessary.

## Unconfirmed chains (mempool mode, 2026-11-01)

Branch `wip/node-check-mempool`. Question: can a user broadcast a multi-transaction STARK chain at once, with
each parent still unconfirmed?

Method: `nc.ts mempool` on a fresh `POLICY=1` node, `nc3-m2` (acceptnonstdtxn=0, default relay policy, listen=0,
connect=0, rpcbind 127.0.0.1). The workload files are the same as run 1 (sha256 prefixes in `raw/nc3-m2-env.txt`).
For each group, the non-chained inputs are funded in one mined block. Then `testmempoolaccept` and
`sendrawtransaction` run on tx0, tx1 (and tx2) in order, with no block in between. Then `generatetoaddress 1` is
called (BCHN's own block assembler), and the block's tx list and the empty mempool are checked. `getblocktemplate`
cannot be used: it refuses with "Bitcoin is not connected!" on a node with connect=0. A first attempt (`nc3-m`) hit
that refusal and was discarded; its sends had also all succeeded. The chain shape is a fan-out: every tx k ≥ 1
spends one thread NFT output of tx0. So fib-S128z has 1 parent and 2 children, and the depth is 2.

| vector | send tx0 | send tx1 (parent unconfirmed) | send tx2 (parent unconfirmed) | mined in 1 block | chain bytes | chain fee (rate) |
|---|---|---|---|---|--:|--:|
| mimc-S128-0 | accepted | accepted | – | yes (block 223: coinbase + 2) | 123,452 | 158,000 sat (1.280 sat/B) |
| fib-S100z-zkmin-0 | accepted | accepted | – | yes (block 225: coinbase + 2) | 136,556 | 238,000 sat (1.743 sat/B) |
| fib-S128z-zkmin-0 | accepted | accepted | accepted | yes (block 227: coinbase + 3) | 234,553 | 327,000 sat (1.394 sat/B) |

- Every per-tx `testmempoolaccept` was `allowed` before its send. Per-tx rates were 1.20–1.80 sat/B. The mempool was
  empty after each block.
- A child submitted before its parent is rejected with `missing-inputs`. Broadcasting means sending in order:
  tx0 first, then its children. Batch `testmempoolaccept` of the whole chain is not available: BCHN answers
  "Array must contain exactly one raw transaction for now".
- **Chain limits did not constrain anything.** BCHN 29.1.0 has no `-limitancestor*`/`-limitdescendant*` options
  (`bitcoind -help -help-debug`). Its `getmempoolentry` has no ancestor or descendant fields, only
  `depends`/`spentby`. No too-long-mempool-chain or ancestor-limit reason appeared. The chains here are at most
  depth 2 with 3 txs, about 235 kB, far below `maxmempool` (320 MB).
- PLONK was not re-run: each chain is a single tx with confirmed inputs, which the policy run above already covers.

Reproduce: `POLICY=1 node.sh start NAME 9`, then
`npx tsx nc.ts mempool --node NAME --src json:<data>/stark-<vector>.json ... --out raw/NAME-mempool.jsonl`, then
`node.sh stop NAME`.

## Discrepancies and findings

1. **libauth vs BCHN, OP_DEFINE.** This is the only discrepancy between the two engines. It is real and is quantified
   above: it is the DEFINE body bytes, 34.7k–38.6k per input for PLONK and 16.2k–24.2k for STARK. Every published
   chain was sized with the adjustment and passes. All 195/195 rows are as expected; the only libauth/BCHN differences are the 4 consensus-basis DEFINE probes,
   which differ by design.
2. **Policy: every valid workload passes `testmempoolaccept` under the default policy.** That covers 20 PLONK txs,
   8 STARK txs including the chained NFT-thread txs, and the reference once fees are paid. No unmodelled rule (P2SH32
   locking, dust on the 1,000-sat token outputs, OP_RETURN, tx size, sigchecks, input standardness) rejected
   anything. "Fits in one standard transaction today" holds on BCHN for the four PLONK circuits and for STARK
   mimc-S100b-0.
3. **Harness fee, not a protocol issue.** The bench's sound-native vectors (and Track 1's `builtin:sound-native`)
   spend 1,000-sat inputs into a 1,000-sat OP_RETURN, which is 0.07–0.09 sat/B. The default relay rejects this with
   `66: min relay fee not met`. With the source values raised to pay 2 sat/B, all 13 are allowed, so the scripts do
   not read input values. The PLONK (12 sat/B) and STARK (1.2–1.8 sat/B) exports already pay the fee.
4. **Rig caveat for the record.** On a node with `acceptnonstdtxn=1`, BCHN does not set `SCRIPT_VM_LIMITS_STANDARD`
   for the mempool (validation.cpp around line 1590 in BCHN master abd433a, checked in a local clone with no v29.1.0 tag; the flag
   needs `fRequireStandard`; the run data agrees). The standard op-cost and hash limits are then
   only checked on a `POLICY=1` node. Track 1's mempool reasons are therefore relaxed-standard. This does not affect
   its block timings.
5. BCHN labels standard-only VM-cost failures `mandatory-script-verify-flag-failed (VM cost limit exceeded)` even when
   the tx is consensus-valid (the consensus-over probes were mined). This is only a label.

## Not covered

- Only today's rules. One-100 KB-input layouts and bch-spec cannot run on BCHN today. The other STARK rows in REPORT §6 (P100, P128,
  S128b, mimc-P128-zkmin) were not asked for and were not run.
- Rejections are a sample of the existing tamper and manipulation vectors: 8 + 12 per PLONK circuit, 12–15 per STARK
  vector. The full libauth suites are not re-run on BCHN. No new attacks were constructed.
- The funding transactions themselves (the creation of the P2SH32 and token source outputs) were mined directly and
  not policy-tested.
- The workload JSON files (about 30 MB) are not committed. The first 16 hex characters of their sha256 are in `raw/nc1-env.txt`, and the
  exporters regenerate them deterministically.

## Track 8 (STARK M1)

Branch `wip/node-check-t8`. Date 2026-11-01. Question: does the Track 8 a′ verifier (Plonky3 batch-STARK proof of
post-quantum ZK Merkle membership plus a nullifier, 128 bits; REPORT §T8.4) run on stock BCHN 29.1.0 as graded?
The two plans are 1 tx / 12 inputs / 98,690 B, and 2 txs of 91,059 + 40,497 B linked by an NFT thread.

**Workloads.** `export-stark-t8.mjs` (groth16_cashscript main 2d96adc) imports Track 8's own `onchain/` code: the
`layouta.mjs` spend and the `grade-a.mjs` plans. It also uses Track 8's libauth, unpatched 3.1.0-next.8. It covers
all **24** M1 statements, using the cached cap-5 proofs in `work/stark-usable/cache/s7/vec`. Proofs 0–2 are
byte-identical to the committed `prover/vectors/S7`. Nothing was re-proved.
- **Assertions.** For every statement and plan, the exporter checks the graded build against
  `results/grade-a.json`. Each transaction's size must be 98,690, or 91,059 and 40,497. Each input's unlocking
  length and libauth standard op-cost must be equal, and every input must be accepted.
- **1tx.** This plan has no token, so it is exported exactly as graded. The node uses only real outpoints.
- **2tx.** The thread NFT's category must be a real genesis outpoint. The plan is therefore rebuilt with the node
  faucet's category, which is 32 bytes inside the code. This changes no size and no per-input op-cost (0
  differences). `programA`'s cache does not key on the category, so the exporter passes a distinct `gen` option.
- **Reject sample** (statements 0 and 23, both plans; 106 cases, test-a.mjs families):
  - 9 prover tampers (S3 families cap, ood, random, pow, final, row, salt, sibling, fri_value) and NF + 1;
  - tx output − 1 sat (CTX differs);
  - script ROOT + 1;
  - constants: FIN TBL, ACC₁ + 1 with ACC₂ compensated, NF lane;
  - inputs: OOD, QRY hint, path, missing query;
  - graph: code blob byte, QRY input order, foreign locking;
  - mix: a QRY input from another statement, tx1 replayed from another statement;
  - 2tx thread cases: foreign-G NFT, mutable NFT, no NFT, a tx0 QRY in tx1, baton not returned, NFT minted mutable.

  Each case is the first transaction that Track 8's libauth consensus VM rejects.

**Runs** (`run-t8.sh nc4 9 7 11`; node on CPU 9, driver on CPU 7, nice, GOMAXPROCS=4). There were three fresh nodes,
each stopped afterwards: `nc4-t` (timing), `nc4-p` (POLICY=1, testmempoolaccept; tx1 spends the mined tx0's NFT) and
`nc4-m` (POLICY=1, mempool mode). Raw data: `raw/nc4-*`; the full table is in `raw/nc4-summary.md`, from
`summarize-t8.mjs`.
- **DEFINE accounting.** Bench's libauth is now patched to charge OP_DEFINE bodies. `nc.ts` detects this with a
  probe and no longer adds the DEFINE bytes again in that case. Track 8 itself still uses unpatched libauth plus
  `defineBytes`: 36,844 B in 1tx, 37,622 B in 2tx.

| plan | valid: BCHN / libauth (bench) / libauth (T8) | rejections: BCHN / libauth (bench) / libauth (T8) | Verify ms per tx (median, K copies) | ns / op-cost | worst input op/budget: bench libauth cons / std (incl. DEFINE) ; T8 std alone / + DEFINE | testmempoolaccept (acceptnonstdtxn=0) |
|---|---|---|--:|--:|---|---|
| a′ 1 tx (12 in, 98,690 B) | 24/24 / 24/24 / 24/24 | 46/46 / 46/46 / 46/46 | 16.64–17.00 | 0.264–0.269 | 89.69 / **91.01%** ; 90.45 / 91.01% | **24/24 allowed** (1.24 sat/B as exported) |
| a′ 2 txs (11 + 5 in, 91,059 + 40,497 B) | 48/48 / 48/48 / 48/48 | 60/60 / 60/60 / 60/60 | 15.32–15.57 + 2.85–2.93 = 18.20–18.47 | 0.268–0.278 | 89.77 / **91.10%** ; 90.54 / 91.10% | 48/48 allowed (2.31 / 2.74 sat/B), tx1 chained on mined tx0 |

- **Op-cost.** On all 672 valid inputs, bench's patched libauth op-cost equals Track 8's libauth op-cost plus
  `defineBytes`, exactly, on both bases. The patch and Track 8's "BCHN-adjusted" figure agree.
- **Binding input.** The worst input is QRY in both plans, at 90.67–91.10% of its budget on the standard basis. Other
  roles: HEAD 25%, CODE1/2 73/67%, FIN 72%. In 2tx, tx1 re-runs HEAD/CODE at 10% and 3%.
- **Rejections.**
  - All 106 got BCHN block verdict `blk-bad-inputs`.
  - On the timing node, `testmempoolaccept` gave script errors: `mandatory-script-verify-flag-failed` with
    OP_NUMEQUALVERIFY, OP_EQUALVERIFY, or Invalid OP_SPLIT range (tx1 without the NFT).
  - No rejection came from size, token or fee rules.
- **Mempool mode (2tx).** For all 24 statements, tx0 and then tx1 were sent with tx0 unconfirmed:
  - `testmempoolaccept` allowed both, and both were accepted into the mempool;
  - BCHN's own assembler mined both in one block, and the mempool was empty afterwards;
  - tx1 sent first is rejected with `missing-inputs`;
  - the chain is 131,556 B at 2.44 sat/B.
- **Policy.** No unmodelled relay rule rejected anything. The 118 B P2S locking on every input, 12 non-P2SH inputs of
  6.4–9.5 KB, the 5,000-sat token outputs and the 98,690 B transaction all pass. **"M1 in one standard transaction
  today" holds on BCHN 29.1.0**, for all 24 statements.

Not covered:
- Only cached proofs were used; the prover was not re-run.
- Rejections are a sample of 2 statements, not the 3,765 / 4,181-case sweeps.
- Encoder-only (malformed) tamper cases are skipped, as in test-a.mjs.
- The "NFT of another category", "extra input" (the transaction would exceed 100,000 B) and VK-variant families
  were not run.
- 2tx ran with the node's category, not Track 8's test constant.
- The funding transactions were mined directly and were not policy-tested.
- The workload JSON (30 MB, `work/node-check3/data/t8`) is not committed. The first 16 hex characters of each file's
  sha256 are in `raw/nc4-env.txt`.

Reproduce: `npx tsx nc.ts category` gives CAT. Then
`G16=<g16 checkout> node export-stark-t8.mjs --cat CAT --out <data>/t8 --rej 0,23 <s7 vec>/*.json`, then
`DATA=<data>/t8 run-t8.sh NAME 9 7 11`, then `node summarize-t8.mjs <data>/t8 raw/NAME > raw/NAME-summary.md`.
