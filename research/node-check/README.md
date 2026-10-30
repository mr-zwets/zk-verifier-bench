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
    every parent was confirmed; acceptance with unconfirmed ancestors (a mempool chain) was not tested.
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
