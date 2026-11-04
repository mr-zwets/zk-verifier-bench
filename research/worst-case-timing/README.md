# Worst-case validation time: today's per-input limits vs 100 KB and 150 KB inputs

Branch `wip/worst-case-timing`. Date 2026-11-04. Research for limit setters, not a leaderboard change.

**Question.** If the per-input limits rose from 10,000 B to 100,000 B or 150,000 B, how slow could the slowest valid
input or transaction be, compared with today's worst case?
- The raised limits are the consensus script-size limit (MAX_SCRIPT_SIZE, which bounds the unlocking bytecode and
  is also checked by relay) and the stack-item limit, plus the matching standard unlocking cap.
- The density base and the op-cost budget rule are unchanged, so the budget is still (41 + unlocking) × 800.
- The 100,000 B transaction size limit is relay policy only (the consensus maximum is 1 MB), and stays as it is.

**Scope.** Plain benchmarking with *valid* scripts only: no consensus-bug hunting, no exploit construction. No node
crash, hang or unbounded blowup was seen. One item is recorded neutrally under "Quadratic behaviour". It comes from
libauth (JavaScript), not from a node, and only under a reading in which VM numbers are also raised.

## Answer in plain English

- **Per byte: about the same as today, at most about 10% higher.** The slowest kernel found costs BCHN about 930 ns
  per unlocking byte in a 10 KB input today. In a 100 KB or 150 KB input it would cost about 1,020–1,030 ns per byte
  (EXTRAPOLATED). Today's worst *transaction*, the CHIP's l0fhm3, costs 972 ns per tx byte (MEASURED, same node), so
  the raised-limit worst case is about 5% above it per byte. The small rise is not quadratic.
  - The worst kernels have a per-input setup (filling the stack to 997 items, cleaning it up) that uses op-cost
    budget but little time.
  - So in a small input a larger share of the budget goes to cheap work.
  - The BCHN fit has a negative intercept (roll: a = −993 µs), which is this effect. In a larger input the share
    shrinks, and the per-byte time approaches the rate of the loop itself.
- **Per input: grows roughly linearly with the limit.** Today's slowest valid standard input takes **9.3 ms**
  (MEASURED, BCHN). A 100 KB input would take **about 90–102 ms**, a 150 KB input **about 130–154 ms** (EXTRAPOLATED,
  BCHN). At the upper ends that is about 11× and 16.5× for 10× and 15× the bytes; the extra is the per-byte rise
  above.
- **Per 100 KB standard tx: essentially unchanged.** Today's worst 100 KB tx takes 93–97 ms (MEASURED). A 100 KB tx
  made of one ~100 KB input would take about 102 ms (EXTRAPOLATED), +5%.
  - A 150 KB input does not fit the 100,000 B relay (standard) tx size limit. It would need that policy limit raised,
    or a miner including it directly; consensus allows txs up to 1 MB.
  - Either way, it costs about the same per byte.
- **Per block: probably similar, not measured.** The per-input budget, hash and sigcheck limits all stay
  proportional to bytes, so the per-byte worst case suggests a block's worst case still scales with its bytes.
  Block-level limits (sigchecks per block) and whole-block runs are not modelled here.
- **No kernel grew faster than linearly** on BCHN inside today's limits (2.5 → 5 → 10 KB), or on bchd-fork and
  libauth at 100 and 150 KB. The one exception is libauth only, and only if VM numbers are raised as well (see
  "Quadratic behaviour").

## Machine and engines

One machine; all results are from it: AMD Ryzen 9 7900 (Zen 4, 12C/24T), Linux 7.2.15, governor and EPP
`performance`, boost on (not controllable without root). Node and timers pinned to CPU 9, drivers to CPU 7, `nice -n
19`, one job at a time; load average 0.88–2.13 during the BCHN runs and 1.32–2.29 during the bchd/libauth runs (another agent ran light
modelling). `raw/en1-env.txt` reports the bchd-fork build as "1 uncommitted". That one entry is the untracked
`opcostbench` binary produced by the build; the source is exactly 4629051d + `bchd-raised-modes.patch` (commit 10fc9be5 at run time; its message was reworded afterwards, same tree).

| engine | what it can run | how timed | label |
|---|---|---|---|
| stock BCHN v29.1.0, regtest, localhost only, via `research/node-check/node.sh` | today's limits only. No BCHN build or flag raises the per-input limits (checked `bitcoind -help -help-debug`; the harness has none) | Track 1 rig (`opcost-timing/bchn/rig.ts`, unchanged): K copies of a tx in one block, `validateblocktemplate` × 11, BCHN's own `Verify N txins` line, median; sig/script caches 0 | **MEASURED (BCHN)** |
| bchd-fork `opcostbench` (Go; Track 1's driver, `-steady`) | raised limits: new modes `txv5-100k`, `txv5-150k` (+`num`), patch `bchd-raised-modes.patch` | steady state, 7 batches ≥ 300 ms, verdict + op-cost checked every eval | **MEASURED (bchd)** |
| libauth 3.1.0-next.8 (`libauth-time.ts`) | raised limits (gen.ts profiles) | same method | **MEASURED (libauth)** |
| BCHN at 100 / 150 KB | – | from BCHN's measurements, two ways (below) | **EXTRAPOLATED** |

**Extrapolation methods (BCHN at 100 / 150 KB).**
1. *Sweep fit:* BCHN per-input time at 5 KB and 10 KB fits t(L) = a + b·L. The loop body does not depend on L (stack
   depth ≤ 1,000, fixed operands), so the fit extends to larger L. This is the primary method for the worst kernels. Check: the 2.5 KB point, which the
   fit does not use, lies on the same line. For roll the fit predicts 1,584 µs; BCHN measured 1,604 µs.
2. *bchd-corrected:* BCHN time at 10 KB × (op-cost at L ÷ op-cost at 10 KB) × (bchd ns/op-cost at L ÷ at 10 KB).
   This is weaker for OP_ROLL, because bchd runs OP_ROLL 6.5× cheaper per op-cost unit than BCHN (0.18 against 1.17 ns).

Where the two differ, the higher one is quoted as the worst case.

**Raised-limit profile** (the same raised limits as `src/harness/vm.ts consensusTxv5`, at 100,000 B or 150,000 B).
The mode and profile IDs `txv5-100k`, `txv5-150k` and `+num` in the code, `raw/` and `tables.md` are code
identifiers only and stand for this profile.
- Raised to 100,000 / 150,000 B: maximum bytecode length (consensus, MAX_SCRIPT_SIZE) and stack item length
  (consensus), plus the standard unlocking length (relay).
- Unchanged: the 100,000 B standard tx size (relay policy only).
- Unchanged: density base 41, op-cost 800 per byte, hash iterations 0.5 (standard) / 3.5 (consensus) per byte,
  sigchecks (L + 60) / 43 per input and 3,000 per tx.
- VM numbers stay at 10,000 B. The `+num` variant also raises them to the item cap; only the mul kernels care.

## Kernels (gen.ts)

Each kernel is one P2S input: locking ≤ 201 B, unlocking push-only and padded to exactly L. The locking runs
`OP_BEGIN … OP_UNTIL` loops, with counts chosen to use as much of the budget as every limit allows.
- `std` kernels fit the standard op-cost (hash iterations at 192) and the standard hash limit. They passed
  `testmempoolaccept` on a POLICY=1 node, as single inputs and as 100 KB txs.
- `cons` kernels are only consensus-valid (a miner's own tx); the policy node rejects those that exceed standard limits.

| kernel | body |
|---|---|
| msig | 1-of-20 legacy `OP_CHECKMULTISIGVERIFY`, ECDSA signature for the key tried last: 19 failed verifies + 1 good per check. The good one repeats the same (signature, sighash, key) every pass, so it is likely served by the 2-entry cache after the first pass. That is consistent with the data: 687 µs per check ≈ 19 × 36 µs, close to one ECDSA verify on this CPU. Signed over the real outpoint by the rig (`resign`). Limited by sigcheck density, 75% of the budget. |
| roll | stack filled to 997 empty items, then `<995> OP_ROLL` to the budget |
| mix-msig-roll | msig to the sigcheck limit, then roll to the budget |
| mix-msig-hash-roll | msig, then `OP_RIPEMD160` of a large item to the hash limit, then roll |
| invoke | `OP_INVOKE` of an empty function |
| hash | `OP_DUP OP_RIPEMD160 OP_DROP` of the largest item, to the hash limit; only 16% (std) / 57% (cons) of the budget |
| mul1 / mod1 / mul32 | small-operand `OP_MUL` / `OP_MOD` |
| mulbig | the largest balanced `OP_MUL` that fits the budget and number cap |
| copy / cat | `OP_DUP OP_DROP` of the largest item; `OP_DUP OP_DUP OP_CAT OP_DROP` building the largest item |

The first run's `sig` kernel (`raw/superseded/wc1-*`) repeated one `OP_CHECKDATASIGVERIFY` 233 times. BCHN measured
0.013 ns/op-cost for it because the signature cache served the repeats.
- The node runs with `maxsigcachesize=0`, but BCHN still keeps a minimal cache. Its log says "Using 0 MiB out of 0
  requested for signature cache, able to store 2 elements".
- Two entries are enough to hold one repeated (signature, message, key) triple.
- A production node's 32 MiB cache would serve the repeats too, so a repeated identical signature is not a worst
  case.
- It was replaced by msig: BCHN caches only successful verifications, so msig's failed verifies are recomputed every
  time.

## Results

### Headline

| case | today (10 KB inputs) | 100 KB inputs | 150 KB inputs |
|---|--:|--:|--:|
| slowest standard input (roll); at 100 / 150 KB, standard under the assumed raised-limit profile (policy tested at today's limits only) | **9.32 ms** MEASURED (BCHN) | **≈ 102 ms** EXTRAPOLATED (sweep fit; bchd-corrected 90.5; linear 93.2) | **≈ 154 ms** EXTRAPOLATED (sweep fit; bchd-corrected 130) |
| same, ns per unlocking byte | 932 | ≈ 1,021 | ≈ 1,025 |
| ns per op-cost unit (roll) | 1.165 | ≈ 1.28 | ≈ 1.28 |
| highest ns per op-cost unit (msig) | 1.284; 7.55 ms per input | 1.28; ≈ 80–81 ms | 1.28; ≈ 103 ms (3,000 sigchecks/tx cap binds) |
| slowest 100 KB standard tx (at 100 KB: standard under the assumed raised-limit profile) | 92.6 ms (10 × roll), MEASURED (BCHN); l0fhm3 97.2 ms (972 ns/tx byte), MEASURED (BCHN) | ≈ 102 ms (one 99.9 KB roll input) EXTRAPOLATED | a 150 KB input does not fit a 100 KB standard tx; at the same per-byte rate, ≈ 154 ms per 150 KB tx |

The "100 KB tx" column for raised limits uses the sweep-fit rate per byte. Per tx byte, the worst case moves from
972 ns (l0fhm3) to about 1,020 ns (+5%). Per input byte, it moves from 932 ns to about 1,025 ns (+10%).

### Full tables

`tables.md` is generated by `analyze.py wc2 en1 raw/kernels.json`. It has four tables:
1. Today's limits, every kernel, std and cons, BCHN µs per input, ms per 100 KB tx, ns per op-cost, policy verdict
   (MEASURED, BCHN).
2. BCHN scaling at 2.5 / 5 / 10 KB (MEASURED, BCHN).
3. Raised limits: bchd ms and libauth ms (MEASURED on each engine), and BCHN bchd-corrected and linear extrapolations.
4. BCHN sweep-fit extrapolation to 100 / 150 KB (EXTRAPOLATED).

BCHN today, standard kernels (excerpt of table 1; MEASURED, BCHN):

| kernel | µs per 10 KB input | ns / op-cost | ns / unlocking byte | ms per 100 KB tx (10 in) |
|---|--:|--:|--:|--:|
| roll | 9,317 | 1.165 | 932 | 92.6 |
| mix-msig-roll | 9,042 | 1.157 | 904 | 89.8 |
| mix-msig-hash-roll | 8,218 | 1.110 | 822 | 81.7 |
| msig | 7,554 | **1.284** | 755 | 75.8 |
| mul1 | 2,081 | 0.259 | 208 | 20.8 |
| mod1 | 1,942 | 0.242 | 194 | 19.5 |
| invoke | 1,424 | 0.177 | 142 | 14.2 |
| mul32 | 916 | 0.114 | 92 | 9.2 |
| hash (std limit binds) | 433 | 0.661 | 43 | 4.3 |
| hash, cons (3.5 iter/B) | 3,069 | 0.667 | 307 | 30.5 |
| cat / copy / mulbig | 109 / 93 / 69 | 0.014 / 0.012 / 0.009 | 11 / 9 / 7 | 1.1 / 0.9 / 0.7 |

## Quadratic behaviour

- **BCHN, inside today's limits (2.5 → 5 → 10 KB, item sizes growing with L).**
  - Linear: hash, invoke, mul1, mod1 and mul32 hold a flat ns per op-cost unit (±2%).
  - Cheaper per byte as items grow: copy, cat and mulbig. BCHN's big multiply is far below its quadratic op-cost
    charge (0.009 ns/op-cost).
  - Rising toward a limit: roll, msig and the mixes. Their ns per op-cost rises (roll 0.79 → 1.04 → 1.17) because a
    per-input setup uses op-cost budget but little time. Its share of the budget falls as L grows (negative fit
    intercept, a = −993 µs for roll). The 5 → 10 KB slope is constant (roll 1,031 ns/B, i.e. 1.28–1.29
    ns per op-cost for the loop itself), so the per-byte cost approaches about 1,030 ns/B and stops there.
- **bchd-fork at 100 / 150 KB (MEASURED).** The ratio of ns/op-cost at L to ns/op-cost at 10 KB is 0.07–1.07 for
  every kernel; none is above 1.07. Big items (copy, cat, mulbig) get cheaper per unit.
- **libauth at 100 / 150 KB (MEASURED).** The ratio is 0.51–1.10 for every kernel in the raised-limit profile.
- **Recorded neutrally, libauth only (`+num` reading).** With VM numbers also raised to the item cap, one OP_MUL of a
  98,000 B number by a 734 B number (100 KB input), and of a 148,000 B number by a 729 B number (150 KB input)
  (`mulwide`), took libauth 402 ms at 100 KB and 1,952 ms at 150 KB.
  - That is 5.6 then 18.0 ns per op-cost: 4.9× the time for 1.5× the op-cost.
  - bchd ran the same two inputs in 2.2 ms and 3.7 ms (0.030 / 0.034 ns per op-cost, linear).
  - BCHN cannot run numbers over 10,000 B, so its behaviour here is unknown.
  - Cause not investigated. It matters only if a limit change also raises the VM number size.

## Not covered

- **One machine.** Bignum and libsecp256k1 timings scale differently across CPUs.
- **No BCHN build with raised limits.** BCHN's own behaviour on items over 10 KB (allocator, cache) is not measured.
  The bchd and libauth runs on large items suggest it is benign.
- **"Worst case" means the worst among these kernels**, plus the VM-limits vectors l0fhm3, ap38fd, w57j6w and trxhzt
  run as references on the same node. Not tried, deliberately:
  - code that is skipped but scanned inside loops (non-executed branches);
  - OP_INVOKE of large function bodies;
  - OP_CODESEPARATOR and sighash tricks;
  - bitwise shift kernels.
  These are the classes to examine next if this is taken further.
- **Block-level limits not modelled:** the sigchecks per block (block size / 141), whole-block worst cases, and the
  150 KB relay tx-size question.
- The kernels' standardness was tested with `testmempoolaccept` on a POLICY=1 node for today's limits only.
- The workload files (about 20 MB, `work/worst-case-timing/data`) are not committed. sha256 prefixes are in
  `raw/*-env.txt`, and `gen.ts` regenerates them deterministically. Per-kernel metrics are in `raw/kernels.json`.

## Reproduce

From the bench checkout root:
1. `npx tsx research/worst-case-timing/gen.ts <data>`
2. `DATA=<data> research/worst-case-timing/run-bchn.sh NAME 9 7 11` (fresh timing node and POLICY=1 node, both stopped)
3. Build bchd-fork `opcostbench` with `bchd-raised-modes.patch` (on 4629051d), then
   `UNITS=<data> BCHD=<dir> research/worst-case-timing/run-engines.sh NAME2 9`
4. `python3 research/worst-case-timing/analyze.py NAME NAME2 <data>/kernels.json > tables.md`

Runs in `raw/`: `wc2-*` (BCHN timing + policy), `en1-*` (bchd + libauth), `superseded/` (wc1, whose cached-signature
kernel was replaced; smoke).
