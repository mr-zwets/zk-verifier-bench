# Track 9: a post-quantum shielded pool on the Track 8 STARK verifier (S0–S3)

Status: research. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json.

## Track 9 (2026-11-01)

The sources are on groth16_cashscript `main` (merged at fd5b1d9; S0 19c42ae … S3 2cc79af, review fixes 86415d2, summary 69e5cf5). The design, with the maintainer decisions, is [DESIGN-T9.md](DESIGN-T9.md). The integrated summary is [`research/pq-pool/summary-t9.json`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/summary-t9.json) in groth16_cashscript.

**Scope.** This is the maintainer's 1-day cut (decision 6): S0–S3 only. It is a nullifier-enforcing pool over a **static genesis tree**. There are no deposits, no flush, no relayer and no SOUNDNESS-T9. S4–S7 are deferred (§9.9).

### 9.1 Question

Track 8 built a CashVM verifier for M1: a post-quantum, zero-knowledge proof of Merkle membership with a nullifier, bound to the spending transaction's outputs. Track 8 was explicitly **not a pool**. ROOT was a script constant, NF was not stored anywhere, and the same note could be spent twice.

Track 9 asks: **can the Track 8 verifier be turned into a pool that enforces nullifiers on chain, under today's standard BCH rules, and run on stock BCHN?** Under that sits a second question the design could only estimate: what do Poseidon2-Goldilocks hashing and a nullifier set cost in CashVM Script? The Poseidon2 cost decides whether deposits can later be added to the tree on chain.

**Answer, for the S0–S3 scope: yes.**
- A 2-transaction withdrawal (the Track 8 a′ plan plus a W-state covenant) is 132,640 B at the empty nullifier set. Every input stays under its BCHN-adjusted op-cost budget, with the busiest at 91.1%.
- On BCHN 29.1.0 regtest it accepted 24/24 withdrawals and rejected an NF double spend, both in the mempool and in a block. A 10-withdrawal unconfirmed chain was mined in one block, and a race loser rebuilt its tx1 without re-proving.
- One Poseidon2-Gl-8 permutation costs about 0.58M op-cost. That keeps the design's k = 4 flush (16 deposits, 4 standard inputs).

### 9.2 What was built

The protocol follows DESIGN-T9 and the maintainer decisions:
- the nullifier set is a SHA-256 sparse Merkle tree (SMT) of depth 64, keyed by a 64-bit truncated hash of NF;
- CTX is computed over outputs[1..];
- the 2-tx a′ plan plus W is the baseline;
- the denomination is D = 0.01 BCH (regtest).

| stage | what | where (groth16_cashscript `research/pq-pool/`) |
|---|---|---|
| **S0** | Poseidon2-Gl-8 permutation and 4-lane compression in CashVM Script; the flush-input fit and the flush op-cost table | `p2/` |
| **S1** | SHA-256 SMT reference (JS) and script (two loops); **W-state covenant** (P2SH32, 499 B redeem); static genesis history (2 epochs × 16 notes) | `w/` |
| **S2** | **Pool R** (three changes to Track 8's a′ verifier); the prover takes an explicit witness; the 24 M1 statements re-proved on genesis notes; grading and sweeps | `r/`, `prover/` |
| **S3** | BCHN 29.1.0 regtest: real W token geneses, 24 withdrawals, NF replay, 10-chain, race, conflict | `node/` |

**The withdrawal** (2 transactions, 17 inputs):
- **tx0** (11 inputs) is the Track 8 a′ first transaction, unchanged in structure. It verifies the proof's HEAD/CODE part and mints the thread NFT.
- **tx1** (6 inputs) has R at inputs 0–4 and **W at input 5**. Its outputs are:
  - output 0, the next W state;
  - outputs 1 and onward, the payout (bound by CTX).

**W** (the W-state covenant, `w/wcov.mjs`) is a P2SH32 locking holding one mutable NFT of the pool category CAT. Its commitment is `0x57 ‖ nfRoot ‖ histRoot ‖ epoch`. W checks:
- **Input graph.** The input count, its own index, and SHA-256 of input 0's locking = HR (the hash of R's P2S locking). W thereby requires R, but R does not reference W, so there is no hash cycle.
- **HEAD's tail.** W reads input 0's unlocking with `OP_INPUTBYTECODE`. Its last three pushes must be ROOT, NF and CTXW, 32 B each, with every push header checked.
- **Ring.** ROOT ≠ Z and ROOT is in the 16-slot ring of epoch roots (`histRoot`, 4 SHA-256 levels).
- **Nullifier set.** NF's key is absent from nfRoot, and nfRoot is updated to insert it with one compressed path.
- **Output 0.** The same locking and CAT‖01, no fungible tokens, the commitment carried over with the new nfRoot, and value = input value − D.

**The R changes** (`r/gena.mjs`, `r/ctx.mjs`; copies, Track 8 files untouched):
1. **ROOT is a HEAD push.** HEAD's items are now ROOTS OOD BPOW FROOTS CPOW QPOW **ROOT** NF CTXW. Every transcript-running input checks that ROOT's lanes are < p, the transcript observes ROOT, and the constraint DAG reads it. One (R, W) pair serves all statements. R is 118 B.
2. **CTX covers outputs[1..]**, with a count of n − 1, and must run at least once. The proof therefore does not depend on the pool state, so after a race a relayer rebuilds tx1 without re-proving.
3. **A graph slot for W.** In tx1, inputs 0–4 must be R and input 5 must not be R. The thread rules skip input 5 and output 0, and output 0 must not carry the thread category.

**The SMT** is depth 64 with SHA-256 nodes and an empty-subtree constant Z. A compressed path is a 64-bit bitmap B, the non-Z siblings, and **L, the lowest set bit of B** (1–2 B). L was added to the design in S1, and the script checks it with LSHIFTNUM/RSHIFTNUM. The script runs two loops:
- **Loop A** covers the levels below L, where every sibling is Z. It hashes only the new path, at about 22 instructions per level.
- **Loop B** covers the rest and hashes both the old and the new root, at about 63 instructions per level.

A sent sibling must not be Z, every bitmap bit and sibling byte must be used, and the loop must end after exactly 64 levels. Every path therefore has exactly one encoding.

### 9.3 Poseidon2 cost (S0)

The script was tested on 1,005 inputs: Plonky3's test vector, 1,000 random inputs and 4 edge inputs. On all of them, the script, the JS reference and p3-goldilocks agree, checked through a small Rust binary at the Track 8 Plonky3 pin. 100 plain rejections (one output lane +1 or +p) were all rejected.

| | op-cost (libauth = BCHN, straight-line, no OP_DEFINE inside) | instructions | code |
|---|--:|--:|--:|
| 8-lane permutation | **580,112–582,868** (mean 582,070) | 4,251 | 7,681 B |
| 4-lane compression | 571,221–573,974 | 4,173 | 7,567 B |
| compression inside a loop | 574,314 | | |

- **The 1.2M gate is not triggered, so k = 4 stays.** Most of the cost is the 100 op-cost per instruction (about 425K). Arithmetic is about 115K and pushed bytes about 41K.
- **Optimizations:**
  - reducing x³ inside the S-box saves 75K;
  - Plonky3's M4 addition chain together with a 3DUP partial-round sum saves another 17K;
  - the plain version costs 673K.
- **Pitfall.** `JSON.parse` rounds the 64-bit round constants. The first build used rounded constants in both the script and the JS reference, so the two agreed with each other but were wrong. Plonky3's test vector caught this. The constants are now parsed as BigInt.

**A flush worker input** (standard rules, P2S locking, 10,000 B unlocking, budget 8,032,800) fits **13 compressions**, at 7,516,362 BCHN-adjusted (93.6%). This counts the code's 7,567 B DEFINE body once per input. 14 compressions exceed the budget even in libauth alone. With one 100 KB input, 138 compressions fit.

**Flush table** (BCHN-adjusted; Poseidon2 only):

| flush size | k | compressions | op-cost | inputs today (10 KB, 13 each) | 100 KB inputs |
|--:|--:|--:|--:|--:|--:|
| 1 (per deposit) | 0 | 30 | 17.38M | 3 | 1 |
| 16 | **4** | 41 | **23.75M** | **4** | 1 |
| 32 | 5 | 56 | 32.41M | 5 | 1 |
| 64 | 6 | 87 | 50.32M | 7 | 1 |

The design estimated 20–41M and 3–5 inputs for k = 4. The other parts of a flush are not measured: the queue SHA-256, the frontier check, the ring update, the lane < p checks and the covenant checks are S4. My unmeasured estimate for them is under 1M; k = 4 leaves 11 compression slots spare, about 6.3M. The flush covenant itself was not built.

On BCHN 29.1.0 regtest, the 13-compression input was allowed by testmempoolaccept and mined, and the bench's DEFINE-charging libauth gives exactly the BCHN-adjusted figure. A DEFINE probe, with its budget set between libauth alone and libauth plus the DEFINE bytes, was rejected by policy with "VM cost limit exceeded", as node-check predicts.

### 9.4 Nullifier SMT cost (S1)

**The SMT costs about 3× the design's estimate.** The design estimated 0.2M but left out the 100 op-cost per instruction. A straightforward single-loop script (about 81 instructions per level) costs 0.575M. That exceeds a W input's budget, about 0.52M at a 650 B unlocking, because W's budget is small: W carries no padding. The two-loop rewrite (§9.2) costs 0.19–0.23M on natural trees.

| W input (libauth, today's standard rules) | unlocking | op-cost | share of budget |
|---|--:|--:|--:|
| empty set (L = 64, loop A only) | 645 B | 221,167 | 40.3% |
| 10,000-transaction random run | 645 B–1.1 KB | 219,804–353,984 | ≤ 41.3% |
| **constructed worst case:** one stored key equal to K xor 1 (L = 0, 1 sibling, loop B over 64 levels) | 676 B | 519,621 | **90.6%** |
| 64 siblings | | | 30.3% (tx 3,069 B) |

- **Why the worst case stays in budget.** Each extra sibling adds 32 B of unlocking, which is 25.6K of budget, so more siblings only lower the share. The constructed worst case therefore has a single sibling.
- **Nobody can aim for the worst case.** It needs a stored key that shares the top 63 bits with the new key, and keys are hashes of hidden NFs.
- **The SMT is depth 64.** Accidental 64-bit key collisions give only a false "already spent", about 2^-25 at 2^20 spends (maintainer decision 1).
- **W adds about 0.75–1.2 KB to tx1.** The design allowed 1.5–1.9 KB.

### 9.5 Withdrawal sizes and op-cost per input

libauth BCH 2026, today's standard rules, 24 statements. Op-cost is **BCHN-adjusted**: libauth plus 37,790 B of OP_DEFINE bodies per R input, since the stock libauth used here does not charge DEFINE bytes. The budget is (41 + unlocking) × 800 per input. The W input spends the genesis state (empty nullifier set).

| plan | accepted | transactions (inputs) | bytes | max input |
|---|--:|---|---|--:|
| **2-tx a′ + W (baseline)** | **24/24** | 2 (11 + 6) | 91,183 + 41,457 = **132,640** | **91.1%** (QRY) |
| 1-tx a′ + W (measured only) | 24/24 | 1 (13) | 99,594 (406 B under 100,000) | 91.0% (QRY) |

Per role, 2-tx plan:

| role | unlocking | op-cost (BCHN-adjusted) | share of its budget |
|---|--:|--:|--:|
| HEAD | 6,487 B | 1.33M (tx0) / 0.53M (tx1) | 25.4% max |
| CODE1 | 9,547–9,572 B | 5.50M (tx0) / 0.24M (tx1) | 71.5% max |
| CODE2 | 9,544–9,569 B | 5.01M (tx0) / 0.24M (tx1) | 65.2% max |
| FIN | 6,462 B | 3.76–3.79M | 72.8% |
| QRY | 8,322 B | 6.07–6.09M | **90.7–91.1%** (Track 8: 90.7–91.0%) |
| W | 645 B (genesis) – 838 B (24th spend, S3) | 0.233–0.287M | 36.8–44.0% |

- **Compared with Track 8's 2-tx a′ plan** (131,556 B), the withdrawal grows by **1,084 B**:
  - tx0 grows by 124 B, from the 33 B ROOT push and larger code blobs;
  - tx1 grows by 960 B, from the W input and output plus the same code growth.
- **tx1 grows with the SMT path.** In S3 it was 41,457–41,650 B over 24 spends.
- **The 1-tx plan fits only at small nullifier sets.** The design expected it not to fit at all. It exceeds 100,000 B once the compressed path adds about 400 B, which I estimate at a few thousand spends (S1 measured about 1.0 KB of W unlocking at 1,000 spends). Maintainer decision 3 dropped the 1-tx plan for the pool, so this is a measurement only.
- **Value flow.** W releases exactly D per withdrawal: a payout of 950,000 sat and φ = 50,000 sat toward fees.
- **Fees on BCHN.** tx0 paid 2.30 sat/B (about 210,000 sat) and tx1 1.51–1.52 sat/B (about 63,000 sat). That is about 0.0027 BCH per withdrawal at these test rates, at the top of the design's 0.0013–0.0027 BCH estimate.

### 9.6 BCHN results (S3)

One fresh node: stock BCHN 29.1.0 (`/Bitcoin Cash Node:29.1.0(EB32.0)/`), regtest, `acceptnonstdtxn=0` and default relay policy, listen=0, connect=0, rpcbind 127.0.0.1. It was stopped afterwards. The run used S2's 24 proofs without re-proving.

| check (DESIGN-T9 §6 S3) | result |
|---|---|
| real W geneses | Two pools: A funded with 30 D, B with 20 D. Each W is a token genesis: a coinbase output spent into **one mutable NFT** of CAT = that coinbase's txid, with **no minting NFT ever created**. BCHN's decoded genesis shows this (`noMintingNft: true`). |
| **24/24 accepted** | Pool A, statements 0–23. For each, tx0 and tx1 were allowed by testmempoolaccept and sent, tx1 with tx0 still unconfirmed, and both were mined in the same block. After every step, BCHN's `gettxout` of W matched the JS state: value, category, capability, commitment and locking. |
| **NF double spend rejected** | Statement 0 replayed on pool A. The fresh tx0 is valid and was mined. tx1, with either the honest present-key witness or a stale absence witness, was rejected by libauth at W (OP_VERIFY), by testmempoolaccept and sendrawtransaction (`16: mandatory-script-verify-flag-failed (OP_EQUALVERIFY)`), and as a block (`blk-bad-inputs`). W was unchanged. |
| **10-withdrawal unconfirmed chain** | Pool B, statements 0–9. All 20 transactions were sent unconfirmed, each tx1 spending the previous tx1's output 0. BCHN's own block assembler mined all of them in one block (21 txs, 1,327,416 B), and the mempool was empty afterwards. |
| **race, rebuilt not re-proved** | Statements 10 and 11 on one W outpoint. The loser's tx1 was refused (`18: txn-mempool-conflict`). It was then rebuilt on the winner's unconfirmed output 0: tx0 byte-identical, R inputs 0–4 identical, same payout; only the W input and output 0 changed. The rebuild was allowed and mined. |
| same NF in conflicting transactions (extra) | Statement 12 relayed twice. The second tx1 is a mempool conflict. Rebuilt on the first one's state, it is rejected by W in libauth, by testmempoolaccept and as a block. |
| **testmempoolaccept at the default policy** | **76/76 valid withdrawal transactions (tx0 and tx1) allowed.** The only 5 refusals are the expected ones: 3 script failures and 2 mempool conflicts. |

- On a real node the thread category is the faucet's, so R was rebuilt (SHA-256 199fcb9a…3481). Only its 32 category bytes differ from S2's R, and its size is unchanged.
- Pool B reuses statements 0–12 on a second W genesis with the same ring. That is valid behaviour for this setup, and it is why §9.8's caveat on ring roots per pool exists.
- **Not timed.** Track 8's [node check](../node-check/README.md#track-8-stark-m1) already timed the a′ plan, at 16.6–17.0 ms Verify per 1-tx proof.

S0 and S1 also ran on BCHN regtest, each on its own fresh node:
- **S0:** the 13-compression flush input and the DEFINE probe (§9.3).
- **S1:** four W withdrawals paired with a stand-in R, all allowed and mined: from genesis, after 1,000 spends, the 90.6% worst case, and with 64 siblings. This confirmed that 2026 loops, the shift opcodes and a P2SH32 token covenant work on BCHN.

### 9.7 Tests

All tests are plain rejection tests, with no attack construction.

| suite | cases | result |
|---|--:|---|
| S0 Poseidon2: script vs p3-goldilocks (test vector, 1,000 random, 4 edge) | 1,005 | 0 disagreements |
| S0 plain rejections (one output lane +1 / +p) | 100 | all rejected |
| S1 SMT script vs JS reference SMT (6,449 inserts, 3,551 present keys; every L from 0 to 64) | 10,000 | 0 disagreements |
| S1 W covenant on whole transactions (7,460 withdrawals, 2,540 already-spent NFs) | 10,000 | 0 disagreements |
| S1 rejection families (NF+1, present key, bitmap/L, sibling, ring, carry-over, output, value, graph, HEAD) | 199 + 4 controls | all 199 rejected by W; 0 'limit' |
| S1 double spend in sequence | 1 | second rejected |
| S2 production sweep: 2-tx + W, all Track 8 S7 families + the pool families | **4,977** | **0 unexpected** |
| S2 harness sweep: 1-tx without W (Track 8 S7 accounting) | 2,387 | 0 unexpected (equal to Track 8 S7's totals) |
| S3 BCHN | §9.6 | all pass |

- **How to read the 4,977.** It is not 4,977 on-chain rejections. It splits into 4,834 chain rejections, 88 required accepts, and 55 encoder-only relabels. An encoder-only relabel is a proof malformed by length whose on-chain witness is the valid one, so the script accepts it. This is the same accounting as Track 8 S7.
- **Not counted in the 4,977:**
  - 26 n/a cases, where a public value is ≥ 2^64;
  - 18 no-op tampers that were skipped: "ROOT of another tree" taken from a note in the same epoch, which has the same root;
  - 26 documented runs of the R-does-not-pin-W property (§9.8).
- **New pool families in the production sweep:**

| family | cases | what is checked |
|---|--:|---|
| nf | 86 | The same NF twice, in sequence and in conflicting transactions. The same proof, a stale witness and a second-seed proof are each rejected by W; 30 required accepts are the honest first spends. |
| ring | 78 | A valid Track 8 proof whose ROOT is not in the ring, the wrong slot, and an empty slot are rejected by W, with every R input accepting. |
| windex | 130 | W at the wrong index, missing, or replaced by an R input is rejected. |
| commit | 104 | A mismatched output-0 commitment is rejected by W. |
| out0 | 208 | Changing output 0 is rejected by W only. A rebuild after a race is accepted (26/26). Changing any output ≥ 1 is rejected by HEAD (CTX). |
| wonly | 52 | W without R at input 0 is rejected by W. |

- **Run-time guards.** S2's verdicts are 3-way, and after the review fix S1's are too. A failure on the standard VM that the loose VM accepts is labelled 'limit' and never counted as a rejection. Any tamper that leaves the transaction unchanged fails its case.

### 9.8 Review, fixes and caveats

**Review.** One internal review covered protocol and soundness against DESIGN-T9, the W covenant (with the SMT traced by hand), the R changes, BCHN op-cost accounting, harness accounting, and branch hygiene. **Verdict: pass, with 0 blocker, 0 major and 6 minor findings.** The reviewer also re-ran the S1 W suite with a new seed (seed 2, 3,000 + 3,000 cases); it passed with the same worst case, 90.59%.

**Fixes** (86415d2): all 6 minors were applied. Five are documentation: items A1–A5 in `research/pq-pool/README.md`, to be used by SOUNDNESS-T9. One is a harness change: S1's rejections now use the 3-way verdict. S1 was re-run with seed 1 and passed with identical results (199 rejections, 0 'limit'). No R, W or prover code changed.

| # | finding | resolution |
|---|---|---|
| 1 | **R does not pin W.** Any non-W input in slot 5 passes R. | Documented as griefing only (A3). No pool funds move, because outputs[1..] are bound by CTX and pool funds leave only through W. The user loses the thread NFT and R carriers and can redo tx0 with the same proof. Closing it means pinning CAT‖01 at wIdx, which creates no hash cycle but makes R pool-specific. **Left for the maintainer.** |
| 2 | **Nullifiers are per pool.** The proof binds only ROOT, NF and CTX. | Documented (A1). L6 (withdrawals ≤ deposits) holds per pool only if each pool's ring roots are its own. A static genesis tree must never seed more than one funded pool; S3's pool B is a test of exactly that case, not a deployment pattern. Adding the pool category to the leaf or NF domain is a possible later change. |
| 3 | **State uniqueness (L1) rests on "no minting NFT of CAT ever existed",** which W cannot check. | Documented (A2) as an off-chain check by wallets and relayers. S3 confirmed it for both geneses. To be re-checked at S4. |
| 4 | The testmempoolaccept 76/76 covers withdrawal transactions only. | Reworded (A4). The geneses and funding transactions spend bare-OP_1 coinbases through submitblock. |
| 5 | The 4,977 headline mixes rejections, accepts and relabels. | A per-family table was added (A5, §9.7). |
| 6 | S1 rejections used the standard VM only. | Changed to the 3-way verdict, and S1 re-run (PASS). |

**Caveats:**
- **Static genesis tree: no deposits and no flush yet.** The history is a fixed ring of 2 epoch roots over 32 genesis notes (k = 4), built offline. S1 builds it with the JS Poseidon2, and S2's proofs confirm it matches the Rust prover. The D-state, the queue, the flush covenant and ring wraparound do not exist (S4). Only the Poseidon2 cost of a flush is measured; a pool that takes deposits has not been demonstrated.
- **Simulation extractability is assumed, not proved** (carried over from Track 8). It is what stops a relayer or mempool observer from re-binding someone's proof to new outputs[1..].
- **Track 5's powers-batching adaptation is unpublished and unreviewed.** Every λ figure rests on it, carried over unchanged from Track 8.
- **About 85-bit quantum collision level.** 128 bits is the classical figure. Digests are 4-element Poseidon2-Goldilocks in the circuit and SHA-256 in the transcript, the SMT and the ring. Generic quantum collision search (BHT) on these reaches about 85 bits, the level of SHA-256 itself, which the maintainer accepted in Track 8. The 64-bit SMT key affects only liveness: an accidental collision gives a false "already spent".
- **Fixed denomination.** Every note is worth D = 0.01 BCH (regtest), and W releases exactly D per withdrawal. There is no variable amount and no change.
- **Anonymity set.** It is per pool. Today it is the 32 genesis notes, whose secrets are published in `w/results/genesis.json`, so this setup provides **no privacy at all**; it is a test pool. With S4, the set grows in flush-sized chunks of 16, and a withdrawal hides only among notes whose roots are still in the ring (16 epochs).
- **The W unlocking grows with the set.** It is 645 B at genesis, about 1.0 KB at 1,000 spends and about 1.13 KB at 2^16 spends, so tx1 grows slowly. The constructed worst case is 90.6% of W's budget.
- **Tight budget.** QRY runs at 91.1% of its budget, as in Track 8.
- **The fee and relayer model is not built (S5).** Fees were measured only at the regtest test rates in §9.5.
- **Proved statements.** Only notes 0–23 have proofs. S3's pool B reuses statements 0–12.
- **Not timed.** See Track 8's node check.

### 9.9 What's next (S4–S7, deferred by the maintainer)

- **S4 – D-state, queue, flush, ring.** Deposits go into a SHA-256 queue. A permissionless flush appends 16 leaves with Poseidon2 in Script, using the 4-input budget measured in S0, and rotates the 16-slot ring. Acceptance:
  - the flush root equals the offline tree over 64 sequential deposits;
  - ring wraparound expires a stale root;
  - a premature flush, a wrong frontier and a leaf lane ≥ p are each rejected;
  - an end-to-end deposit → flush → prove → withdraw runs on BCHN.

  The non-Poseidon2 cost of a flush, and the A2 baton check for D-state deposits, are measured and re-checked here.
- **S5 – relayer reference.** A CLI that builds tx0/tx1, pays φ, and rebuilds after a race. S3's race already shows that a rebuild needs no re-proving.
- **S6 (optional) – M1-N** for N = 2 and 4 (one user's notes in one proof), with λ re-checked in params8.
- **S7 – SOUNDNESS-T9 and reviews**, using A1–A5. Open maintainer calls for S7:
  - whether R pins W's category;
  - whether the pool category goes into the leaf or NF domain.

### 9.10 Sources

groth16_cashscript `main`, [`research/pq-pool/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool):
- [`README.md`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/README.md): the stage index and assumptions A1–A5 (input to SOUNDNESS-T9).
- [`summary-t9.mjs`, `summary-t9.json`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/summary-t9.json): the integrated S0–S3 summary.
- [`p2/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool/p2) (S0):
  - `p2gl8.mjs`, which provides `genPerm`, `permCode` and `permRef`;
  - `poseidon2-gl8-constants.json`;
  - `p3ref/`, a Rust p3-goldilocks reference binary;
  - `test-p2.mjs`, `flush-fit.mjs`, `s0-bchn-export.mjs`;
  - `results/s0-p2.json`, `s0-flush.json`, `s0-bchn-policy.jsonl`.
- [`w/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool/w) (S1):
  - `smt.mjs` (the reference SMT), `wcov.mjs` (the W covenant), `wtx.mjs`, `genesis.mjs`, `test-w.mjs`, `s1-bchn-export.mjs`;
  - `results/s1-w.json`, `genesis.json`, `s1-bchn-policy.jsonl`.
- [`r/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool/r) (S2):
  - `gena.mjs`, `ctx.mjs`, `layouta.mjs`, `pool.mjs`, `genn.mjs`, `gen-statements.mjs`, `grade-a.mjs`, `test-a.mjs`, `gen-s2.sh`;
  - `results/grade-a.{txt,json}`, `test-a-2tx-pool.json`, `test-a-harness.json`, `test-a.txt`, `gen-vec.txt`.
- [`prover/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool/prover) (S2): the Track 8 batch-stark prover with an explicit-witness case `m1@LEAF@0@CTX@WIT` (circuit unchanged), and `vectors/S2` (3 of the 24 statements).
- [`node/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool/node) (S3):
  - `s3.ts` (the driver), `rig.ts` and `node.sh` (copies of bench node-check), `run-s3.sh`, `summarize-s3.mjs`;
  - `results/s3.jsonl`, `s3.log`, `s3-summary.json`.

Track 8's verifier on `main` ([`research/pq-stark-batch/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark-batch)) is unchanged; Track 9 works on copies.

zk-verifier-bench (this folder): [DESIGN-T9.md](DESIGN-T9.md) with the maintainer decisions, and `t9calc.py` (the design's estimate calculator). See also [the Track 8 report](../pq-stark/REPORT.md) and [node-check](../node-check/README.md).

Development branch: groth16_cashscript `wip/pool`:
- S0 19c42ae, 1fb9a3a;
- S1 1b79964, 8ed52de, 3cd10cd;
- S2 1dbdef8, 1ab99ec;
- S3 2cc79af;
- review fixes 86415d2;
- summary 69e5cf5.

**Reproduce** (groth16_cashscript `research/pq-pool`):
- Run Rust under nice, with RAYON_NUM_THREADS=4 and `-j4`, and run one heavy job at a time.
- A repo-root `node_modules` (gitignored) must hold libauth 3.1.0-next.8 and tsx.
- BCHN runs need a bench checkout (`research/node-check`) and a fresh regtest node per run.

```sh
C=/path/cache; export OPCOST_DIR=/path/bchn-datadirs
# S0: Poseidon2 (minutes)
cd p2 && CARGO_TARGET_DIR=$C/target-p3ref nice cargo build --release --offline -j4 --manifest-path p3ref/Cargo.toml
node test-p2.mjs --cache $C && node flush-fit.mjs && node s0-bchn-export.mjs $C/s0-bchn/t9-s0.json
#   bench: POLICY=1 research/node-check/node.sh start NAME 9
#          npx tsx research/node-check/nc.ts policy --node NAME --src json:$C/s0-bchn/t9-s0.json --out policy.jsonl
#          research/node-check/node.sh stop NAME
# S1: SMT + W (about 4 min)
cd ../w && node genesis.mjs && nice node test-w.mjs          # --lib 10000 --w 10000 --seed 1
node s1-bchn-export.mjs $(npx tsx <bench>/research/node-check/nc.ts category) $C/s1-bchn/t9-s1.json   # then as S0
# S2: re-prove 24 statements, grade, sweeps (about 10 min; needs Track 8 S7 vectors and S3 case files)
cd ../r && CARGO_TARGET_DIR=$C/target S2_CACHE=$C/s2 T8_S7_VEC=<T8 cache>/s7/vec T8_S3_CASES=<T8 cache>/s3/cases ./gen-s2.sh
# S3: BCHN regtest 2-tx withdrawals (about 15 min, fresh node NAME)
cd ../node && S2_VEC=$C/s2/vec ./run-s3.sh NAME
# summary
cd .. && node summary-t9.mjs                                  # summary-t9.json
```