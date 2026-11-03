# Track 9: a post-quantum shielded pool on the Track 8 STARK verifier (S0–S4, soundness)

Status: research. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json.

## Track 9b (2026-11-01): deposits, flush and soundness

The sources are in groth16_cashscript `research/pq-pool/` (merged to `main` at 88f0719; developed on `wip/pool9b`: S4 8953563 … 2f8f931, SOUNDNESS-T9 545b8c8, review fixes 029d8f2, summary 8808381). The integrated summary is [`research/pq-pool/summary-s4.json`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/summary-s4.json). The design is [DESIGN-T9.md](DESIGN-T9.md).

**Scope.** Track 9 (below) stopped at a static genesis tree. Track 9b adds S4 (deposits, the queue, the permissionless flush, the 16-slot ring, R pinning the pool's W) and S7a (SOUNDNESS-T9 with one review round). The relayer (S5) and M1-N (S6) are still not built.

**Answer: a pool that takes deposits works under today's standard rules and on stock BCHN.**
- A deposit is 645 B. A flush of 16 deposits is one 42.1 KB transaction (D, W and 4 worker inputs, 41 Poseidon2 compressions) with every input under its BCHN-adjusted budget, the busiest at 91.1% (91.9% in a synthetic edge state).
- On BCHN 29.1.0 regtest (POLICY=1): a policy-tested genesis, 272 deposits, 17 flushes whose roots all equal the offline Poseidon2 tree, 5 fresh proofs and 4 withdrawals against flushed roots. A root 17 flushes old was rejected by W in the mempool and in a block.
- SOUNDNESS-T9 argues L1–L7 per pool (state uniqueness, nullifier set, ring, verifier, one NF per leaf, conservation, binding) under stated hash, proof-system and deployment assumptions. The review found 0 blocker, 0 major and 8 minor issues, all fixed in documentation.

### 9b.1 What changed

| | change | where (`research/pq-pool/`) |
|---|---|---|
| **D state** | New P2SH32 covenant (291 B redeem), the second mutable NFT of the pool category CAT (prefix 0x44; W is 0x57). Commitment `0x44 ‖ queue ‖ depHash`: queue = SHA-256(len ‖ chain) of up to 16 queued leaves, depHash = SHA-256(count ‖ frontier at levels 4..29). | `d/dcov.mjs` `buildD` |
| **Deposit** | Requires len < 16, a 32 B leaf with every lane < p, and D′ = D + δ + f with the extended queue. | `d/dcov.mjs` |
| **Flush coordinator** | D's redeem runs a 2,209 B blob it holds by HASH256. It re-derives the queue from the 16 leaves (so len = 16, order kept), checks the frontier against depHash, writes the new root into ring slot epoch mod 16 (old slot proven with 4 siblings), builds each worker's expected IO program and compares it with that worker's first push, and moves 16δ from D to W. The keeper takes the released 16f. | `d/dcov.mjs` `flushBlob` |
| **Flush workers** | One 43 B P2S locking (`DEPTH 3`, H(WBLOB)) running S0's compression plus a 4-op IO interpreter. The 41 compressions split 10 / 12 / 12 / 7. | `d/dcov.mjs` `workerBlob`, `workerLocking` |
| **W flush branch** | W accepts a flush only with the real D at input 0 whose value drops by 16(δ + f), which only D's flush branch allows. W's redeem grows from 499 to 671 B. | `w/wcov.mjs` |
| **R pins W (A3)** | In tx1, HEAD checks input 5: category CAT ‖ 0x01 and commitment prefix 0x57 (the prefix is needed because D shares CAT). R becomes pool specific. | `r/gena.mjs` |
| **Genesis** | CAT is the txid of a funding outpoint, fixed before R, W and D are built (no hash cycle). The genesis creates exactly two mutable NFTs of CAT and no minting NFT. | `d/dpool.mjs`, `node/s4.ts` |

### 9b.2 Sizes and op-cost per input

libauth BCH 2026, today's standard rules. Op-cost is **BCHN-adjusted** (libauth plus the OP_DEFINE body bytes BCHN charges per input). Budget (41 + unlocking) × 800. Ranges over the 17 flushes of the libauth run.

| transaction / input | bytes | op-cost (BCHN-adjusted) | share of its budget |
|---|--:|--:|--:|
| **deposit** (2 inputs, 2 outputs) | **645** | D input 18,598–18,611 | 5.8% |
| **flush** (6 inputs, 3 outputs) | **42,127–42,129** | 25.4M in all | **max 91.1%** |
| – D (coordinator) | unlocking 4,213 | 0.699–0.700M | 20.6% |
| – W (flush branch) | 674 | 0.048M | 8.3% |
| – worker 1 (10 compressions) | 8,600 | 6.07M | 87.9% |
| – worker 2 (12) | 10,000 | 7.27–7.32M | **91.1%** |
| – worker 3 (12) | 10,000 | 7.24M | 90.2% (91.9% when every bit of count is set) |
| – worker 4 (7) | 8,036 | 4.25M | 65.9% |
| **withdrawal** at the genesis state (2-tx a′ + W) | 91,229 + 41,675 = **132,904** | max 91.1% (QRY) | Track 9: 132,640 |

- **The S0 flush estimate holds.** S0 measured 41 compressions at 23.75M in 4 inputs; the built flush is 4 workers plus D and W. The non-Poseidon2 work S0 left open (queue hashes, frontier, ring, IO building, reading the worker unlockings, W) costs about 0.75M, and the lane checks and interpreter add about 2% per worker.
- **Depositors cannot push a flush over budget.** The review measured worker op-cost for honest flushes with leaf lanes random, 0, 1, p − 1, 2^63 and all-ones: it moves by at most about 0.2%. The worker IO sizes depend only on count's bits and the position of the lowest zero bit, never on the data (472–~560 B), so the fixed PUSHDATA2 IO header is always minimal.
- **What A3 costs the withdrawal.** tx0 and tx1 each grow by 46 B, and BCHN's per-R-input OP_DEFINE charge grows by 92 B (37,790 → 37,882 B). Proofs are not pool specific.
- **Fees.** On BCHN the flush paid 1.19 sat/B (50,000 sat); the keeper output got 118,000 sat (16f = 160,000 minus the fee, plus 4 × 2,000 sat workers). A third-party keeper breaks even only if 16f ≥ (flush bytes + worker-setup bytes) × feerate: f_min ≈ (42,129 + ~400) × feerate / 16 ≈ **2.7k sat at 1 sat/B** (the ~400 B setup transaction is an estimate). The regtest f = 10,000 sat covers about 3.7 sat/B.

### 9b.3 BCHN end to end (S4)

One fresh node (`t9s4a`): stock BCHN 29.1.0 regtest, POLICY=1 (`acceptnonstdtxn=0`, default relay policy), `node.sh` identical to the bench copy, stopped afterwards.

| step | result |
|---|---|
| **genesis** | Spends a P2SH32(OP_1) output, so it was **policy-tested** (allowed). BCHN decodes exactly 2 outputs of CAT, both mutable (0x44, 0x57), no minting NFT. 389 B. |
| **272 deposits** | 645 B each, allowed by testmempoolaccept, sent as unconfirmed chains on D, mined 16 per block. |
| **17 flushes** | 42,127–42,129 B, max input 90.5–91.1%, all allowed and mined. **Root = offline tree 17/17.** After every step, `gettxout` of D and W matched the JS state (value, category, capability, commitment, locking). |
| **proofs** | The Track 8 prover with an explicit witness (nk, r, 30 siblings from the offline tree): 5 proofs, 73,744–76,208 B, 2.5–5.6 s; public values equal (flush root, NF, CTX). |
| **4 withdrawals** | Note 3 @ root 0 and note 20 @ root 1 (after the second flush), note 5 @ root 0 at epoch 16, note 9 @ root 16 (new proof). Each tx0 + tx1 allowed and mined: 91,229 + 41,675–41,739 B, max input 91.1%, W 33–35%. |
| **stale root** | Note 9 @ root 0 at epoch 17 (slot 0 overwritten): tx0 valid and mined; tx1 rejected by W in libauth (OP_VERIFY), by testmempoolaccept (`16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)`), by sendrawtransaction and as a block (`blk-bad-inputs`). |
| **testmempoolaccept totals** | **299 valid transactions allowed** (genesis, 272 deposits, 17 flushes, 9 withdrawal transactions); the single refusal is the expected stale tx1. |

W's end value checks conservation: 268,100,000 sat = 100,000 + 272δ − 4δ, and D is back at 100,000. The funding transactions (deposit inputs, worker UTXOs, R carriers, the thread NFT) still come from bare-OP_1 coinbases through submitblock (A4). BCHN timing was not measured.

### 9b.4 Tests

All tests are plain acceptance and rejection tests, with no attack construction. A rejection counts only if the input also rejects on the loose VM (no 'limit' verdicts).

| suite | cases | result |
|---|--:|---|
| `d/test-d.mjs` (libauth, 14 s) | **72** | **0 unexpected**: 59 rejections + 13 required accepts (its family table sums to 76 because `seq` also counts 4 root/ring equality checks) |
| – root = offline tree | 4 flushes / 64 deposits; 17 / 272 | all equal |
| – ring wraparound | 5 | root 0 accepted at epoch 16, **rejected by W at epoch 17**; root 16 and root 1 still accepted |
| – premature flush / wrong frontier / leaf lane ≥ p | 2 / 7 / 4 | all rejected by D (lane ≥ p in a queue a deposit could never build: rejected by worker 1) |
| – other families (deposit, ring, mid, io, wout, dout, wbranch, edge) | 46 rejections | all rejected; consistent wrong claims across D and the workers (wrong ROOT, X, H11, A8) are rejected by the worker that computes them |
| S1 `test-w` re-run with the S4 W | 10,000 + 10,000 + 203 | PASS, 0 disagreements |
| S2 grading re-run (pool-specific R) | 24 statements | 24/24, 132,904 B, max 91.1% |
| S2 production sweep re-run | **5,055** | 0 unexpected = 4,912 chain rejections + 88 required accepts + 55 encoder-only relabels; includes the new `wpin` family (78: a non-W input, another pool's W naming this R, CAT with prefix 0x44; all rejected by HEAD) |
| S2 harness sweep re-run | 2,387 | 0 unexpected = 2,232 chain rejections + 51 accepts + 69 encoder-only + 35 not run on chain |
| S3 BCHN re-run (`t9s3b`, one R per pool) | 81 transactions | same verdicts as Track 9: 24/24, 76/76 allowed, the same 5 expected refusals |
| S4 BCHN (`t9s4a`) | 300 transactions | 299 allowed, 1 expected refusal (§9b.3) |

### 9b.5 A1 and A3

- **A3 (R does not pin W): closed.** The final HEAD checks input 5's category CAT ‖ 0x01 and prefix 0x57; under L1 that is the pool's W. Each pool now needs its own R (and R carriers). The S2 `documented` case became the `wpin` rejection family.
- **A1 (nullifiers are per pool): resolved by G, no script change.** The pin does not stop one proof from working in another pool whose ring holds the same root. It does not need to: a pool's ring starts empty (16 × Z, and W rejects ROOT = Z), and only its own flushes, built from its own paid deposits, write roots. So withdrawals from a pool ≤ distinct NFs over its leaves ≤ its deposits. A note can be withdrawn from two pools only if its leaf was deposited and paid in both. The "never seed a funded pool's ring" rule is now part of the genesis check G. A pool-specific NF would need an AIR change.
- **New consequence of S4:** with a minting NFT of CAT someone could forge a W and take a flush's 16δ, or forge a D. The off-chain genesis check (A2/G) now protects funds, not only state uniqueness.

### 9b.6 Soundness summary

[SOUNDNESS-T9.md](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/SOUNDNESS-T9.md) argues, **per pool**, under H1 (SHA-256 collision resistance, no preimage of Z), H2 (Poseidon2 T∘P collision resistance), KS (Track 8's 128.06-bit result for M1, Z128, cap 5, from [SOUNDNESS-T8](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-stark-batch/SOUNDNESS-T8.md)), SE (simulation extractability) and the deployment checks G and T:

| | property |
|---|---|
| L1 | Exactly one D and one W of CAT exist at any time; each spend replaces it by its own successor (G, CashTokens rules, successor pins). |
| L2 | An accepted withdrawal inserts a key absent from the nullifier set; 64-bit key truncation only causes a false "spent" (about 2^-25 at 2^20 spends), never a payout. |
| L3 | Every non-empty ring entry is the Poseidon2 root of a 16e-leaf prefix of the pool's own deposits, written by its own flush (induction over deposits, flushes, withdrawals, including the frontier append). |
| L4 | An accepted tx0 + tx1 is one fully verified Track 8 proof; each Track 9 change to R (ROOT push and lane check, CTX over outputs[1..], graph slot, W pin) keeps T8's argument. |
| L5 | One leaf yields one NF. |
| L6 | Withdrawals ≤ 16 · flushes ≤ deposits; W's value = genesis value + δ(16E − w), so W always covers what can still be withdrawn. |
| L7 | Outputs ≥ 1 are bound by CTX and output 0 is fixed by W; a relayer can censor but not redirect (redirection with a fresh proof excluded under SE). |

An owner table maps every accept-relevant value of the genesis, deposit, flush and withdrawal to the script that checks it.

**Assumptions A1–A6:** A1 resolved by G; A2 carried as G, now a full list (exactly two mutable NFTs of CAT, no minting NFT, no fungible amount, the reference D and W lockings, the empty initial commitments with the ring all Z); A3 closed; A4 carried as a test-scope note; A5 carried as the reading rule for sweep totals. **New A6 (assumption T, fund relevant):** every minting NFT of the thread category TCAT must be locked by a reference R. tx1 alone skips the AIR identity check and queries 0..20; only the thread NFT ties it to a checked tx0. The S3/S4 regtest rig keeps a TCAT minting NFT at OP_1 in the faucet, a fixture that breaks T on purpose; a deployment must not.

**Open items:** SE is assumed; the powers-batching proof (BCIKS20 Thm 7.2 plus the FRI step in ../pq-stark/BATCHING-PROOF.md) is reviewed internally, not externally; G and T have no standalone checker (natural S5 task); the frontier append is argued and tested but not machine-checked; L6's multi-proof extraction bound is not written out.

### 9b.7 Review and fixes

One internal review (S7b) covered the D/flush protocol against the code, value conservation, the permissionless flush, A1/A3, SOUNDNESS-T9's L1 case analysis and L3 induction, BCHN accounting and harness accounting. **Verdict: fix, with 0 blocker, 0 major and 8 minor findings.** It confirmed conservation in every branch, the end-to-end queue binding, the frontier update in every case, full pinning of the worker IO and hand-overs, and that a keeper cannot take more than 16f.

All 8 were fixed in 029d8f2; all are documentation or accounting, and no script or test changed, so no re-run was needed.

| # | finding | resolution |
|---|---|---|
| 1 | d/README overstated "54 more" rejections | 46 more, 59 in all; 72 = 59 rejections + 13 accepts; family table 76 explained |
| 2 | Harness sweep reported without a split | 2,387 = 2,232 + 51 + 69 + 35 not run on chain, everywhere |
| 3 | Full-tree end state misdescribed | After count = 2^30, D still accepts one queue of up to 16 deposits that can never be flushed or refunded (up to 16(δ + f) locked). Unreachable in practice; a sentinel-queue final flush is noted, not implemented |
| 4 | Worker UTXOs are anyone-can-spend | Keeper-side griefing documented (pool funds unaffected, D binds every worker's IO); keepers fund workers at about dust (~600 sat, computed) and broadcast setup and flush together |
| 5 | No keeper fee lower bound | f_min ≈ 2.7k sat at 1 sat/B stated; below it, only self-flushing keeps the pool moving, no theft |
| 6 | Assumption T worded for a single R | Reworded for pool-specific R sharing TCAT (each R mints thread NFTs only to its own locking) |
| 7 | A1 status words differed | "Resolved by G (initial ring all Z); no script change" everywhere |
| 8 | PUSHDATA2 precondition unstated | Worker IO sizes are data-independent and ≥ 256 B (sampled 472–~560 B), so the header is always minimal |

### 9b.8 Caveats

- **Simulation extractability is assumed, not proved** (from Track 8). It is what stops a relayer or mempool observer from re-binding someone's proof to new outputs[1..].
- **Powers batching is reviewed internally, not externally.** Every λ figure, and so L4, rests on it: the powers-batching step is a direct application of [BCIKS20] Thm 7.2, with the remaining FRI step proved in [BATCHING-PROOF.md](../pq-stark/BATCHING-PROOF.md), reviewed internally but not externally.
- **About 85-bit quantum collision level.** 128 bits is the classical figure; generic quantum collision search on SHA-256 and the 4-lane Poseidon2 digests reaches about 85 bits.
- **Fixed denomination.** Every note is δ (0.01 BCH on regtest); W releases exactly δ per withdrawal. No variable amounts, no change.
- **Anonymity set grows per flush.** It is per pool, grows in chunks of 16 leaves, and a note only hides among notes whose roots are still in the 16-slot ring. A withdrawal against an expired root must be re-proved against a newer one (BCHN: note 9).
- **Off-chain checks protect funds.** G (pool genesis) and T (thread-category batons) are not enforced by any script and have no standalone checker yet. The regtest rig fails T on purpose.
- **Liveness, not safety:** deposits stall at len = 16 until someone flushes; there is no partial flush or refund; with f below f_min third-party keepers have no incentive; worker UTXOs can be swept before a flush confirms; after 2^30 leaves up to 16 deposits lock for good.
- **Flush size.** 42 KB in one transaction under today's rules, plus a worker-setup transaction. With 100 KB per-input limits it would be one worker.
- **Tight budgets.** QRY at 91.1%, flush worker 2 at 91.1%, worker 3 at 91.9% in the synthetic all-bits-set state.
- **Not built:** the relayer (S5) and M1-N (S6). **Not measured:** BCHN timing; the worker dust and setup sizes in the fee bound are computed estimates.
- **Withdrawals in `d/test-d.mjs` use S1's stand-in R**; the real R with real proofs is the BCHN run.

### 9b.9 Sources

groth16_cashscript `main`, [`research/pq-pool/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool):
- [`README.md`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/README.md): stage index, S4 headline, A1–A5 with S4 updates.
- [`SOUNDNESS-T9.md`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/SOUNDNESS-T9.md): L1–L7, owner table, A1–A6, liveness, open items.
- [`summary-s4.mjs`, `summary-s4.json`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/summary-s4.json): S4 results, the S1–S3 re-runs, soundness and review summary (`summary-t9.json` stays the S0–S3 snapshot).
- [`d/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool/d) (S4): `README.md`, `dcov.mjs` (`buildD`, `flushBlob`, `workerBlob`, `workerLocking`), `dpool.mjs` (`DState`, `WState`, `flushPlan`, transaction builders), `test-d.mjs`, `results/s4-d.json`.
- [`w/wcov.mjs`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/w/wcov.mjs): W with the flush branch; re-run in `w/results/s4rerun/`.
- [`r/gena.mjs`](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/pq-pool/r/gena.mjs): R's W-slot pin; re-runs in `r/results/s4rerun/` (`grade-a.json`, `test-a-2tx-pool.json`, `test-a-harness.json`).
- [`node/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-pool/node): `s4.ts`, `run-s4.sh`, `summarize-s4.mjs`, `results/t9s4a{.jsonl,.log,-summary.json}`; `s3.ts` with one R per pool, `results/t9s3b*`.
- `rerun-s4.sh`: the S1–S3 re-runs.

Track 8's verifier ([`research/pq-stark-batch/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/pq-stark-batch)) is unchanged.

**Reproduce** (groth16_cashscript `research/pq-pool`; same environment rules as Track 9 §9.10):

```sh
node d/test-d.mjs                                   # libauth acceptance (14 s); --flushes 17
./rerun-s4.sh                                       # S1 test-w, S2 grade and sweeps
CARGO_TARGET_DIR=$C/target nice cargo build --release --offline -j4 --manifest-path prover/Cargo.toml
cd node && S2_VEC=$C/s2/vec PROVER=$C/target/release/pq-pool-prover S4_CACHE=$C/s4 \
  OPCOST_DIR=<datadirs> ./run-s4.sh <fresh NAME> 9 7 --wrap      # BCHN, about 6 minutes
cd .. && node summary-s4.mjs                        # summary-s4.json
```

---


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
- **Powers batching is reviewed internally, not externally.** Every λ figure rests on it, carried over unchanged from Track 8: the powers-batching step is a direct application of [BCIKS20] Thm 7.2, with the remaining FRI step proved in [BATCHING-PROOF.md](../pq-stark/BATCHING-PROOF.md), reviewed internally but not externally.
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