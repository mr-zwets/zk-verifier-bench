# Track 9 design: a privacy-pool reference covenant on the Track 8 STARK verifier

This is a design only. Nothing was built, proved or edited. The numbers marked *est.* come from a calculator I wrote for this note, `/tmp/claude-1000/-home-mrzwets-BCH-projects-verifier-cash/cee4e8ef-c674-4939-b1b7-b1ff05774a8a/scratchpad/t9calc.py`. Every other number is a Track 8 measurement. The ShieldKit README was reachable, but its landing page has no protocol detail (Chipnet research beta, Groth16, one pool per genesis), so it is not used below.

## 0. Summary of choices

| question | choice |
|---|---|
| nullifier set | **SHA-256 sparse Merkle tree (SMT)**, depth 64, keyed by a truncated hash of NF. Its root sits in a covenant NFT commitment. Each withdrawal checks that NF is absent and inserts it with one compressed path. |
| deposit tree | Poseidon2-Gl-8 depth-30 incremental tree (M1 is unchanged). Deposits go into a **SHA-256 queue**. A permissionless **flush** appends 2^k leaves at once with Poseidon2 in Script. |
| root history | 16-slot ring of epoch roots, committed as a 4-level SHA-256 Merkle root (`histRoot`). |
| state | **Two state UTXOs** of one pool category: D-state (deposits and the queue) and W-state (nullifiers and history; it holds the withdrawable funds). |
| withdrawal binding | CTX = SHA-256 over **outputs[1..]**: the W-state output at index 0 is excluded. The proof then does not depend on the pool state, so a relayer rebuilds the transaction after a race without re-proving. |
| today's rules | Withdrawal uses the 2-tx a′ plan plus the W-state (about 133–134 KB). The 1-tx plan does not fit (§5). |
| aggregation | Batching one user's N notes (M1-N, a taller table) is cheap to add. Batching across users needs recursion and is out of scope. |

## 1. Nullifier set

There is no global state, so uniqueness has to come from one serialized state UTXO whose script checks that NF is absent.

| option | real double-spend prevention? | per-spend cost |
|---|---|---|
| NF as its own UTXO/NFT | **No.** Script cannot prove that an outpoint or commitment does not exist, and anyone can mint a second NFT with the same commitment. At best a log. | – |
| Sorted list in a 128 B commitment | No: the list does not fit (at most 4 NFs). | – |
| Indexed (sorted linked-list) Merkle tree | Yes | 2 paths of depth ~32: **about 2 KB**, about 0.2M op-cost |
| **SHA-256 SMT, compressed path** | **Yes** | 8 B bitmap + 32 B × (log₂n + 1.3) siblings: about **370 B at n = 2^10, 690 B at 2^20, 820 B at 2^24**. Op-cost about **0.2M** for 64 levels × 2 hashes (*est.*; about 2.5% of one 10 KB input's 8.03M budget). |
| Epoch-reset sets | Only with per-epoch deposit trees and note migration. That adds complexity for no gain here. | – |
| RSA or class-group accumulators | Yes, but not post-quantum. Rejected. | – |

**SMT details**
- The key is the first 64 bits of SHA-256("t9NF" ‖ NF as 32 B little-endian).
- Truncation can only cause **false "already spent"** results, never a false "unspent": the same NF always maps to the same key.
  - A deliberate collision needs a victim's NF, which stays hidden (in leaf = T(P(NF‖r))) until the victim spends.
  - After the victim spends, a collision only blocks the attacker.
  - The chance of an accidental collision is about n²/2^65, roughly 2^-25 at 2^20 spends.
- Empty-node convention: H(0,0) = 0, otherwise SHA-256(l‖r). A present leaf has value 1. Depth is fixed, so leaves and internal nodes cannot be confused.
- One loop (2026 loops) walks the 64 key bits. At each level it computes the old root (leaf 0) and the new root (leaf 1) from the same siblings.

**Contention**
- Every withdrawal spends W-state. Because the proof is state-independent (CTX excludes output 0), the loser of a race rebuilds only the final transaction. The user does not re-prove.
- BCHN 29.1.0 has no ancestor or descendant chain limits (node-check), so withdrawals can chain unconfirmed.
- The binding limit on throughput is block space: about 133 KB per withdrawal, so about 240 per 32 MB block. The single UTXO is not the bottleneck.
- Scale-out later: shard W-state by the top bits of the NF key into S UTXOs. Each flush then updates every shard's `histRoot`.

**Double-spend argument**
- Two withdrawals with the same NF: the second fails non-membership against any later state. Two conflicting transactions on the same state cannot both confirm.
- Two different NFs for one leaf: impossible without a T∘P collision, because the leaf commits to NF directly.

## 2. Deposits and root updates

**Hash choice.** The deposit tree stays Poseidon2-Gl-8, because M1's AIR proves Poseidon2 paths. Switching to a SHA-256 tree would put SHA-256 inside the AIR, which would grow the proof well past the a′ budget. Rejected.

**Poseidon2-Gl-8 in CashVM (*est.*, to be measured in stage S0)**
- Per permutation: 86 S-boxes x^7, 22 internal layers (8 diagonal multiplies), 9 external layers, 86 round-constant adds.
- Cost model: VM-limits costs (100 per instruction, pushed bytes, a_len·b_len for MUL/MOD) plus about 30% stack traffic.
- Result: **about 0.6–0.8M op-cost per permutation; planning range 0.5–1.0M.**
- Code: about 1.4 KB, including 688 B of round constants and 960 B of zero-hash constants for the flush.

**Root-update cost per flush size**

| flush size 2^k | permutations ((2^k − 1) + (30 − k)) | op-cost | padded 10 KB inputs today | permutations per deposit |
|--:|--:|--:|--:|--:|
| 1 (per deposit) | 30 | 15–30M | 2–4 (20–40 KB per deposit) | 30 |
| 16 (**recommended**) | 41 | 20–41M | 3–5 (30–50 KB) | 2.6 |
| 32 | 56 | 28–56M | 4–7 | 1.8 |

With 100 KB inputs (budget 80M), a k = 5 flush fits in one input.

**Mechanics**
- **Deposit transaction** (anyone; about 1.0–1.5 KB *est.*). It spends D-state and adds exactly D to its value.
  - It pushes leaf C (4 lanes, each checked < p) and updates `queue = SHA256(len ‖ chain)`, where chain′ = SHA256(chain ‖ C) and len < 2^k.
  - The script cannot check that the leaf is well formed, and does not need to. A bad leaf is unspendable and only the depositor loses.
  - Depositors also pay a flush fee f into D-state.
- **Flush transaction** (permissionless keeper; 3–5 worker inputs today, using the a′ pattern of a code blob authenticated by hash and intermediate nodes passed as pushes checked by their owner):
  - takes the 2^k queued leaves, re-derives the queue hash and checks len = 2^k;
  - builds the subtree;
  - verifies the frontier against `depHash = SHA256(count ‖ frontier[30])` and computes the new root on the path, using zero-hashes on the right;
  - writes the new root into ring slot (epoch mod 16) of W-state's `histRoot`, with the old slot and 4 siblings;
  - moves 2^k·D from D-state to W-state and pays 2^k·f to an output the keeper chooses.
- **Window.** 16 epochs × 16 deposits: a proof stays valid for at least 256 deposits after its root. Notes become withdrawable only after a flush.

**Commitments (well under 128 B)**
- D-state: `0x44 ‖ queue(32) ‖ depHash(32)` = 65 B.
- W-state: `0x57 ‖ nfRoot(32) ‖ histRoot(32) ‖ epoch(4)` = 69 B.
- Both NFTs are mutable. The minting baton is burned at genesis, and each covenant pins that its output carries the category with its own locking.

## 3. Withdrawals

**Changes to Track 8 (script side only; the AIR, prover and wire format are unchanged)**
1. ROOT moves from a script constant to a HEAD push, with its lanes checked < p.
2. CTX is computed over outputs[1..], with an output count of n − 1. This needs new proofs, because CTX changes; the prover takes about 1 s per statement.
3. R's input graph allows exactly one non-R input at a fixed index, the W-state.

**W-state withdraw branch.** W-state is P2SH32: its redeem script does not fit the 201 B standard output-locking limit. The branch:
- requires the final-transaction graph: input 0's prevout locking equals R (W holds R's hash), plus the input count;
- reads NF and ROOT from HEAD's unlocking with exact push headers;
- checks ROOT ∈ ring through `histRoot`: slot plus 4 siblings, 128 B;
- runs the SMT absence check and insert;
- requires output 0 = W-state with nfRoot replaced and the other fields copied, and value = in − D.

R never references W, so there is no hash cycle. The funds sit only in W, which demands R.

**Fee and relayer model (fixed denomination D)**
- The user puts their payout and an optional relayer output in CTX, summing to D − φ. φ covers the miner fee: about 133 KB at 1–2 sat/B, i.e. 0.0013–0.0027 BCH.
- The relayer funds the dust R-carrier UTXOs (pre-created P2S outputs).
- A relayer can censor but cannot redirect funds: the outputs are bound by CTX, and front-running with new outputs fails under the simulation-extractability assumption already stated in Track 8.
- A user can always relay their own withdrawal.

## 4. Aggregation

- **Across users: not possible without recursion.** An M1-style batch proof needs every user's nk and r, so one prover would have to see everyone's secrets. Each user's floor is therefore one proof, about 74–79 KB. Amortizing across users needs a recursive STARK; that is outside Track 9.
- **One user, N notes (M1-N).** This is how to withdraw N·D. The statement is a single table of 2^(10+log₂N) rows with one shared ROOT, public values NF₁..N and CTX, and N one-hot periodic selectors of period 32N gating the nullifier constraint.
  - Proof growth (*est.*): about +3 KB per doubling of N (deeper paths), plus one more arity-8 FRI round (about 12–16 KB) per 3 bits.
  - The batch-stark "N instances" variant costs about 8 KB per instance in openings, so it is worse for large N.
  - The script performs N SMT inserts.

| N | proof (est.) | withdrawal bytes (2-tx, est.) | per note |
|--:|--:|--:|--:|
| 1 | 74–79 KB | ~134 KB | 134 KB |
| 4 | ~85–95 KB | ~150 KB | ~38 KB |
| 8 | ~100–110 KB | ~170 KB | ~21 KB |

- Prover memory is about 1.06 GB × N (*est.*), so N ≤ 4 is practical on this machine.
- M1-N needs a new AIR, new vectors and a soundness re-check (the λ tables move with the height). That makes it multi-day.

## 5. Today's rules vs raised limits

| transaction | today | with raised per-input limits (100 KB) |
|---|---|---|
| deposit | fits (~1–1.5 KB) | same |
| flush, k = 4 | fits: 3–5 padded inputs, 30–50 KB | 1 input |
| withdrawal, 2-tx a′ + W | **fits**: 131,556 B + about 1.5–1.9 KB (W input with redeem about 0.8 KB, SMT path about 0.7 KB, history path 0.13 KB, W output about 0.15 KB) in tx1, which has room (40.5 KB) | – |
| withdrawal, 1-tx a′ + W | **does not fit**: it needs about 1.5–1.9 KB against a 1,310 B margin | – |
| withdrawal, layout b + W | – | about 93–97 KB, fits one 100 KB transaction |
| withdrawal, layout b2 + W | – | likely over 100 KB (96.2–98.3 KB + W) |

A 1-tx stretch is possible only if the W logic lives in R's code blobs and W is R-locked. That pushes the deposit and flush paths into heavy code. It is not recommended.

## 6. Build plan

**S0 – Poseidon2-Gl-8 in CashVM (libauth)**
- Acceptance: matches p3-goldilocks on the test vector plus 1,000 random inputs (via the air8_ref constants); measured op-cost per permutation, and a flush op-cost table that replaces the estimates above.
- Gate: if a permutation costs more than 1.2M, use k = 5 and today's flush becomes 5–8 inputs; reconsider.

**S1 – SMT library and the W-state covenant (static history)**
- Scope: no deposits yet. The genesis tree is built offline from 2^k leaves, `histRoot` is seeded, and W is funded at genesis.
- Acceptance: a JS reference SMT agrees with the script on 10k random insert and non-membership cases; NF + 1 is rejected; a present key is rejected; wrong bitmap or sibling, wrong commitment carry-over and wrong value out are each rejected.

**S2 – R changes and re-proved vectors**
- Changes: ROOT as a witness, CTX over outputs[1..], graph slot for W. Re-prove the 24 M1 statements; the circuit is unchanged.
- Acceptance: all Track 8 S7 families re-run with 0 unexpected verdicts. New families:
  - ROOT not in the ring;
  - **same NF twice**, in sequence and in conflicting transactions;
  - W at the wrong index or missing;
  - an output-0 commitment that does not match;
  - changing output 0 still accepted by CTX, while changing any output ≥ 1 is rejected;
  - a withdrawal without R at input 0 (just W).

**S3 – BCHN regtest (2-tx withdrawal)**
- Acceptance:
  - 24/24 accepted;
  - a double spend of an NF is rejected by both libauth and BCHN;
  - a 10-withdrawal unconfirmed chain on W is mined in one block;
  - a race in which the loser's tx1 is rebuilt (not re-proved) and accepted;
  - `testmempoolaccept` allows each transaction at the default policy.

**S4 – D-state, queue, flush, ring**
- Acceptance:
  - the flush root equals the offline Poseidon2 tree root over 64 sequential deposits (4 flushes);
  - ring wraparound expires a stale root (rejected at epoch + 16);
  - premature flush, wrong frontier and leaf lane ≥ p are each rejected;
  - an end-to-end deposit → flush → prove → withdraw runs on BCHN.

**S5 – Relayer reference.** A CLI that builds tx0/tx1, pays φ, and rebuilds after a race.

**S6 (optional) – M1-N for N = 2 and 4**, with λ re-checked in params8.

**S7 – SOUNDNESS-T9 and reviews.**

**Soundness outline (constructive)**
- **L1 State uniqueness:** exactly one D and one W UTXO of the category exist at all times (baton burned; covenants pin their successor outputs).
- **L2 SMT correctness:** under SHA-256 collision resistance, an accepted insert means the NF key was absent from the set committed by nfRoot, and the new root commits to the set plus that key.
- **L3 Ring:** every ring entry is a root computed by a flush from queued leaves, given SHA-256 and Poseidon2 collision resistance and L1.
- **L4 Verifier:** Track 8 (128-bit IOP, digest at the birthday bound). Acceptance means the prover knows nk, r and a path with NF and a ROOT taken from the ring.
- **L5 One NF per leaf:** a second NF for the same leaf is a T∘P collision.
- **L6 Conservation:** withdrawals ≤ distinct NFs over flushed leaves ≤ deposits. W pays exactly D per withdrawal, and W's balance always covers what is still withdrawable.
- **L7 Binding:** CTX binds outputs[1..] (Track 8 Lemma 13). Front-running rests on the simulation-extractability assumption. Output 0 is fully determined by W's rules.
- **Liveness:** flush and relaying are permissionless. Censorship is limited by self-relay.

**Risks**
- Poseidon2 op-cost is unmeasured, and flush cost scales with it.
- Bytes in the 1-tx plan.
- The anonymity set is per pool and grows in flush-sized chunks.
- Withdrawal fees of about 0.0013–0.0027 BCH.
- Simulation extractability is assumed, and Track 5's powers-batching adaptation is unreviewed (both carried over from Track 8).
- Accidental 64-bit key collisions (self-inflicted denial of service; negligible).
- The P2SH32 redeem size of W.
- Reorgs: safe, but relayers must rebuild transactions.

**Scope cut**
- **About 1 day:** S0 + S1 + S2 + S3, i.e. a nullifier-enforcing pool over a static genesis tree, the 2-tx withdrawal on BCHN, and the Poseidon2 measurement.
- **Multi-day:** add S4 (deposits and flush), S5 (relayer), S7 (soundness and reviews), and optionally S6 (M1-N).

## Decisions needed

1. **Nullifier structure:** a SHA-256 SMT with a 64-bit truncated key (false positives only), or depth 256 with the full key (32 B bitmap, about 0.4M op-cost)?
2. **CTX over outputs[1..]:** accept the redefinition? It needs re-proved vectors and changes R.
3. **Today's withdrawal plan:** the 2-tx plan (about 134 KB) as the baseline, and drop the 1-tx stretch for the pool?
4. **Deposit flow:** queue plus a batched flush (k = 4, withdrawable after the flush, 256-deposit root window), or per-deposit Poseidon2 updates (20–40 KB per deposit)?
5. **Two state UTXOs (D/W)** or one, and when (if ever) to shard W?
6. **Track scope:** the 1-day cut (static tree, nullifiers, BCHN), or the multi-day track with deposits, relayer and M1-N?
7. **Denomination D and flush fee f** for the reference deployment.

## Maintainer decisions (2026-11-01)

1. Nullifier set: SHA-256 SMT, depth 64, 64-bit truncated key (only false "already spent", accidental ≈ 2^-25 at 2^20 spends).
2. CTX over outputs[1..] (W-state output 0 excluded): accepted; re-prove the M1 vectors.
3. Today's withdrawal: 2-tx a′ plan + W as the baseline; no 1-tx stretch for the pool.
4. Deposits (when built): queue + permissionless flush, k = 4, 16-slot ring.
5. Two state UTXOs (D, W); no sharding in Track 9.
6. Scope: the 1-day cut, S0 (Poseidon2-Gl-8 in CashVM, measured) + S1 (SMT + W covenant, static genesis tree) + S2 (R changes, re-proved vectors) + S3 (BCHN regtest). S4–S7 later.
7. Reference denomination D = 0.01 BCH (regtest only).
