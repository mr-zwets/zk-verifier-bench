# pq-stark verifier: CashVM verifier for Plonky3 SHA-256 STARK proofs (Track 5, Verifier phase)

Research only, not a leaderboard entry. Nothing here is registered anywhere.

This folder holds a CashVM (BCH 2026: BigInt, loops, OP_DEFINE/OP_INVOKE, shifts) verifier for the **real-prover proofs**
of the Prover phase: Plonky3 `p3-uni-stark` at commit `0d803737`, configured with SHA-256 everywhere and Goldilocks
(degree-3 trinomial extension `u^3 = u + 1`, or degree 2 `u^2 = 7`), in the byte format p3s-v1
(`../prover/FORMAT.md`). It verifies every vector the prover produced: 2 AIRs (fib, mimc), 11 parameter sets,
and the zero-knowledge (HidingFriPcs) variants.

## Results in short

- **Every valid vector is accepted on the real libauth BCH 2026 VM.** That is 45 proofs:
  - Layout (b), one 100 KB input: TXv5, standard and consensus, whenever the unlocking fits 100,000 B.
  - Layout (a), today's standard rules: every input on BCH 2026 standard and consensus, plus libauth's
    full-transaction `verify`.
- **Every tampered vector is rejected,** and so is every witness manipulation:
  - Layout (b): `test-b` ran 2,302 cases (45 valid, 1,114 tampered proofs, 1,143 witness manipulations). All
    verdicts were as expected. Most manipulations keep the item count and size.
  - Layout (a): `test-a` ran 417 cases on 8 representative vectors (see `results/test-a.log`), 0 unexpected. One honest caveat is below.
- **The best 128-bit set is S128** (mimc, 78,393 B proof):
  - Security: 128.17 bits λ_IOP under the Soundness phase's per-round bound (Johnson regime, m = 10), **with the
    powers-batching adaptation, which is not a published statement** (see the security section). That is
    λ = 128 under the usual digest convention, and 127.21 under the strict reading.
  - Layout (b): 33.87M op-cost (BCHN-adjusted 33.87M), **47.9% of the base-41 budget** of one 88.3 KB input. Track 5 field P128
    (Track 4 format, 92 KB) was 50.05M, 64.9%.
  - Layout (a), today's standard rules: **2 transactions, 17 inputs, 123,452 B.** Track 5 field P128 needed 19
    inputs and 150,891 B.
- **At about 100 bits, S100b** (mimc, 60.8 KB proof, 100.25 bits) costs 25.64M in one input (45.5%). Under today's
  rules it takes **1 transaction, 12 inputs, 83.5 KB.**
- **AIR-specific code is small.** The constraint evaluation generated from `air.mjs` costs **0.13M op-cost (fib)
  and 0.26M (mimc)**. That is 0.2-1.1% of the total, and 330 B / 660 B of code (4% / 7.5% of the redeem).
  Everything else is the generic STARK verifier:
  - per query: folds about 57%, final polynomial about 31%, DEEP about 10% (at S128);
  - Merkle authentication: 25-40% of the total.
- **Honest negatives:**
  - Plonky3 with Track 4's parameters (P128) is only **126 bits** under the Soundness bound. The batch or query
    round binds. Plonky3's own estimator says 128.
  - The proof is 110 KB, so it does not fit one 100 KB input.
  - ZK proofs (86-189 KB) mostly do not fit one input, and need 2-5 transactions under today's rules.
  - The C sets (degree 2, and the conjectured C128) are far below target under the same bound: 60 and 75 bits.

The full tables (every AIR × set × ZK variant, both regimes) are in [results/tables.md](results/tables.md). They are
also summarised below.

## How it works

The on-chain algorithm is written first in JS ([model.mjs](model.mjs)). `test-model.mjs` checks it against the
prover's independent reference verifier (`../prover/verify.mjs`) on all 1,159 cases: every verdict is equal, and on
valid proofs every SHA-256 transcript input is equal, byte for byte, to Plonky3's own recording. The generators
emit exactly that algorithm.

| step | on chain |
|---|---|
| Fiat-Shamir | A chain of SHA-256 digests. The three domain-separator seeds (Keccak-derived in Plonky3) are baked as the byte strings the challenger observes, so no Keccak runs on chain. Samples are 8-byte big-endian slices popped from the end of the digest. PoW checks: low bits of the next u64 are zero. Indices: the low log H bits. |
| AIR at ζ | Generated per AIR from [air.mjs](air.mjs) (expression trees in Plonky3's `eval()` order). It is multiplied through by (ζ−1)(ζ−g⁻¹), so no inversion is needed. Periodic columns are evaluated by Horner on their interpolant at ζ^(n/m). The quotient is rebuilt from its chunks. The script also checks ζ^n ≠ 1 (and ζ^n ≠ −1 under ZK). |
| DEEP | Per query, both opening points at once. The row values are dot-multiplied with packed α′-power columns: one OP_MUL per row value covers both points and all 3 coefficients (17-byte slots). 1/(z − x) = adj(x)/N(x), with adj and N polynomials in x whose coefficients are per-proof constants. One 8-byte hint per query, T = 1/(N_ζ(x)·N_ζg(x)·s₀), is checked by one product. It also yields s₀⁻¹ for the folds. |
| query point | s₀ = g^rev(idx ≫ a₀) comes from 4-bit window tables over idx, built once per proof with a bit-reversed doubling (Track 5 "xtab"). The next fold's s⁻¹ is (s⁻¹)^a times a table entry. The final-polynomial point is x^(2^S). |
| FRI folds | Arity 2^k as k binary levels over adjacent pairs (Plonky3's bit-reversed leaf order). Values are packed in 26-byte slots, with packed rotation columns of β^(2^l) (Track 5 PAIRK). The folded value is serialized into the next round's leaf at its slot, so the witness carries only the a−1 siblings, as the proof does. |
| final polynomial | Group-packed dot product, Track 5 "gpd": H = 8 groups at 256 coefficients, 4 below that. |
| Merkle | Leaf digests (input batches; FRI leaves holding the computed fold) are collected per query on the altstack. Layout (b) then authenticates every tree with Track 4's sorted LIFO records (MERGE/DUPM/PARK/ROOT, σ permutation check, DEPTH pin after each tree). New here: every record push must hold exactly 2 records, so records cannot be repacked. Layout (a) climbs a full path per query and tree. |

Witness, layout (b), bottom of the stack first:
- `L_q`, one per query: the leaf preimages of the input batches, the FRI sibling values (plus salts under ZK), and
  the hint T.
- The Merkle record pushes.
- PT: the header byte followed by the roots, then the OOD values in observation order, the PoW witnesses, the FRI
  roots and the final polynomial.

Witness bytes = proof bytes + 8 B per query (the hint) + the record opcodes − the u16 counts. Under ZK, the OOD values
are reordered: the witness stores them in transcript observation order.

### Layout (a), today's standard rules

This follows Track 4's design. One shared 59-236 B P2SH32 redeem R is in every input. R reads the code blob(s) from
inputs 1..nc, checks their SHA-256, defines them and invokes them. The code defines every function, pins the graph
(input count, and every input under the same locking) and dispatches by transaction kind and input index:

| role | input | what it does |
|---|---|---|
| HEAD | 0 | Holds PT. Runs the transcript, PoW checks and AIR. |
| CODE | 1..nc | One code blob each. |
| QRY | the rest | Each one: re-derives the transcript from HEAD's pushes (headers checked) and the per-proof constants and final polynomial, then verifies its queries with full paths. |

- The phases are separate functions (TRN, AIRF, CNS, QA), so that no function body exceeds the 10,000 B item limit,
  and HEAD and QRY share the transcript code.
- Code blobs are balanced in size: every CODE input runs R, which hashes all blobs, and a tiny blob's input would not
  have the hash-iteration allowance.
- **Transactions:** plans with T > 1 transactions are linked by an NFT thread. tx0 spends a minting baton and mints
  one immutable NFT per later transaction k, with commitment `k ‖ SHA256("pq-stark/thread" ‖ G ‖ k)`, where G is the
  final transcript digest. Transaction k holds that NFT in input 0 and burns it.
- **Pads:** HEAD and QRY pads (zero bytes, checked) grow by least fixpoint until every input's BCHN-adjusted op-cost is
  at most 94% of its budget. Planning is redone if the pads push a transaction over 100,000 B.

## Security of each set (bits)

Computed by zk-verifier-bench `wip/pq-stark-verifier` `research/pq-stark/verifier/security.py`. It is the Soundness
phase's calculator (`params5.py`, P3 model) run on each vector's exact FriParameters and each AIR's shape. The JB
regime is per-round Johnson-bound list decoding, with Fiat-Shamir per Block et al. Cor. 5. λ is capped at 4h (the
usual birthday convention).

**None of these figures is a proven bound as published.** Every vector here is a Plonky3 proof, and Plonky3 batches
the DEEP quotients (and the constraints) with powers of one challenge. The batching term for that, (t−1)(A0 + B1), is
the Soundness phase's adaptation of [ADK] Thm 2 (BCIKS Thm 7.2 in place of Thm 7.4). A proof sketch is in
zk-verifier-bench `wip/pq-stark-soundness` `research/pq-stark/soundness/SOUNDNESS.md` §2.1; it is not published and
not peer reviewed. Only Track 4-format proofs (independent γ_j, the Track 5 field phase's P100/P128) rest on [ADK]
Thm 2 as published. The S sets depend on this term: their batching round is within 0.2-1.2 bits of the binding query
round (S100b 100.66 vs 100.25, S100z 100.39 vs 100.21, S128 129.38 vs 128.17).

| set | D | λ (JB) | binding round | regime / note |
|---|---|---|---|---|
| S128 | 3 | 128 (λ_IOP 128.17) | query | JB, powers-batching adaptation, unpublished; m = 10; 127.21 under the strict digest reading |
| S128b | 3 | 128 (λ_IOP 128.09) | query | JB, powers-batching adaptation, unpublished |
| S128z (ZK) | 3 | 128.00 | query | JB, powers-batching adaptation, unpublished |
| S100 | 3 | 101.11 | query | JB, powers-batching adaptation, unpublished |
| S100b | 3 | 100.25 (mimc), 100.32 (fib) | query | JB, powers-batching adaptation, unpublished |
| S100z (ZK) | 3 | 100.21 | query | JB, powers-batching adaptation, unpublished |
| P100 | 3 | 100 (λ_IOP 100.11) | query / digest | JB, powers-batching adaptation, unpublished; h = 25: 99.21 under the strict digest reading. The ZK variants (h = 32): 103.6 |
| P128 | 3 | **125.94 (mimc), 126.31 (fib)** | query / batch | **below 128** (JB, powers-batching adaptation). Plonky3's own LDR estimator says 128. ZK variants: 123.2-124.2 |
| C128 | 3 | 74.93 | query | conjectured 128 only |
| C100, C100h | 2 | 59.6-59.8 | query | conjectured 100 only (degree 2) |

Every unique-decoding figure is far lower (43-69 bits). Caveats carried over from the Soundness phase:
- Plonky3 batches with powers of one challenge. Using BCIKS Thm 7.2 inside the ADK proof for that is the Soundness
  phase's adaptation, not a published statement (see above).
- Zero knowledge of the ZK variants is by Plonky3's construction (HidingFriPcs, ePrint 2024/1037 §4.2), not proven
  here; the conditions are in the prover README. This verifier only checks the proofs; it does not affect hiding.
- The AIR shape passed to the calculator (width, 5 constraints, degree 3 for mimc and 2 for fib) is this phase's
  mapping of the two AIRs.

## Results

The full tables are in [results/tables.md](results/tables.md), generated by `node tables.mjs`. They cover every
AIR × set × ZK variant, both regimes, and the per-phase profile. Selected rows (mimc unless noted):

Security is λ under the per-round bound with the powers-batching adaptation (not published; see above). BCHN-adjusted
op-cost is on the standard basis (libauth standard op-cost + OP_DEFINE body bytes); the consensus-basis figure is in
the JSON as `opBchnAdjustedCons` / `opBchnConsTotal`.

| set | proof B | security | (b) one 100 KB input: op-cost std / BCHN-adj., % of budget | (a) today: txs / inputs / total B |
|---|--:|---|---|---|
| S128 | 78,393 | 128 | 33.87M / 33.87M, 47.9% | 2 / 17 / 123,452 |
| S128b | 99,795 | 128 | does not fit (110,710 B unlocking) | 2 / 25 / 166,343 |
| S100 | 76,019 | 101.1 | 30.58M / 30.58M, 44.3% | 2 / 19 / 127,870 |
| S100b | 60,793 | 100.3 | 25.64M / 25.65M, 45.5% | 1 / 12 / 83,515 |
| P100 (h = 25) | 58,183 | 100 | 23.83M / 23.83M, 43.5% | 1 / 13 / 85,649 |
| P128 | 110,765 | 125.9 | does not fit (122,057 B) | 2 / 26 / 185,338 |
| C100 (D = 2) | 56,893 | conj. 100 | 19.96M / 19.97M, 38.6% | 1 / 11 / 93,794 |
| fib S128z (ZK) | 112,501 | 128 | does not fit (126,183 B) | 3 / 35 / 234,553 |
| fib S100z (ZK) | 85,853 | 100.2 | 29.42M / 29.42M, 37.0% | 2 / 25 / 136,556 |

Comparison with the Track 4 format (Track 5 field phase, same CashVM techniques, P128 at 91.5 KB, 128.19 bits):

| | Track 5 field P128 (Track 4 format) | this phase, Plonky3 S128 (mimc) |
|---|---|---|
| (b) op-cost / share of budget | 50.05M / 64.9% | 33.87M / 47.9% |
| (a) today | 19 inputs, 2 txs, 150,891 B | 17 inputs, 2 txs, 123,452 B |

The win comes from Plonky3's parameter knobs: blowup 2^8, arity 16, 26 queries, and PoW on commit and batch. It does
not come from the protocol. With Track 4's own parameters (P128) the Plonky3 proof is 21% larger and does not fit
one input.

### Where the op-cost goes (layout b, mimc S128, per query 884k)

| part | op-cost |
|---|--:|
| x tables | 13k |
| DEEP | 89k |
| two arity-16 folds, including leaf assembly and hashing | 505k |
| final polynomial, 256 coefficients | 277k |
| Merkle (all trees) | 8.30M (24.5%) |
| per proof: transcript and PoW | 0.17M |
| per proof: AIR block (0.26M AIR-specific) | 0.55M |
| per proof: DEEP and fold constants, tables | 0.60M |
| per proof: final-polynomial unpack | 1.10M |

The AIR-specific part is the constraint evaluation, the periodic column and the Horner in α. All other code is shared
by every AIR. Per set it costs:

| AIR | AIR-specific op-cost | code |
|---|--:|--:|
| fib | 0.06M (D = 2) / 0.13M (D = 3) | 263-362 B |
| mimc | 0.12M (D = 2) / 0.26M (D = 3) | 524-703 B |

That is 0.2-1.1% of the op-cost and 3-8% of the redeem bytes.

## Deviations, limits and caveats

- **Rejection sampling:** a challenge sample ≥ p is rejected on chain, where Plonky3 would draw again. This is
  safe for soundness. The completeness loss is about 2^-32 per sample, roughly 12 samples per proof.
- **Range checks (accepted deviation):**
  - Field values in leaves, OOD and the final polynomial are not range-checked. The residues are used, and the
    bytes are bound by the Merkle roots and the transcript.
  - So the script accepts a slightly larger byte language than Plonky3's verifier (and `../prover/verify.mjs`),
    which reject a u64 ≥ p. This is accepted as **language-level malleability with no soundness impact**: a
    non-canonical twin v + p hashes to different transcript bytes and a different Merkle leaf, so it is a different
    oracle query, not a second answer to the same one. It does not let anyone change what the proof proves.
  - No value in the 45 proofs has such a twin (v + p must still fit 8 bytes, so v < 2^32 − 1), so `test-b`
    reports these cases as n/a.
  - Adding the check would cost one `DUP <p> LESSTHAN VERIFY` per 8-byte value in PKL and parseOOD (as POPB
    already does); it was not built or measured.
  - The hint T is checked to be < p.
- **Layout (a) and malformed p3s-v1:** layout (a) carries full paths instead of the pruned multiproof. So two
  format-level tamper cases, "one trailing byte" and "extra sibling digest (count + 1)", are refused by the layout (a)
  encoder. The script itself accepts their re-encoded witness, which is the valid proof's witness: the byte string
  wraps a valid proof. `test-a` reports them as "encoder only". Layout (b) carries the multiproof, and its script
  rejects both.
- **Malleability:** in layout (b), the record pushes, pads and every item size are pinned. The witness encoding is
  otherwise the encoder's choice.
- **Scope:**
  - The verifier covers the prover's AIR class: one trace, all matrices the same height, no preprocessed columns,
    and periodic columns as in Plonky3. ZK salts and random codewords are generic.
  - The statement (public values) is baked into the code.
- **Cost accounting:**
  - BCHN-adjusted op-cost = libauth op-cost (standard basis) + the body bytes of every OP_DEFINE the input executes.
    This matches the Track 5 field phase and the layout (a) padding gate. The consensus-basis figure is kept in the
    JSON (`opBchnAdjustedCons`, `opBchnConsTotal`, per input `opBchnCons`). Before this fix the figures used the
    consensus basis, so they were not comparable with the field phase.
  - In layout (a) every input pays for all code. That is an upper bound for CODE inputs.
- **Not done:**
  - No further op-cost work beyond the Track 5 field techniques. Folds (57% of a query) and Merkle (25-40%) are the
    targets.
  - Splitting the oversized proofs (P128, S128b, most ZK) over two 100 KB inputs was not built. Layout (a) covers
    them under today's rules.

## Files

| file | what |
|---|---|
| `air.mjs` | AIR descriptions (fib, mimc) used by the model and the generator |
| `model.mjs` | the on-chain algorithm in JS; witness encoders `encodeB` / `encodeA` (from the proof's own multiproof) |
| `gen.mjs` | shared functions and phase emitters (`makeGen`); `build` is layout (b) |
| `gen-a.mjs`, `layout-a.mjs` | layout (a): roles, code blobs, NFT thread; plans, witnesses, transactions |
| `layout-b.mjs` | layout (b) spends |
| `vm.mjs`, `lib/` | libauth BCH 2026 VMs (real, loose, TXv5, bch-spec); assembler and straight-line compiler (from Track 4/5) |
| `test-model.mjs` | model vs `../prover/verify.mjs` (`results/test-model.log`) |
| `grade-b.mjs`, `test-b.mjs`, `profile-b.mjs` | layout (b): grades, accept/reject sweep, per-phase profile |
| `grade-a.mjs`, `test-a.mjs` | layout (a): grades, accept/reject sweep |
| `tables.mjs` | `results/tables.md` |
| `results/` | `layout-b.json`, `layout-a.json`, `profile-b.json`, `security.json` (copied from zk-verifier-bench), logs |

## Reproduce

Requirements: node with `@bitauth/libauth` 3.1.0-next.8, through the `node_modules` link at the worktree root. All
runs are single-threaded; keep them under `nice`.

```
cd research/pq-stark/verifier
V=../prover/vectors
node test-model.mjs $(ls $V/*-[0-9].json)          > results/test-model.log   # 1159 cases, 0 mismatches
node grade-b.mjs $(ls $V/*-[0-9].json)             > results/grade-b.log      # layout (b), ~1 min
node test-b.mjs --wit $(ls $V/*-[0-9].json)        > results/test-b.log       # 2302 cases, ~15 min
node profile-b.mjs $(ls $V/*-0.json)                                          # results/profile-b.json
node grade-a.mjs $(ls $V/*-[0-9].json)             > results/grade-a.log      # layout (a), ~10 min
for a in "mimc-S128-0 mimc-S128-1" fib-S128-0 "mimc-P128-0 mimc-P128-1" mimc-P100-0 mimc-C100-0 fib-S100z-zkmin-0 fib-S128z-zkmin-0 mimc-S100b-0; do
  set -- $a; node test-a.mjs $V/$1.json ${2:+$V/$2.json}; done                > results/test-a.log
# security (zk-verifier-bench wip/pq-stark-verifier):
#   python3 research/pq-stark/verifier/security.py <this folder>/../prover/vectors > security.json
node tables.mjs > results/tables.md
```
