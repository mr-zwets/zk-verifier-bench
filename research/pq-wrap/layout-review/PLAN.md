<!-- Output of the pq-merkle-bytes review (2026-11-04): 3 designers, a shortlist step, 5 skeptic checks, 1 plan agent. Modelled and estimated figures are not measurements; nothing here was built or proven. Scratch scripts were not kept. -->

# Merkle-path optimization plan for the PQ bridge (T10 G2, T8 M1)

## 1. Are the Merkle paths encoded efficiently today?

The path bytes are tight, but the code that checks them is not. Making the paths smaller would save nothing at today's operating point.

One query input is 8,587 B (MEASURED):
- **Opened rows:** 2,056 B. This includes salts (256 B), random-codeword columns (336 B) and 6 bottom siblings (192 B).
- **Path item:** 4,352 B, which is 136 digests.
- **Padding:** 2,170 B of zero bytes, there only to buy op-cost budget.
- **Push headers:** 9 B.

Counting the 6 bottom siblings, each query carries 142 digests (4,544 B). Across the whole G2 transaction set (MEASURED):

| Part | Size | Share |
|---|---|---|
| Overhead repeated in each of 7 txs | ~265 KB | 41% |
| Path siblings | ~187 KB | 29% |
| Padding | ~98 KB | 15% |
| Opened rows | ~89 KB | — |

- **No structural waste in the encoding.** There are no length fields, and indices are taken from the table input. The only waste is that one query per input stops queries from sharing path nodes: 5,848 digests are sent where a multiproof needs 3,979, which is 47% more (MODELLED).
- **SHA-256 is about 2% of op-cost** (MEASURED), which confirms your finding.
- **The real cost is the path-checking code.** It costs 1.06M op per query (MEASURED). About two-thirds of that comes from re-pushing the shrinking path blob at every level (gena.mjs:524).
- **Smaller paths alone don't help yet.** Every query input is limited by op-cost, so cutting path bytes only adds padding. The repo already showed this: at cap 5 the padding grew from 2,170 to 2,908 B and HEAD went over 10,000 B, so no plan fit (MEASURED).

## 2. Candidates that survived verification, ranked

1. **Push each sibling separately in the path check.** It saves about 642K op per query (MODELLED; the claimed 689K was too high). No soundness change. Low-to-medium effort.
   - **G2:** still 7 txs, about 602 KB. Fitting 6 txs fails by about 190 B per tx (ESTIMATE).
   - **M1:** no change.
   - It makes 2 queries per input fit the op budget (7.34M of 7.47M), but only once paths shrink by other means.
2. **Carry verified state across txs in the NFT, and give later txs a query-only library.** The bound holds under SHA-256 collision resistance. Medium effort.
   - **G2:** 6 txs, about 489–493 KB (MODELLED; the library size is an ESTIMATE).
   - **M1:** not applicable.
3. **Publish the alpha' ladder once in FIN instead of recomputing 2.08M op in every query input.** The bound holds because FIN owns and checks the value. Medium effort.
   - **G2 alone:** 5 txs, about 478 KB.
   - **G2 with candidates 1 and 2:** about 372 KB, 4 txs (MODELLED).
   - It only works while the unmeasured pack cost stays at or below about 0.7M. Above that the plan becomes 6 txs.
4. **Non-ZK outer wrap at log-blowup 7, cap 4.** Q drops to 31 and each input carries 2 queries; the bound is 128.24 bits against 128.15 today (MODELLED). This drops hiding, not soundness, so it is your policy call. Medium effort, and it needs a prover run.
   - **G2:** about 3 txs, 31 inputs, about 248 KB (ESTIMATE).
5. **A Merkle cap layer published once per tx.** It is worth nothing today because inputs are op-bound.
   - **After candidates 1–3:** about −21.5 KB at c=3, giving 4 txs and about 351 KB (MODELLED).
   - The best value, c=4, leaves only 398 B of margin.
   - The page must check which input holds the layer.

**Under raised limits** (100 KB standard-tx cap lifted, 10 KB per input kept; all ESTIMATE):
- **G2:** 1 tx. Roughly 409 KB today, about 372 KB with candidate 1, about 280 KB with candidates 1 and 3, about 171 KB with candidate 4.
- **M1:** 1 tx, 98,690 B, unchanged under every candidate.

## 3. What combining them could reach (ESTIMATE)

- Candidates 1+2+3+5 give 4 txs and about 350 KB.
- Adding the non-ZK wrap gives roughly 2–3 txs and about 180–210 KB. This combination is not modelled.

This does not change the "not viable today" verdict. There is an ordering hole in the current design: nothing makes the final tx depend on the middle txs having run. So only the queries in tx0 and the final tx (7 of 43) are enforced before the outputs exist. Any multi-tx plan must close this first, and the fix collides with candidate 2's "no mint path" rule. With the hole closed and the plan at 2–3 txs, the verdict would move to "plausible, pending measurement."

## 4. First experiments to run

All of these are Node-only scratch work unless noted.

1. **Path-check rewrite.** In a scratch copy of gena.mjs, push each sibling separately and fetch it with DEPTH 1SUB ROLL. Then:
   - run profile-a2 on the cap-0 vector and expect the queries phase to fall from about 1.06M to about 0.42M;
   - run grade-a2 to see whether 8 query inputs fit in one tx;
   - run the test-a2 length and count malformation tests.
2. **Ladder in FIN, plus library size.** Emit the ladder in finRole and parse it in qryRole, then measure the pack cost with profile-a2. The decision thresholds are ≤0.48M for zero padding and ≤0.7M for 5 txs. In the same scratch tree, build the query-only library blob and confirm it is ≤9,972 B.
3. **Non-ZK vector (your step, needs a prover run).** Generate one 2T vector at log-blowup 6, cap 4, Q36: about 7.5 GB expected (ESTIMATE). Log-blowup 7 at about 14.9 GB is the stretch option. Then run grade-a2 and profile-a2 with --per 2. Success means at most 3 txs, at most 260 KB, and every input at or below 95% of its budget.

## 5. What was dropped

- **Sorted query assignment with multiproofs:** gains only 7–15 KB, and a bug in the coverage check could silently drop queries.
- **Leaf packing under ZK:** needs a Plonky3 fork and a re-prove, and the non-ZK option mostly covers it.
- **FRI arity 16:** adds 144 B per query and a larger commit-phase error.
- **Code or the cap layer in the padding:** made pointless by candidate 3; keep it as a fallback.
- **Final polynomial 2^8 to 2^5:** needs a re-prove and overlaps candidates 1 and 3; re-evaluate later.
- **Query PoW 30–32 bits:** a parameter-policy follow-up, not a layout fix.
- **Target of 124–126 bits:** lowers the bound.
- **Re-parameterizing M1:** already 1 tx, and out of scope.
- **Truncated digests or a different hash:** truncation lowers the collision margin, and emulated hashes cost 24–194 times as much.
- **Plain proof-level cap 5:** already measured; it gives no plan.

The scratch work is in (session scratch, not kept)/; the path-check benchmark is climb2.mjs there.