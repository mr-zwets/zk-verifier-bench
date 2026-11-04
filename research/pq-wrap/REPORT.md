# Track 10: a post-quantum ZisK bridge on BCH (gates G0–G2)

Status: research, 2026-11-03. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json. Merged to `main` as a research record (bench design notes and this report; groth16_cashscript `research/pq-wrap/`). No security claim is made.

## Headline

**No-go for the post-quantum ZisK bridge under today's BCH limits. This is a measured result, not an abandoned one.**

- A **same-size stand-in** for the bridge's outer proof (a Track 8-style STARK with the size and shape the bridge would have, **not a real ZisK proof verified end to end**) needs **7 standard transactions, 78 inputs, about 639 KB**. We measured this with libauth and with stock BCHN 29.1.0 on a local regtest node (the node-check harness), not on chipnet. The gate allowed at most 4 transactions and 300 KB, and no blowup that fits in prover RAM gets there.
- These numbers are **measured, not sound**. Nobody has reviewed the soundness of the 7-transaction layout, and multi-transaction chains have seams between transactions (the F3 class of issues) that still need a review.
- **A bridge that is not post-quantum remains viable.** Track 11 (on `main`: groth16_cashscript 075689b, bench ef58440) verifies real SP1 v5 Groth16 proofs, under the production SP1 v5 verifying key, in one 27.5 KB standard transaction. So the proof-check step of an Ethereum-to-BCH bridge via SP1-Helios + Groth16 works today. The bridge itself (an SP1-Helios light-client covenant) has not been built, and SP1 v5's own security is not assessed here. It rests on BN254, which is not post-quantum, and on a trusted setup.
- With raised limits (about 150 KB per input and 300 KB per transaction), the same stand-in fits in **1 transaction of about 260 KB**. That is what a future limit change would unlock. **No May 2027 upgrade candidate raises these limits.**

## Gate summary

| Gate | Question | Result | Where |
|---|---|---|---|
| G0 | Are ZisK's 128 bits real? | **PARTIAL.** It depends on which accounting you use (see Security). | bench 22dd3e8, `research/pq-stark/design-t10/params10.py` |
| G1 | Can we read and verify real ZisK final proofs? | **PASS, with limits.** | bench eb83dd5, `research/pq-stark/design-t10/ZISK-FINAL.md`, `g1/` |
| G2 | Does a verifier of the bridge's size fit BCH's limits? | **FAIL under today's rules.** It passes only under raised limits that no node implements. | groth16_cashscript 8014fd2, ffa3b32, daad7db; bench 81cb45f |

## Security

**ZisK v1.4.0-alpha Poseidon2 final proof (the bridge's target):**

| Accounting | Bits | Binding round | Basis |
|---|---|---|---|
| Track 8 (BCIKS20 Thm 7.2/7.4, per-round, conservative) | **~122.6** (122.57) | query | published theorem, plus Track 8's FRI wrapper (BATCHING-PROOF.md, internally reviewed only) |
| soundcalc (EF, b325e30), re-implemented in params10 | **~129.0** (128.97; compressed STIR 128.63) | query | BCHKS25 Thm 4.2, a **preprint** that has not been peer reviewed |
| soundcalc model with m exactly as printed in Thm 4.2 (see m-factor note) | 128.38 | batching | same preprint |
| Unique-decoding regime only (UDR) | 71.3 (compressed 57.2) | | published bounds |

- **The 128 figure is not the headline.** It appears only under soundcalc's accounting, which rests on BCHKS25 Thm 4.2 (ECCC TR25-169 = ePrint 2025/2055, Ben-Sasson, Carmon, Haböck, Kopparty, Saraf, Nov 2025, "On Proximity Gaps for Reed–Solomon Codes"). Thm 4.2 was read from ECCC TR25-169 on 2026-11-03 ("Correlated agreement for curves, up to Johnson bound"). It is stated for curves u0 + z·u1 + … + z^M·uM with a leading factor M. So the powers-batching step soundcalc uses, error = linear bound × (B−1), is the published theorem applied directly, not an extrapolation. G0 had flagged this step as unverified because it could not fetch the PDF (HTTP 403); that concern is now closed.
- **The BLAKE3 setup is a separate case.** soundcalc's ZisK report covers the BLAKE3 setup, which ZisK uses by default (Final: 2^18 rows, 51 queries, 27-bit grinding): 128.03 under soundcalc's model, 113.5–118.3 under Track 8's. G1 showed that the Poseidon2 final circuit is a different, smaller circuit, so the table above was recomputed from its generated verifier (`g1/zisk_p2_final.toml`).
- **The stand-in's outer proof** scores 128.15 under Track 8's accounting (binding round: query) and 130.22 under Track 8's accounting with the BCHKS25 bound swapped in. End to end, the inner proof sets the bound.
- **Why RISC Zero was dropped.** soundcalc scores RISC Zero's segment circuit at 48 bits provable (G0 recomputation: 48.22 JBR, 33.90 UDR; Track 8 accounting gives 45.63). The binding round is query: BabyBear^4, ρ 1/4, 50 queries, no grinding. RISC Zero's "97 bits" is conjectured, and the conjectures it rests on have since been disproved (Crites & Stewart, ePrint 2025/2046, and others). Raising its parameters cannot reach 100 bits in the Johnson-bound regime without changing the field (security panel). Also, soundcalc's `reports/risc0.md` is stale: its cells match an older m formula without the factor 2 and the BCIKS20 bound. The 48-bit total is unchanged.
- **The ZisK final proof is not zero-knowledge.** Its commitments are a plain LDE with no blinding; blinding exists only in the optional pilfflonk wrap. That is fine for a bridge, where the statement is public, but it rules out privacy uses unless an outer ZK layer is added.

### Note: the m factor in soundcalc's `johnson_bound.py`

Light compute only, with no downloads, against the soundcalc clone at b325e30.

- **As printed (maintainer's reading of TR25-169):** m = max(⌈√ρ / (1−√ρ−γ)⌉, 3) = max(⌈√ρ/η⌉, 3), where η = 1−√ρ−γ.
- **soundcalc** (`soundcalc/proxgaps/johnson_bound.py`, `_get_m_from_eta`): m = max(⌈√ρ/(2η)⌉, 3). Its docstring says the factor 2 "is missing from the statement of BCHKS25 Theorem 4.2, which is a typo confirmed by the paper authors". We could not verify that confirmation: the Nov 2025 text as read does not have the factor 2, and we know of no published erratum.
- **Direction.** A smaller m makes the (m+½)^5 term smaller, so soundcalc's choice is the **less conservative** one.
- **The rest of the bound matches.** soundcalc's error, ((2(m+½)^5 + 3(m+½)γρ)·n/(3ρ^{3/2}) + (m+½)/√ρ)/|F|, has the same shape as the printed theorem, and multiplying by (B−1) matches its leading factor M.
- **Effect on ZisK.** ZisK pins the gap at η = 1/300 with ρ = 1/16. That gives m = 38 under soundcalc's formula and m = 75 as printed.

| Circuit | soundcalc m (factor 2) | m as printed | Change |
|---|---|---|---|
| Poseidon2 Final | 128.97 (query) | **128.38** (batching 133.24 → 128.38) | still ≥ 128 |
| Poseidon2 Final_Compressed | 128.63 (final round) | 128.63 | none |
| BLAKE3 setup, minimum over all 60 circuits | 128.03 (Final, query) | **123.13** (Main, batching); all 60 circuits below 128 | soundcalc's 128 for the default setup depends on the unprinted fix |

- **Our numbers** use soundcalc's m (`params10.py` `sc_m`), as above.
- **Still open:** whether the factor-2 correction is right. Confirming it needs the authors' revised text. Track 8's ~122.6 does not depend on this question.

## G1: ZisK final-proof extraction (PASS, with limits)

**Pins**
- ZisK v1.4.0-alpha: 64a1f1664184e76053686745d50c6b9aaa51b034 (2026-10-29).
- pil2-proofman v1.4.0-alpha: 27b2fc20d52d8b8899291505c27e156c7cd8ef9c.
- The crates.io `proofman-verifier` / `proofman-fields` 1.4.0-alpha are source-identical to the tag.

**Proof format (Poseidon2 `vadcop_final`)**
- Trace: 2^16 rows, ρ 1/16.
- Queries: 54, with 22-bit grinding.
- Evaluations: 130 Gl^3 evaluations over 5 opening points.
- Stage trees: 4, of widths 47/48/12/21.
- FRI: folds 20 > 16 > 12 > 8 > 5, final polynomial of 32 evaluations.
- Size: 369,368 B. The fixture file is 369,976 B, and the re-derived layout matches it byte for byte.
- Compressed (STIR) variant: body 199,824 B.

**Field and hash**
- Field: Goldilocks^3 with u^3 − u − 1, the same extension as Track 8.
- Hash: Poseidon2 with x^7, 8 full and 22 partial rounds. Width 16 for the Merkle trees and transcript, width 8 for grinding.
- **pil2's internal diagonal and M4 matrix differ from Plonky3's** (the round constants match). Track 8's Poseidon2 AIR would therefore need pil2's linear layers.
- The transcript squeezes all 16 lanes, capacity included.

**Verification cost**
- **3,876 Poseidon2-16 permutations** per proof. The panel's 6–7k figure was for BLAKE3.
- q_verify: 3,378 Gl^3 operations.
- Lookups: one connection grand product, no LogUp.

**Publics and binding**
- Publics: flag(1) | program_vk(4) | 64 u32 outputs.
- The covenant pins program_vk as a constant. A SHA-256 of the context committed by the guest can be rebuilt with OP_SHA256.
- The bridge must re-impose the checks the host does: flag = 1, outputs < 2^32, canonical publics.

**Fixtures and tests**
- All 6 published fixtures verify on CPU with the stock no_std verifier.
- 706/706 rejection checks pass.
- A Python replay matches the transcript, query indices, grinding, all 432 Merkle paths and all 8 roots.

**Limits**
- The fixtures cover one guest program (fib_mod).
- **There is no published Poseidon2 proving key** (HTTP 404). Only BLAKE3 and Poseidon1 keys exist, so new Poseidon2 proofs need our own ZisK setup.
- Local proving needs sudo-installed dependencies and was not attempted.

## G2: same-size stand-in (FAIL under today's rules)

**The stand-in**
- Track 8's prover with two tables: Poseidon2-Gl AIR at 2^18 rows (17 columns, degree 4), plus a dummy Gl^3 mul-add table at 2^16 rows.
- Gl^3, SHA-256 trees, ZK on.
- Parameters: blowup 2^5, final polynomial 2^8, Q 43, PoW 24/20/11. Soundness: 128.15 bits under Track 8's accounting.
- It matches the bridge's rows, columns, field and hash, **not** ZisK's verifier logic. Whether 3,876 permutations plus the 130-evaluation DEEP check fit in 2^18 rows is not checked.

**Prover**

| | |
|---|---|
| Proof size | 224,142–225,262 B (cap 0) |
| Proving time | 15.1–22.0 s at 4 threads |
| Peak RAM | **19.5 GB** (VmHWM 19,521,448 kB), under the 24 GB ceiling |
| Blowup 6 (Q 36) | about **39 GB** (measured RAM is 1.82× the model), so it does not fit |

**Layouts**

| | a' (today's rules) | b2 (raised limits) |
|---|---|---|
| Transactions / inputs | 7 / 78 | 1 / 2 |
| Bytes | 637,951–639,351 | 260,355–260,784 (unlocking 134,965 + 125,256) |
| Worst input vs. budget | 92.72% (BCHN-adjusted) | 51.7% (r150 rules) |
| libauth | 286/286 cases as expected | 172/172 under raised limits; rejected today, as expected |
| BCHN 29.1.0, local regtest (run g2n2) | 43/43 block cases as expected; 14/14 valid transactions pass `testmempoolaccept` (POLICY=1); the unconfirmed 7-transaction chain enters the mempool and is mined in one block | rejected today (`blk-bad-inputs`), as expected; no node implements the raised limits |
| Node verification time | about 59 ms per transaction, about 414 ms per proof | n/a |

- Even at blowup 8, a' would need about 430–450 KB (modelled, not built), so a' cannot reach 300 KB at any blowup.

**Bug fixed (daad7db).** In a' chains of more than 2 transactions, tx0's thread-NFT outputs carried 5,000 sat while the middle transactions assumed 200,000 sat. BCHN rejected tx1–tx5 with `bad-txns-in-belowout` (run g2n1, kept in `research/node-check/raw/`). Only values changed, so sizes and op-cost are identical; the rerun g2n2 passes. Two test-offset bugs and one mis-targeted test case were also fixed. The middle transactions' outputs are unbound by design: the statement is bound to the final transaction's outputs.

## Cost comparison

This is a computed, illustrative figure; nothing was paid on any network. It sets an unreviewed same-size stand-in against an unverified gas estimate, so treat the ratios below as rough orders of magnitude, not a result.

- **BCH:** about **$1.80** to verify one proof. That is 639,351 B at 1 sat/B = $1.76 at BCH ~$276.
- **Ethereum** (gas prices and ETH ~$2,279 from the prover.cash market research, `prover.cash/BUSINESS-CASE.md`, measured 2026-11-03; the ~6M gas for Starknet's verification is a reviewer's estimate, unverified and not from that file):
  - At today's unusually low gas (~0.13 gwei), it costs about $1.78.
  - At the 95-day median (~0.77 gwei), it costs about $10.5.
- **So BCH sits between the two:** about the same as Ethereum at today's low gas, and roughly 6× cheaper than at the median (illustrative only).
- **Ethereum amortises its check over a batch of proofs; BCH does not here.** The BCH figure is for one proof.
- Under the raised limits (b2, ~260 KB), the BCH figure would be about $0.72.

## Open items

1. **Seam review** of the multi-transaction a' chain (F3 class: thread NFTs, the binding of middle outputs, ordering). Until it is done, the 7-transaction result is measured, not sound. A known gap from the 2026-11-04 layout review: tx0 mints every thread NFT at once and each later tx burns only its own, so the final transaction (the one that creates the bound outputs) does not depend on the middle transactions having run. Only the queries in tx0 and the final transaction (7 of 43) are enforced before the outputs exist. Any multi-transaction layout must close this first, for example by forwarding one NFT through the chain.
2. **A real ZisK proof verified end to end.** This needs the bridge AIR, then a Poseidon2 ZisK setup of our own (no published proving key; sudo-installed dependencies; fit in 24 GB unverified).
3. **Poseidon2 linear layers.** pil2's internal diagonal and M4 differ from Plonky3's, so Track 8's AIR must be adapted.
4. **The m-factor question** in soundcalc's Thm 4.2 (above). It moves Poseidon2 Final from 128.97 to 128.38, and the BLAKE3 setup from 128.03 to 123.13.
5. Track 8's own accounting: the Thm 7.2 vs. Lemma 8.2 constant (3ρ^{3/2} vs. 2ρ^{3/2}) footnote and the proposed M1 commit-PoW bump, on `wip/batching-proof`.

## Sources

| What | Where |
|---|---|
| G0 calculator and output | bench `wip/t10-gates` 22dd3e8: `research/pq-stark/design-t10/params10.py`, `params10-output.{txt,json}` |
| G1 note, scripts and Poseidon2 config | bench eb83dd5: `research/pq-stark/design-t10/ZISK-FINAL.md`, `g1/` (`zisk_p2_final.toml`, `params10-p2.out`, `replay.py`, `p2.py`, `layout.py`) |
| G2 stand-in, layouts and tests | groth16_cashscript `wip/t10-gates` 8014fd2, ffa3b32, daad7db: `research/pq-wrap/{prover,verifier,onchain}`, results in `onchain/results/g2/` |
| G2 node runs and parameters | bench 81cb45f: `research/node-check/raw/g2n1-*`, `g2n2-*`; `research/pq-stark/design-t10/g2/params-g2.py` |
| Track 11 (SP1 v5 / RISC Zero Groth16, real keys) | groth16_cashscript `main` 075689b (wip 40f3ad9), bench `main` ef58440 (wip 4516363) |
| External pins | ZisK 64a1f166; pil2-proofman 27b2fc20; ethereum/soundcalc b325e30 (TOML files read as data; `johnson_bound.py` read for the m-factor note) |
| Papers | BCHKS25: ECCC TR25-169 / ePrint 2025/2055 (Thm 4.2, preprint); BCIKS20 (Thm 7.2/7.4); Crites & Stewart ePrint 2025/2046 |
| Prices | `prover.cash/BUSINESS-CASE.md` (06df1fa, 2026-11-03) |
