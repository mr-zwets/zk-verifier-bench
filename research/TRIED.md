# Tried and not pursued

Ideas we measured or modelled and then parked. Check this list before retrying one. Each entry links to the details.

| idea | result | reopen if | details |
|---|---|---|---|
| Batch-verifying N Groth16 proofs (same VK) in one tx (Track 13, 2026-11-04) | Best variant saves ~13% per proof (N = 4, ~24.0 KB each vs 27.6 KB), modelled. Not worth the new soundness-critical code. | many same-VK proofs per tx are needed, or the standard tx size is raised | groth16_cashscript `chunked/bn254/batch/DESIGN.md` |
| Further layout work on the PQ zkVM-bridge stand-in (Track 10) | At 4 txs / 356 KB, measured. The proof alone (~225 KB) means at least 3 txs at 100 KB, so only a smaller proof helps. | a smaller outer proof (non-ZK wrap, STIR) | `pq-wrap/REPORT.md`, `pq-wrap/layout-review/PLAN.md` |
| Circle STARKs / Stwo (Mersenne-31) | A QM31 multiply costs 15,076 op vs 7,449 for Goldilocks³, measured | — | `pq-hash/REPORT.md` |
| Binary-field proofs (Binius, FRI-Binius, Ligerito) | A GF(2^128) multiply costs 36–373× a prime-field multiply, measured | — | `pq-hash/REPORT.md` |
| Polymath / Pari / FFLONK / SnarkPack | Estimated no better than Groth16 (FFLONK ~35–45 KB; SnarkPack >150 KB) | — | landscape survey, 2026-11-04 (estimates; notes not published) |
| Bulletproofs range proofs over secp256k1 | ~250 KB, 3+ txs per range proof (estimate). Our STARK is cheaper and post-quantum. | — | landscape survey, 2026-11-04 (estimates; notes not published) |
