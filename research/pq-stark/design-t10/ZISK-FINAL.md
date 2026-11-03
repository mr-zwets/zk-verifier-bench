# Track 10 gate G1: what the ZisK final proof is (extraction from source)

Status: extraction note for gate G1. Read-only on ZisK and pil2-proofman sources, plus light compute: verifying published fixtures on CPU, an independent Python replay, and soundcalc/params10 runs on a config we wrote. Nothing here is a claim about BCH costs. Labels:
- **[SRC]**: read in the pinned source; file and line are given.
- **[RUN]**: executed here; reproduce with §13.
- **[EST]**: our estimate.
- **[UNV]**: not verified.

## 0. Gate G1 verdict: PASS (narrow)

Every item the gate asks for is pinned with a source line, and real ZisK final proofs can be obtained without a GPU. "Narrow" has three parts.

1. **The real proofs are published fixtures.** There are six: one guest program (`fib_mod`) in each of three hash families, each as a leaf (FRI) proof and a compressed (STIR) proof. They are in the ZisK repo at the release tag and verify on CPU in about 5 ms each. That is enough for the bridge's first differential tests and the tamper families. It is **not** the "≥ 20 receipts from different guests" Track 10 Stage 2 wanted.
2. **New Poseidon2 proofs need our own setup.** ZisK publishes proving keys only for **BLAKE3** (the default, 6.5 GB) and **Poseidon1** (4.9 GB). The **Poseidon2** key returns 404 in the release bucket. Producing new Poseidon2 proofs means running ZisK's setup ourselves.
3. **Local CPU proving was not attempted.** It needs system packages this machine lacks (openmpi, grpc, libpqxx, OpenMP, nlohmann-json, nasm) and `ulimit -l unlimited` (here it is 8192). Both need sudo, which only the maintainer can grant. ZisK documents no RAM figure for CPU proving within 24 GB [UNV].

**The finding that matters most for Track 10:** the "ZisK Final" in the security panel and in G0 is the **BLAKE3** setup. That is the one EF soundcalc models, and it is the default published key: 2^18 rows, 1,122 evaluations, 71 opening points, 51 queries, 27-bit grinding, BLAKE3 Merkle trees. The **Poseidon2** Final is a different and much smaller circuit:
- 2^16 rows;
- 130 evaluations and 5 opening points;
- 54 queries, ρ = 1/16, 22-bit grinding;
- Poseidon2-Goldilocks width-16, arity-4 Merkle trees;
- 369,368 B.

Run on a config we wrote from the generated verifier (§12), soundcalc's model gives it **128.97 JBR**, and params10 (G0's Track 8 accounting) gives **122.57**. The Poseidon2 Final is the bridge target recommended here.

## 1. Pins

| what | pin | how checked |
|---|---|---|
| ZisK | **v1.4.0-alpha** = `64a1f1664184e76053686745d50c6b9aaa51b034`, released 2026-10-29, the latest release on 2026-11-03 | `gh release list`, `git rev-parse` |
| pil2-proofman | **v1.4.0-alpha** = `27b2fc20d52d8b8899291505c27e156c7cd8ef9c` (tag on HEAD, 2026-10-28) | `git describe` |
| crates.io `proofman-verifier` / `proofman-fields` 1.4.0-alpha, which ZisK's `Cargo.lock` uses (checksums `e010f8ab…`, `5437c76a…`) | source **identical** to the git tag | `diff -r` of `src/` against `verifier/src`, `fields/src`: no differences [RUN] |
| soundcalc (for comparison) | `b325e30dc5dda80b21c7c0465728aca54f29087b` | as in G0 |
| Release keys (Poseidon2) | `VADCOP_FINAL_VK_POSEIDON2 = [7235627588029747190, 4964294244843319518, 15944021041411876293, 9165814394267558940]`; compressed `[4751769779349204665, 8025699667731212605, 10343005230049885991, 17515878728116835452]` | zisk `verifier/src/keys.rs:64-68` [SRC]; the const-tree root equals this key [RUN, §10] |

Release notes for v1.4.0-alpha [SRC, `gh release view`]:
- "Unified proof format".
- "Trusted release keys: verification uses the keys shipped with the release, not the ones carried by the proof".
- "STIR low-degree test: the compressed proof is now under 256 KB".
- Proof files from 1.3.1 and earlier are rejected.
- The version "is currently undergoing security and correctness audits".

Covenant consequence: a covenant is tied to one ZisK release, because every new release regenerates the keys.

## 2. Hash families, and which proof we target

- ZisK v1.4 has **three** STARK hash families, each with its own recursion circuits and keys: `HashMode::{Poseidon1, Poseidon2, Blake3}`. The default is **Blake3**.
  - Merkle arity is Poseidon1 4, Poseidon2 4, Blake3 2.
  - Source: zisk `common/src/hash_mode.rs:14-39` [SRC].
- The pipeline is guest → Main/AIRs → … → Recursive2 → **vadcop_final** (the "leaf" final STARK, FRI), then optionally → **vadcop_final_compressed** (STIR, the `--minimal` proof).
  - The optional BN254 pilfflonk wrap follows; we skip it.
  - Source: zisk `verifier/README.md`, `verifier/src/verifier.rs:35-47` [SRC].
- The generated per-family verifiers are in zisk `verifier/src/{blake3,poseidon1,poseidon2}/{vadcop_final,vadcop_final_compressed}.rs`. ZisK keeps them in its own repo "because the aggregator binds the application's publics into q_verify" (`verifier/src/lib.rs:5-7`) [SRC].

Parameters per family (from each generated `verifier_info()`) [SRC]:

| family / stage | rows | ρ | evals | opening pts | tree widths (const, cm1, cm2, Q) | LDT | queries | grinding | Merkle hash / arity | body bytes |
|---|---|---|---|---|---|---|---|---|---|---|
| **Poseidon2 / vadcop_final** | 2^16 | 1/16 | 130 | 5 (−2…2) | 47, 48, 12, 21 | FRI 20→16→12→8→5 | 54 | 22 | P2-16 / 4 | **369,368** (exact) |
| **Poseidon2 / compressed** | 2^15 | 1/16 | 130 | 5 | 47, 48, 12, 21 | STIR k=[3,4], deg [15,12,8] | [54, 36] | [22, 22] | P2-8 / 2 | ≤ 266,696 flat; fixture 199,824 (multiproof) |
| Poseidon1 / vadcop_final | 2^16 | 1/16 | 138 | 5 | 46, 48, 12, 21 | FRI 20→16→12→8→5 | 54 | 22 | P1-16 / 4 | 369,128 |
| Blake3 / vadcop_final | 2^18 | 1/16 | 1,122 | 71 | 43, 236, 60, 21 | FRI 22→18→14→10→7 | 51 | 27 | BLAKE3 / 2 | 412,152 |
| Blake3 / compressed | 2^18 | 1/32 | 649 | — | 43, 128, 36, 21 | STIR k=[4,3,3] | [41, 26, 22] | [27, 26, 23] | BLAKE3 / 2 | fixture 248,728 |

**Recommendation: target Poseidon2 vadcop_final (FRI).**
- The field is native Gl³.
- Its sponge is an x^7 Poseidon2 that Track 8's Poseidon2-Gl AIR can be re-parameterised for (§5).
- It needs about 9× fewer DEEP evaluations than BLAKE3, and 5 opening points instead of 71.
- It uses FRI, which Track 8 already verifies.

STIR (compressed) is about 46% smaller but uses a low-degree test that is new to us. Keep it as a size lever. BLAKE3 in a Goldilocks AIR (32-bit XOR and rotations) is the costliest choice in-circuit and is not recommended.

## 3. Final proof layout and size (Poseidon2 vadcop_final)

**Saved file** (zisk `verifier/src/decode.rs` doc; `verifier/README.md`) [SRC]:
- Format: `[minimal][n_publics][publics…][STARK body][vadcop_final_vk(4)][hash tag]`, as little-endian u64 words.
- A file may end with an unauthenticated seed trailer (`ZISKSEED`).
- The `vk(4)` and tag carried in the file are **untrusted**: verification uses the release key.

**STARK body**, in `stark_verify` read order (pil2 `verifier/src/verifier.rs:261-463`; geometry in `verifier/src/layout.rs:293-337`) [SRC]:
- The words below are computed by `g1/layout.py`, a re-implementation of `layout.rs`, and match the fixture byte-exactly.
- 46,171 words = 369,368 B. With 76 words of header and trailer the file is 369,976 B, the fixture size [RUN].

| region | words | bytes |
|---|---:|---:|
| roots cm1, cm2, Q (3×4) | 12 | 96 |
| evals: 130 Gl³ | 390 | 3,120 |
| const tree: 54 queries × 47 values | 2,538 | 20,304 |
| const paths: 54 × 8 levels × 12 (3 sibling digests) | 5,184 | 41,472 |
| const last level (4^2 × 4 words) | 64 | 512 |
| cm1 (48 wide) values / paths / last level | 2,592 / 5,184 / 64 | 41,920 total |
| cm2 (12 wide = 4 Gl³ columns) values / paths / last level | 648 / 5,184 / 64 | 47,168 total |
| Q tree (21 wide = 7 Gl³ chunks) values / paths / last level | 1,134 / 5,184 / 64 | 51,056 total |
| FRI roots (4×4) | 16 | 128 |
| FRI layers 1-4: values 48 / 48 / 48 / 24 per query, path levels 6 / 4 / 2 / 1, last level 64 | 2,592+3,888+64, 2,592+2,592+64, 2,592+1,296+64, 1,296+648+64 | 112,640 total |
| final polynomial: 32 Gl³ evaluations | 96 | 768 |
| PoW nonce | 1 | 8 |

Merkle paths are 59% of the bytes. `last_level_verification = 2`: the verifier recomputes each tree's top two levels from a published 16-node level. Paths stop below it (pil2 `verifier/src/verifier.rs:672-722`).

**Compressed (STIR):**
- A multiproof: duplicated siblings are removed, so the size varies per proof, with a stated bound of `flat + 8 B`.
- Fixture: 199,824 B body, 200,424 B file [RUN].
- Source: zisk `verifier/src/poseidon2/vadcop_final_compressed.rs:3677-3686`; pil2 `verifier/src/multiproof.rs` [SRC].

## 4. Field and extension

- **Base field:** Goldilocks, p = 2^64 − 2^32 + 1 (zisk `verifier/src/verifier.rs:49-51`).
  - Coset shift `SHIFT = 7`.
  - Roots of unity table `W[0..32]`, with `W[1] = p−1`.
  - Source: pil2 `fields/src/goldilocks.rs:20-57` [SRC].
- **Extension:** Gl³ = Gl[u]/(u³ − u − 1), i.e. `x^3 = x + 1` (pil2 `fields/src/extended_field.rs:265-269`) [SRC].
  - This is the **same** extension as Track 8's `CubicTrinomialExtensionField` (u³ = u + 1; pq-stark REPORT.md:380).
  - So the bridge does Gl³ arithmetic natively, with no non-native emulation.
- **Canonical encodings:**
  - Publics must be canonical (< p), or the proof is refused (pil2 `verifier.rs:278-290`).
  - **STARK-body words are not range-checked.** `Goldilocks::new` stores the raw u64, and equality compares canonical values (pil2 `goldilocks.rs:60-62, 101-104, 271-277`).
  - So a body word x in [p, 2^64) is read as x − p, and proof bytes are malleable. This does not change the statement. A bridge that takes field elements as witnesses is unaffected [SRC; observation, not a soundness claim].

## 5. Hash: Poseidon2-Goldilocks (Merkle, transcript, grinding)

**Permutation** (pil2 `fields/src/poseidon2.rs:17-130`; constants `fields/src/poseidon2_constants.rs`) [SRC]:
- S-box x^7.
- R_F = 8: 4 full rounds before and 4 after the partial rounds.
- R_P = 22 for widths 8, 12 and 16; 21 for width 4.
- An initial external linear layer before round 1.
- **External layer:**
  - Horizen Labs M4 = `[[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]` (the `matmul_m4` addition chain) applied to each 4-block.
  - Then add the column sums across blocks (`matmul_external`).
- **Internal layer:** `x_i ← x_i·DIAG[i] + Σx`.
- **Round constants:** added before the S-box, `RC` of length 2·4·W + 22.

**Widths used:**
- **Poseidon2_16** (rate 12, capacity 4): Final's Merkle leaves and nodes, and the transcript of both Final and compressed.
- **Poseidon2_8** (rate 4, capacity 4): grinding in both, and the **compressed** proof's Merkle tree (arity 2).
- Sources: generated verifier `poseidon2/vadcop_final.rs:3664-3679`, `vadcop_final_compressed.rs:3667-3675`; pil2 `fields/src/hash.rs:47-75` [SRC].

**Independent check [RUN]:**
- `g1/p2.py` is a from-scratch Python permutation that parses the constants file.
- It reproduces pil2's four test vectors (widths 4, 8, 12, 16; `poseidon2.rs:139-244`).
- Every Merkle path and transcript value in §10 was recomputed with it.

**Differences from Track 8's Poseidon2-Gl-8 AIR** (Plonky3 `0d80373`, `goldilocks/src/poseidon2.rs`) [SRC]:
- The **external round constants are identical** (the same Grain-LFSR output; for example, width 8 starts `0xdd5743e7f2a5a5d9`, width 16 starts `0x15ebea3fc73397c3`).
- The **internal diagonal differs**:
  - Plonky3 uses small `MATRIX_DIAG_8/16_GOLDILOCKS` (−2, 1, 2, …).
  - pil2 uses HL random diagonals (width 8 `0xa98811a1fed4e3a5, …`; width 16 `0xde9b91a467d6afc0, …`).
- The **4×4 matrix differs:** Plonky3 uses `MDSMat4`, pil2 the HL M4.
- The test vectors differ accordingly (width 8 on [0..7]: Plonky3 `0x020cf04a1b214d14…`, pil2 `14266028122062624699…`).
- **Consequence:** the bridge needs a Poseidon2 AIR with pil2's matrices and diagonals, at **width 16**, with width 8 also needed for grinding. Track 8's AIR structure (x^7, 8 + 22 rounds) carries over. Its constants and linear layers do not.

**Merkle** (pil2 `fields/src/merkle.rs`) [SRC]:
- **Leaf:** `linear_hash_seq` (lines 13-38).
  - Absorbs 12 elements per permutation into lanes 0..11.
  - From the second block on, it copies the previous output lanes 0..3 into lanes 12..15 as the capacity.
  - Zero-pads the last block; the digest is lanes 0..3.
- **Node:** one P2-16 permutation over the 4 child digests in index order; the digest is lanes 0..3 (lines 42-81).
- **Top levels:** recomputed by `partial_merkle_tree` with zero padding (lines 84-146).
- **Query index:** a query reads the same row index in every stage tree. FRI layer s uses `idx mod 2^{steps[s+1]}` (pil2 `verifier.rs:572-664`).

**Transcript** (pil2 `fields/src/transcript.rs:24-139`, `verifier/src/replay.rs:41-101`) [SRC]:
- A P2-16 sponge with rate 12 and capacity 4. Absorbing overwrites lanes 0..11 with the pending block and keeps lanes 12..15 from the previous state's lanes 0..3.
- **Squeeze reads all 16 lanes of the output state**, capacity included, in index order: `out[(16 − out_cursor) % 16]`. This is non-standard but deterministic, and the bridge must copy it exactly.
- Challenges are Gl³: three consecutive squeezed elements.
- **Order:**
  1. `put(root_c = vadcop_final vk)`
  2. `put(H(publics))`
  3. `put(root1)` → c0, c1
  4. `put(root2)` → c2
  5. `put(rootQ)` → c3 = ξ
  6. `put(H(evals))` → c4 = vf1, c5 = vf2
  7. for each FRI root: `put(root)` → fold challenge
  8. `put(H(final_pol))` → query challenge
  9. Query indices: a **fresh** transcript `put(query_challenge) ‖ put(nonce)`, then `get_permutations(54, 20)`, which reads 63 bits per Gl element.
- `H(x)` (`hash_commits = true`) is the first 4 lanes of a fresh transcript's state after absorbing x (`replay.rs:25-34`).

**Grinding** (pil2 `verifier.rs:512-529`) [SRC]: Poseidon2_8 on `[q0, q1, q2, nonce, 0, 0, 0, 0]`. Lane 0 must be < 2^(64−22).

## 6. FRI and STIR parameters

**Poseidon2 vadcop_final (FRI)** [SRC, `verifier_info()`, `poseidon2/vadcop_final.rs:3633-3661`]:
- `n_bits` 16, `n_bits_ext` 20 (blowup 16), 54 queries, `pow_bits` 22.
- `fri_steps` [20, 16, 12, 8, 5]: folds of 16, 16, 16 and 8.
- Fold: each query opens a coset of 2^(prev−cur) Gl³ values, interpolates it with `intt_tiny`, and evaluates at challenge·shift⁻¹·w^−idx (pil2 `fields/src/fri.rs:138-167`).
- Final layer: 32 Gl³ evaluations. The verifier interpolates them and requires the coefficients at index ≥ 2^(5−4) = 2 to be zero, so the final polynomial has degree < 2 (pil2 `verifier.rs:739-765`).
  - The source comment notes this check is what gives FRI its degree bound and that "poseidon vadcop_final [clears it] by one bit".
- DEEP batching (pil2 `verifier.rs:136-221`):
  - Within one opening point, columns are weighted by vf2^col.
  - Each group is multiplied by 1/(x − ξ·w^o).
  - Groups combine by Horner on vf1 across the 5 opening points o ∈ {−2, −1, 0, 1, 2}.
  - These are powers batchings, not independent coefficients, which matters for the soundness accounting (G0).

**Poseidon2 compressed (STIR)** [SRC, `vadcop_final_compressed.rs:3629-3661`]:
- The construction is ACFY ePrint 2024/390 Construction 5.2 (pil2 `verifier/src/stir.rs:1-18`).
- Folding factors are 2^3 then 2^4; log degrees [15, 12, 8]; log domains [19, 18, 17].
- Queries [54, 36] with 22-bit grinding per round; one OOD sample per round.
- Âns/shake hints are taken from the proof and checked at one random point.
- Binary Merkle trees with P2-8.

## 7. AIR, lookups and permutation arguments inside Final

Poseidon2 vadcop_final is the **Aggregator** AIR template of pil2's plonk2pil:
- 48 witness columns `a[48]`, 24 connection columns `S[24]`, 10 gate constants `C[10]`, and selectors.
- Poseidon2-16 is laid out at 5 rows per permutation, with CMul, FFT4, EvPol4, TreeSelector4, SelectValArity4 and PLONK gates.
- Source: pil2 `setup/stark-recurser/plonk2pil/pil/poseidon2/aggregator.pil:43-50`; header doc in `plonk2pil/setups/poseidon2/aggregation.rs` [SRC].
- The mapping is inferred from the column counts: cm1 = 48 matches `a[48]`, and 47 constants is consistent with S[24] + C[10] + selectors. It is not read from the proving key, which is not published [UNV in detail].

**The only argument across columns** is `connection(1, A, S, PIOP_BUS_PROD)` (`aggregator.pil:209`):
- A PLONK copy-constraint **grand-product** argument (gprod) over the 24-column band.
- Stage 2 (cm2) is 12 base columns, i.e. 4 Gl³ columns: the grand product and its intermediate columns.
- **There is no LogUp or gsum lookup in Poseidon2 Final.** The BLAKE3 Final has three `Lookup_gsum` buses besides the connection (soundcalc `zisk.toml:3848-3880`).

**Constraint check:**
- `q_deg` is 7, so the maximum constraint degree is 8.
- The quotient Q is opened as 7 Gl³ chunks (21 base columns).
- Q(ξ) = Σ ξ^{N·i}·Q_i(ξ) is compared with `q_verify(challenges, evals, publics, zi)` (pil2 `verifier.rs:724-736`). The only boundary is `everyRow` (`zi = 1/(ξ^N − 1)`).
- The generated `q_verify` for Poseidon2 Final is **3,378 Gl³ assignments** (1,556 multiplications, 1,813 additions or subtractions). BLAKE3's is 6,365 [RUN, line count].
- That is the "constraint DAG" the bridge must evaluate once per proof. Track 8 found that this kind of check dominates on chain.

## 8. Program identity, public outputs, and binding

**Public vector of a leaf proof** (69 Gl elements) [SRC: zisk `verifier/src/verifier.rs:29-47, 67-87`]:

`[is_vadcop_final_proof (1 = leaf) | program_vk (4) | outputs (64)]`

The compressed proof drops the flag and carries 68. Fixture values [RUN]:
- flag = 1
- program_vk = `[7446428795450488681, 14079471120546152230, 10336116091114721665, 560677452129968275]`
- outputs[0] = 190820 = 100 | 233<<8 | 2<<16, i.e. `fib_mod(100, 233) = 2`

**How the publics enter the proof** [SRC]:
- **Transcript:** after the vadcop_final vk (`root_c`), as `H(publics)` (`replay.rs:57-61`). Every challenge depends on them.
- **AIR:** boundary constraints `PUBLICS_ROW·(a[i mod 24] − publics[i]) = 0` on a fixed row (`aggregator.pil:71`). In the generated `q_verify` they appear as `evals[50+i] − publics[i]` times a selector (`poseidon2/vadcop_final.rs:12-114`).
- **vadcop_final vk:** this is the root of the stage's **constant** tree, which our replay confirms (§10). It identifies the prover setup, not the program (`keys.rs:43-46`). The verifier must take it from the release, never from the file.

**Program identity:**
- `program_vk` is the 4-element Merkle root of the program's ROM "custom commit" under the family hash (zisk `rom-setup/src/rom_merkle.rs:59-111`).
- Binding it to the executed ELF happens inside ZisK's recursion (ROM AIR and custom commit). We inherit that argument [UNV here; ZisK's responsibility, as in the panel].

**Outputs:**
- The guest commits bytes with `ziskos::io::commit_slice`, or `commit` (bincode).
- The bytes are packed little-endian into up to 64 u32 slots, appending across calls (zisk `ziskos/entrypoint/src/io.rs:57-72`; `zisklib/lib/zkvm_io.rs:90-110`; `lib.rs:329-350`).
- That gives at most 256 bytes of public output.

**Checks the stock verifier makes outside the STARK.** The bridge or covenant must re-impose them (zisk `verifier/src/verifier.rs:369-416`) [SRC]:
- Exactly 69 publics (68 compressed), each canonical.
- Flag ∈ {0, 1}. 0 means an aggregate, which is accepted only when `program_vk == vadcop vk`.
- `program_vk` equals the expected program.
- **Every output < 2^32 for a leaf.** This is checked on the host, not proved by the STARK. A bridge that exposes outputs must range-check them or require them < 2^32.
- Exact body length.
- Recommendation: the bridge enforces **flag = 1** (leaf only) and the 2^32 range.

**Can OP_SHA256 or our generator rebuild and bind them?**
- **program_vk:** OP_SHA256 cannot recompute it, because it is a Poseidon2 Merkle root over the ROM. It does not need to. Like RISC Zero's image_id, it is a 32-byte constant (4 × u64 LE) that the covenant pins, or that the generator bakes in, as an equality check on the bridge's public values.
- **vadcop_final vk:** a circuit constant of the bridge, fixed per ZisK release and hash family.
- **Outputs:** the guest can commit `SHA-256(CTX ‖ statement)` as 8 u32 slots. The BCH script recomputes it with OP_SHA256 and compares it with the bridge's public values, because the packing is plain little-endian bytes. The Track 8 Lemma-13 pattern (CTX observed before every challenge) carries over if the bridge's public values hold those words.
- **Precedent:** ZisK's own Ethereum path binds the statement as `sha256(programVK ‖ publicValues ‖ rootCVadcopFinal) mod r_BN254` (zisk `zisk-contracts/poseidon2/ZiskVerifier.sol:35-43`). A BCH covenant can build the same digest with OP_SHA256 if a single 32-byte binding is preferred. The exact `publicValues` byte encoding there is [UNV].

## 9. Is the final proof zero-knowledge? **No evidence that it is; treat it as not ZK.**

- The STARK commit path is a plain low-degree extension of the trace, followed by the Merkle tree (pil2 `pil2-stark/src/starkpil/starks.hpp:148-175`).
- There are no random rows, no blinding or masking columns, and no salted leaves.
- The verifier's degree bound is exactly the trace length (§6), which leaves no room for randomizers.
- No blinding appears anywhere in the STARK prover or verifier. The only blinding in pil2-proofman is in the **pilfflonk SNARK** wrap (`pilfflonk/docs/protocol.md:210-232`), which we skip.
- The proof is deterministic apart from the PoW nonce.
- Each proof opens 54 trace rows of every committed column, plus 130 out-of-domain evaluations.
- **Caveat:** the opened witness belongs to the vadcop_final circuit, i.e. a verifier of Recursive2 proofs. Whether this leaks the guest's private inputs through the recursion chain is not established. A ZK property cannot be claimed either way [SRC for the mechanism; the leakage extent is UNV].
- ZisK's README and book call it a "zero-knowledge proof", but no hiding mechanism exists in the STARK layers we read.
- **Consequence** (DESIGN-T10 §4.6): the ZK-inheritance lemma does not apply. If private statements are in scope, the outer BCH layer needs ZK (+25–45% bytes, per DESIGN-T10).

## 10. Stock no_std reference verifier and the differential evidence

**Reference verifiers:**
- **`zisk-verifier`** (zisk `verifier/`): `#![no_std]` with `alloc`, compiled-in release keys, typed API (`verify`, `verify_saved`, `verify_saved_words`).
- **`proofman-verifier`** (pil2 `verifier/`): `no_std` with `default-features = false`; contains `stark_verify` and `verify_multiproof_stir`.
- **`proofman-fields`:** Goldilocks, Gl³, Poseidon1/2, BLAKE3, transcript and Merkle.
- All three come from crates.io, source-identical to the git tags (§1).
- They can be used directly as the bridge's differential oracle, so Track 10 Stage 2's "write our own reference verifier" is not needed.

**What we ran [RUN]:**
- **Harness:** `g1/zv-harness/` is zisk `verifier/{src,tests}` at the tag in a standalone crate, plus `examples/g1probe.rs`. Built with cargo `-j4` under nice.
- **The crate's own test suites pass:** 13 unit tests and 8 real-proof tests.
- **`g1probe`** (output `g1/g1probe.out`):
  - All 6 fixtures verify, at 4.8 ms per Poseidon2 proof, 12–15 ms per Poseidon1 and 1.4 ms per BLAKE3.
  - Each fixture's file key equals the release key.
  - Plain rejection checks: every single-public increment (69 or 68), a 1-bit flip at three offsets in each body region (17 named regions for the Poseidon2 leaf, 16 evenly spaced points elsewhere), and a 1-bit change in the key. **Rejected: 119/119 (P2 leaf), 117/117 (P2 compressed), 118/118, 117/117, 118/118, 117/117.**
- **`g1/replay.py`:** an independent Python replay of the Poseidon2 leaf fixture using `p2.py` and `layout.py`, written without calling pil2 code.
  - It parses the body.
  - It replays the whole Fiat–Shamir transcript to the 54 query indices (first four: 991318, 728441, 794145, 824473).
  - It checks the 22-bit grinding.
  - It checks **all 432 Merkle paths** (54 queries × 8 trees: const, cm1, cm2, Q, FRI 1-4) against the published last levels.
  - It recomputes **all 8 roots** from the last levels. The constant-tree root equals the release `VADCOP_FINAL_VK_POSEIDON2`.
  - It used 3,876 P2-16 and 1 P2-8 permutations.
  - **Not** replayed in Python: the DEEP and FRI fold arithmetic, the final-polynomial degree check, and `q_verify`. These were checked only by the Rust verifier.

## 11. Can we get real ZisK final proofs without a GPU?

| route | status |
|---|---|
| Published fixtures | **Yes.** 6 proofs in zisk `verifier/tests/fixtures/` at the tag: `{poseidon1,poseidon2,blake3}_{leaf,compressed}.bin` plus `*_program_vk.json`. One guest (`fib_mod`, n = 100, m = 233). They were generated on GPU (`tools/release-artifacts/regen.sh --prove`) and **verify on CPU** [RUN]. |
| Download a proving key and prove on CPU | Keys are published for **BLAKE3** (`zisk-provingkey-1.4.0-alpha.tar.gz`, 6,539,109,839 B) and **Poseidon1** (`…-poseidon1.tar.gz`, 4,887,543,560 B). **Poseidon2: HTTP 404** [RUN, HEAD requests to `storage.googleapis.com/zisk-setup`; `ziskup` offers only `--blake3`/`--poseidon1`, `ziskup/ziskup:25-28,128-135`]. |
| Own Poseidon2 setup, then CPU proving | Possible in principle: `regen.sh --families Poseidon2` runs the setup, which writes "GBs of temporary sources". Its RAM and time are [UNV]. Whether the setup is deterministic, i.e. whether our key would equal the release `VADCOP_FINAL_VK_POSEIDON2`, is also [UNV]. |
| Local CPU proving in general | **Not attempted.** ZisK needs `ulimit -l unlimited` (here 8192) and openmpi, grpc, libpqxx, OpenMP, nlohmann-json and nasm (missing here; book `installation.md:24-36`). Both need sudo, so this is a maintainer decision. Hints of the scale: the distributed docs ask for "~32 GB free RAM" for the assembly emulator (`distributed_execution.md:160`), and the release notes cite CPU Keccak-f peak memory of 21.5 GiB. The 24 GB ceiling is at risk for anything but `--minimal-memory` runs of tiny guests [UNV]. |

**Answer:** yes, through published fixtures, enough for a first bridge and tamper matrix on one program. More diversity needs a maintainer-approved environment change, plus either (a) our own Poseidon2 setup or (b) switching the target family to Poseidon1, which has a published key but a costlier in-circuit hash.

## 12. Soundness parameters of the Poseidon2 Final (input to G0; corrects the panel)

- soundcalc's `zisk.toml` "Final" and "Final_Compressed" (lines 3825-3936) match the **BLAKE3** verifier parameters exactly: 2^18 rows; widths [43, 236, 60, 21]; 1,122 evals; 51 queries; 27-bit grinding; STIR [41, 26, 22].
- So G0's "Final 128.03, margin 0.03" and the panel's "51 queries, 27-bit grinding, 372–382 KiB, about 6–7k permutations, 1,122-term batching" describe the **BLAKE3** setup, not the Poseidon2 setup.
- We wrote `g1/zisk_p2_final.toml` from the Poseidon2 `verifier_info()`. `num_constraints` and the connection-bus shape are placeholders; their terms are about 2^−170 and do not bind. We ran it through soundcalc (our toml, its code, executed here) and params10 (G0's code, run from a scratch copy so G0's committed outputs were not overwritten) [RUN]:

| circuit | soundcalc JBR (binding) | params10 SC JBR / best-m | params10 T8 JB (BCIKS20) | UDR |
|---|---|---|---|---|
| Poseidon2 Final (FRI) | 128 (query) | 128.97 / 129.40 | **122.57** (query) | 71.28 |
| Poseidon2 Final_Compressed (STIR) | 128 (fin) | 128.63 / 129.31 | n/a (STIR) | 57.19 |
| BLAKE3 Final (G0, for comparison) | 128 | 128.03 | 118.26 (batch) | 73.5 |

- The margins are slightly better than BLAKE3's.
- Under Track 8's own accounting the Poseidon2 Final is **query-bound at 122.57**, not batching-bound. Its batching is over 130 terms instead of 1,122.
- G0's caveats stand unchanged: 128 holds only under soundcalc's BCHKS25 model with the unpublished powers step, and the two accountings must not be mixed.
- G0 should re-state its ZisK row for the Poseidon2 setup.

## 13. Implications for the bridge [EST unless marked]

**Hash work per Final verification:** 3,876 P2-16 permutations plus 1 P2-8 [RUN, replay count]. This is about 2/3 of the panel's figure and of RISC Zero's 5,693.
- Per query: 11 leaf hashes, 32 node hashes in the stage trees, 14 FRI leaf hashes and 13 FRI node hashes.
- That is 70 per query, × 54 = 3,780.
- Plus about 40 for the 8 partial top trees and about 56 for the transcript.

Other work:
- **DEEP:** 130 Gl³ evaluations over 5 opening points, per query.
- **FRI:** 4 coset interpolations per query, of sizes 16, 16, 16 and 8.
- **Constraint check:** one `q_verify` DAG of 3,378 Gl³ operations.
- **Copy-constraint argument:** the connection grand product, which is part of `q_verify`.
- **Not needed:** LogUp, a BabyBear port, or non-native arithmetic.

Bridge AIR set:
- Poseidon2-Gl-16 with pil2 constants (new), plus Poseidon2-Gl-8 (Track 8's, with pil2's matrix and diagonal).
- A native Gl³ ALU and table.
- FRI with fold 16, DEEP over 5 points, and `last_level_verification` recomputation.

Public values: about 69 Gl elements (552 B), or 8 + 4 words if the covenant pins program_vk and the guest outputs a SHA-256 digest.

## 14. Corrections to the T10 security panel's ZisK route

| panel claim | finding |
|---|---|
| Final: 51 queries, ρ 1/16, 27-bit grinding, 372–382 KiB, widths 43/236/60/21, 1,122 evals | That is the **BLAKE3** setup. Poseidon2 Final: 54 queries, ρ 1/16, 22-bit grinding, **369,368 B**, widths 47/48/12/21, **130 evals**, 2^16 rows [SRC]. |
| Merkle Poseidon2 width 16 / arity 4 [UNV] | **Confirmed** for Final. The compressed proof uses width 8, arity 2. The transcript is width 16 (rate 12) in both, and grinding width 8 [SRC]. |
| about 6–7k Poseidon2-Gl-16 permutations | **3,876** P2-16 plus 1 P2-8 for Poseidon2 Final [RUN]. |
| Final_Compressed 240–247 KiB, 89 queries | That is BLAKE3 (41 + 26 + 22). Poseidon2 compressed: 54 + 36 queries; fixture 199,824 B body; bound 266,696 B [SRC/RUN]. |
| Lookups in Final: Connection_gprod, Lookup_gsum | In Poseidon2 Final, **only the connection grand product**; gsum buses exist only in BLAKE3 Final [SRC, inferred template, §7]. |
| ZK [UNV] | **Not ZK** as far as the source shows (§9). |
| "Adapted from Track 8 M1's existing width-8 Poseidon2-Gl AIR" | Round constants are shared; the **internal diagonal and the 4×4 matrix differ**, so the AIR needs pil2's linear layers (§5). |
| "pil2-proofman ships a no_std reference verifier" | **Confirmed.** It runs on all six fixtures, and the generated per-release stage verifiers are in `zisk-verifier` (§10). |
| (unstated) which hash family | The **default** published family is BLAKE3; Poseidon2 has **no published proving key** (§11). |

## 15. Open items

1. **Poseidon2 setup reproducibility.** Run `regen.sh --families Poseidon2 --skip-checks` in a maintainer-approved environment and check that the key equals `VADCOP_FINAL_VK_POSEIDON2`, recording RAM and time [UNV]. If the setup is too heavy, decide between (a) bridging the two published Poseidon2 fixtures only for E2E-0 and (b) moving to Poseidon1, which has a published key, and re-pricing the hash AIR.
2. **CPU proving within 24 GB:** untested. It needs the system packages and the memlock change (sudo).
3. **The vadcop_final AIR is the aggregator template:** the template is inferred from column counts. Confirm it from a Poseidon2 proving key's `starkinfo`, together with `num_constraints` for the soundcalc config.
4. **The recursion chain binding program_vk to the ELF and ROM:** ZisK's argument, not reviewed here.
5. **Leakage through non-ZK openings of the recursion chain:** not analysed.
6. **The Solidity `publicValues` byte encoding:** only needed if we mirror ZisK's SHA-256 statement digest.

## 16. Reproduce

Scripts are in `research/pq-stark/design-t10/g1/`. Sources:
- `git clone https://github.com/0xPolygonHermez/zisk` at `v1.4.0-alpha`;
- `git clone https://github.com/0xPolygonHermez/pil2-proofman` at `v1.4.0-alpha`;
- soundcalc at `b325e30`.

```
python3 -I g1/p2.py <pil2>/fields/src/poseidon2_constants.rs            # 4 test vectors -> True
python3 -I g1/layout.py                                                  # body layout, 369368 / 266696 B
python3 -I g1/replay.py g1 <pil2>/fields/src/poseidon2_constants.rs <zisk>/verifier/tests/fixtures/poseidon2_leaf.bin
# harness: copy <zisk>/verifier/{src,tests} next to g1/zv-harness/Cargo.toml, then
CARGO_TARGET_DIR=<cache>/target nice -n 19 cargo test --release -j4
nice -n 19 cargo run --release -j4 --example g1probe                     # -> g1probe.out
# soundness (soundcalc venv with `toml`; run from the soundcalc checkout):
#   zkVM.load_from_toml("g1/zisk_p2_final.toml") + report_cli.print_summaries
# params10 (scratch copy, so G0's committed outputs are not overwritten):
python3 params10.py --zisk-all g1/zisk_p2_final.toml                      # -> g1/params10-p2.out
```

The outputs committed next to the scripts are `p2.out`, `layout.out`, `replay.out`, `g1probe.out` and `params10-p2.out`. Caches, the cargo target and the fixtures are not committed. They live under `work/t10-gates/cache/` and in the cloned repos.
