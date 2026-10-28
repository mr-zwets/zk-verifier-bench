# pq-hash Kernels: what a SHA-256 STARK verifier's building blocks cost on CashVM

Track pq-hash, phase Kernels (SPEC.md §8, K1–K19). Date: 2026-10-28. Branch `wip/pq-hash-kernels` (zk-verifier-bench), files under `research/pq-hash/kernels/`.

**Research only, not a leaderboard entry.** Nothing here touches REGISTRY, results.json or score-history.json.

- Full per-kernel table: [results/RESULTS.md](results/RESULTS.md).
- Derived ratios and projections: [results/RATIOS.md](results/RATIOS.md).
- Raw data: `results/*.json`.

## Question

[beyond-groth16.tsx](https://github.com/mr-zwets/zk-verifier-competition/blob/main/src/routes/beyond-groth16.tsx) gives a "BCH VM fit" for each post-quantum proof system. Those entries are estimates: "our assessment, not measured", "reviewer estimates". This phase answers two questions:

1. What do the primitives of those systems cost on CashVM (BCH 2026 rules)? That means native SHA-256 Merkle checks; emulated RPO, Tip5 and Blake2s; GF(2^128) multiplication; and prime fields of several sizes.
2. What do the building blocks of the pq-hash design (SPEC.md) cost? The design is a DEEP-FRI STARK over Goldilocks with challenges in F_{p^3}, hashed with SHA-256. The calculator's op-cost model (`params.py`, OPC) gets replaced by these measurements.

## Answer

**Hashing (32 proof bytes buy 25,600 op-cost and 16 standard hash iterations).**

| 2-to-1 hash on CashVM | op-cost per node (standard) | × what its 32 digest bytes buy | hash iterations per 32 B (of 16) |
|---|--:|--:|--:|
| SHA-256, native (`OP_CAT OP_SHA256`) | 680 | 0.03 | 2 |
| SHA-256 path level with index-bit handling, h = 32 | 1,938 | 0.08 | 2 |
| Tip5 permutation, emulated (Triton) | 756,986 per 40-byte digest | **24** | 0 |
| Blake2s compression, emulated (Stwo) | 837,797 (unrolled) / 961,245 (function) | **33 / 38** | 0 |
| RPO permutation, emulated (Miden) | 4,966,796 | **194** | 0 |
| RPO, inverse S-box witnessed (+672 proof bytes) | 1,053,526 | 41 | 0 |

- **Native SHA-256 pays its own way 13 to 38 times over.**
  - A 32-byte Merkle node buys 16 standard hash iterations and checking it costs 2, exactly as the page says.
  - In op-cost, the node buys 25,600 and a full authentication-path level costs 1,938, index bit included.
- **No emulated hash comes close to paying its way.** Every one costs 24–194 times what its digest bytes buy.
  - **RPO** costs 194×, above the page's "~100×". The x^(1/7) S-box alone is 84 exponentiations at about 50k each.
    - If the prover supplies each x^(1/7) and the verifier checks y^7 = x, the cost falls to 41×.
    - That adds 672 bytes per hash, 21 times the digest.
  - **Tip5** costs 24×, well below the page's "~100×". Its lookup S-boxes are cheap with the table kept on the stack.
  - **Blake2s** costs 33–38×, just above the page's "10–30×".

**Fields.**

| operation | op-cost |
|---|--:|
| BabyBear / M31 mulmod | 376 |
| Goldilocks mulmod | 569 |
| 128-bit prime mulmod | 1,234 |
| P-192 prime mulmod | 2,278 |
| BN254 Fr mulmod (context) | 3,588 |
| Goldilocks^2 mul | 3,657 |
| Goldilocks^3 mul: schoolbook / Kronecker-packed / Karatsuba | 8,064 / 7,449 / 10,998 |
| BabyBear^4 mul | 11,783 |
| QM31 (M31^4) mul | 15,076 |
| BabyBear^5 mul | 18,072 |

- **Op-cost is mostly an instruction count.** OP_MUL and OP_MOD on 8-byte operands cost about 200–260, but every stack move costs 100 or more.
  - Small fields lose: at the same challenge size (≈ 2^124–2^128), BabyBear^4 and QM31 cost 3.2–4.1× Goldilocks^2.
  - Karatsuba loses: it saves multiplications but adds moves.
- **GF(2^128) (Magnetar).** The best emulation costs 44,362 per multiplication. It is an integer multiplier with holes: five 26-bit-sparse parts per operand, 25 OP_MULs, one mask per bit class.
  - Against a 128-bit prime mulmod that is **36×**. A 4-bit windowed method gives 81–95×, and bit-serial shift-and-XOR 373×.
  - Against a Goldilocks^2 multiplication (also a ≈ 128-bit field) it is 12×.
  - The page's "tens to over a hundred times the op-cost of a prime-field multiply of the same size, depending on technique" holds: 36× at best, 81–373× for the textbook methods.

**STARK steps (the design, P128 shape).** The sum of the measured kernels is **1.47M op-cost per query**. The calculator assumes 0.99M.
- The 256-coefficient final polynomial is half of that: 0.71M per query evaluation, against 0.46M modelled.
- **Layout (b), one input.** The projection is ≈ 72.0M standard op-cost. That is 94% of the TXv5-as-written budget (76.5M at base 41) and 85% of bch-spec's.
  - The design expected 59%: op-cost is not slack there.
- **Layout (a).** A 10,000-byte query input runs out of op-cost after 4 queries (6.7 KB of query data). So op-cost, not bytes, sets the input count at P128 with this final degree.
- **Final degree.** At final degree < 2^5 the final polynomial costs 87k per query, and the per-query total falls to 0.85M.
  - SPEC §4.4 puts that at +8.1 KB of proof, which no longer fits one TXv5 input.
  - So the final degree is the knob that trades bytes against op-cost. The Build phase should pick it from these numbers.

## Method

**VM and accounting.**
- **Library:** libauth 3.1.0-next.8 with the BCH_2026 instruction set, the bench's VM.
- **Op-cost** = 100 per instruction (executed or skipped) + pushed bytes + arithmetic cost + hash digest iterations × 192 (standard) or 64 (consensus).
  - Arithmetic cost is 2·len(out) for most ops; OP_MUL/OP_DIV/OP_MOD add len(a)·len(b).
- **BCHN-adjusted:** BCHN also charges each executed OP_DEFINE its body's bytes (research/opcost-timing/KERNELS.md). Every table shows this where a kernel defines functions or loads code.

**Measuring one kernel** (`lib/measure.mjs`).
- The kernel's inputs are pushed by the unlocking bytecode. The locking script is `<prologue: OP_DEFINEs> OP_NOP <kernel> OP_NOP <checks> OP_1`.
- The instruction set is wrapped so that each OP_NOP snapshots the raw metrics before it executes. The kernel's op-cost is the difference between the two snapshots.
- A calibration run with an empty kernel measures 0; `run.mjs` asserts this.
- Function definitions sit outside the measured region. Their libauth and BCHN costs are reported once ("define once").

**Correctness.** Every case leaves its outputs on the stack, and the checks compare them with OP_EQUALVERIFY / OP_NUMEQUALVERIFY against an independent JS reference. An accepted run is a correctness check. Random inputs come from a seeded RNG: 1–16 trials per kernel, and the tables give mean (min–max).

| kernel family | reference |
|---|---|
| SHA-256, Blake2s | node:crypto (`sha256`, `blake2s256`), on the full Blake2s-256 of a 64-byte message |
| RPO | JS reference with Miden's constants. It reproduces all 19 hash vectors in Miden's `generate_test_vectors.py` (commit 3f7063d; constants parsed as data, the script was not run) |
| Tip5 | JS reference with twenty-first's constants. It reproduces the permutation test vector in `tip5/mod.rs` (commit d067251) |
| GF(2^128) | BigInt carry-less multiply and reduction |
| fields | BigInt |
| FRI fold | the measured formula, checked in JS against the even/odd-split definition f'(y) = Σ_t β^t f_t(y) |
| AIR check | the verifier's identity on honest values (H0(z) solved from the identity) |

**Validity under the real limits.** Every case is also run on the real BCH 2026 VM, standard and consensus, as a P2SH32 spend.
- The spend's unlocking is zero-padded so that its budget covers the whole script, including BCHN's define charge.
- "ok" in the tables means both modes accepted it.
- "over" means the padded spend would exceed one standard input (10,000 B). The cause is unrolled code above about 9 KB or 768 pushed values. Those cases are measured on the loosened VM only.
- No case was rejected for any other reason.

**Normalisation for hashes.** We divide op-cost per 2-to-1 node by the digest size, then by 25,600 (= 32 × 800).
- One RPO or Tip5 permutation is one 2-to-1 hash: rate 8 (two 4-element digests) and rate 10 (two 5-element digests).
- One Blake2s compression is one Blake2s-256 of a 64-byte node.

## Results

### Native SHA-256 and Merkle (K17, K6, K7, K8)

| kernel | standard | consensus | iterations | code B |
|---|--:|--:|--:|--:|
| node: two 32-byte children, OP_CAT OP_SHA256 | 680 | 424 | 2 | 2 |
| level, branchless `<bit> OP_ROLL OP_CAT OP_SHA256`, h = 32 / 25 | 812 / 933 | 556 / 805 | 2 / 1 | 3 / 7 |
| level, `OP_NOTIF OP_SWAP OP_ENDIF`, h = 32 | 980 | 724 | 2 | 5 |
| path level with index bit (idx mod 2, idx >>= 1), siblings as separate pushes, h = 32 / 25 | **1,938 / 2,059** | 1,682 / 1,931 | 2 / 1 | 16 / 19 per level |
| same, siblings in one blob (unrolled / loop) | 2,785 / 3,091 | 2,529 / 2,835 | 2 | 19 per level / 57 total |
| leaf hash + parse, 64 B (8 values), h = 32 | 6,913 | 6,657 | 2 | 67 |
| leaf hash + parse, 192 B (24 values), h = 32 | 21,178 | 20,666 | 4 | 195 |
| multiproof merge per node, entries as stack items, h = 32 / 25 | 4,958–5,103 / 5,367 | 4,702–4,847 / 5,239 | ≈ 2 / 1 | 492–783 total |
| multiproof merge per node, blob bookkeeping, h = 32 | 12,662–15,592 | 12,406–15,336 | ≈ 2 | 820 total |

- **h = 25 costs more op-cost than h = 32.** Truncation is `25 OP_SPLIT OP_DROP`, 3 instructions, and it saves only one iteration (192 standard, 64 consensus).
  - So h = 25 is a byte saving, not an op-cost saving.
- **Blobs are expensive.** A blob costs its remaining length in pushed bytes on every OP_SPLIT and OP_PICK.
  - Siblings pushed as separate items are 30% cheaper per level than a sibling blob.
  - The multiproof merge is 3× cheaper with entries as stack items: list direction alternates between main stack and altstack, and siblings come from the stack bottom with `OP_DEPTH OP_1SUB OP_ROLL`.
- **A deduplicated multiproof node costs about 2.6 path levels.** Deduplication saves bytes, but each saved sibling also removes 25,600 of budget.

### Emulated hashes (K16)

| kernel | standard (= consensus) | code B (+ functions) |
|---|--:|--:|
| Blake2s compression, unrolled | 837,797 | 8,787 |
| Blake2s compression, G as an OP_DEFINE function | 961,245 | 1,681 + 104 |
| RPO permutation, x^(1/7) computed (72-mul chain) | 4,966,796 | 1,744 + 1,135 |
| RPO permutation, x^(1/7) witnessed (+672 B) | 1,053,526 | 1,828 + 569 |
| RPO parts: MDS + ARK (Kronecker-packed circulant) / x^7 / x^(1/7) | 32,395 / 2,837 / 49,968 | |
| Tip5 permutation (lookup table pushed and dropped per call) | 756,986 | 1,584 + 1,801 |
| Tip5 parts: lookup S-box (net of table) / table push+drop / MDS 16×16 + RC | 12,223 / 38,656 / 56,759 | |

Implementation choices (each measured, the cheaper kept):

**Blake2s.**
- The a/c words are VM numbers, added without reduction.
- The b/d words are 4-byte LE binaries, XORed natively.
- Rotations by 16 and 8 bits are byte moves (SPLIT/CAT). Rotations by 12 and 7 are REVERSEBYTES plus OP_LSHIFTBIN/OP_RSHIFTBIN/OP_OR.
- Each value crosses between the number and binary domains once per use. That costs 3–5 instructions, and it dominates.
- A 4-lane SWAR variant (one 16-byte vector per row) was not built.

**RPO MDS.**
- The 12 elements are packed into one integer with 80-bit slots and multiplied once by the packed circulant row. The wrap-around is folded and the slots unpacked.
- That is 32k per MDS layer, against an estimated ~75k for 144 small multiplications.

**Tip5.** The 256-entry table is kept as 256 one-byte stack items, so a lookup is `<base> ADD PICK` and copies 1 byte. The canonical↔Montgomery conversion costs 2 mulmods per lookup element.

### GF(2^128) (K15), field x^128 + x^7 + x^2 + x + 1

| variant | op-cost | / 128-bit prime mulmod | / Goldilocks^2 mul | / Goldilocks^3 mul |
|---|--:|--:|--:|--:|
| bit-serial, OP_LSHIFTBIN + conditional OP_XOR, loop | 460,668 | 373 | 126 | 57 |
| 4-bit windowed, table built in-script (17k of it) | 117,009 | 95 | 32 | 14.5 |
| 4-bit windowed, table reused | 100,031 | 81 | 27 | 12.4 |
| integer multiplier with holes, 25 OP_MUL | **44,362** | **36** | **12** | **5.5** |

- **Karatsuba over 64-bit halves** was not built. Op-cost here is driven by the instruction count, not operand length, so three half-size products need more instructions, not fewer.
  - In the holes method the half-size parts would still need 25 products each.
- **The holes method is correct for any input.**
  - Each part of a 128-bit operand has ≤ 26 set bits spaced 5 apart.
  - So a column of one part product has at most 26 < 2^5 terms, and carries never reach the next bit of the same class.
  - XOR-ing the 5 products of a class before masking is therefore exact.

### Field arithmetic (K1, K2, K19)

| kernel | op-cost |
|---|--:|
| Goldilocks mulmod (OP_MUL, push p, OP_MOD) | 569 |
| Goldilocks mulmod, special-form reduction with shifts (2^64 ≡ 2^32 − 1) | 3,313 |
| Goldilocks addmod / submod / lazy add | 425 / 649 / 118 |
| Goldilocks lazy dot product of 2 / 3 / 4 (one OP_MOD) | 1,545 / 2,312 / 3,088 (≈ 772 per product) |
| F_{p^3}: mul schoolbook-lazy / Kronecker packed in-out / Kronecker unpacked / Karatsuba | 8,064 / 7,449 / 9,067 / 10,998 |
| F_{p^3}: square / × F_p / add reduced / add lazy / add packed | 6,273 / 2,896 / 2,549 / 1,632 / 186 |
| 192-bit prime (P-192) mulmod / addmod (K19) | 2,278 / 1,040 |

- **Special-form reduction is not worth it.** It needs about 25 instructions where OP_MOD needs 2, so it costs 5.8× as much.
- **K19, a 192-bit prime field.** Its multiplication costs 0.28× an F_{p^3} multiplication.
  - The price is 3× larger trace leaves: +128 B per query at k0 = 4, which buys 102k op-cost.
  - The FRI arithmetic per query is a few hundred thousand op-cost, so the 192-bit field would save more than the extra bytes buy.
  - It is worth a look only if op-cost binds. The P128 projections above suggest it might.

### STARK steps (K3, K4, K5, K9–K14)

| kernel | op-cost (std) |
|---|--:|
| **K3** F_p inversion, chain for p − 2 (76 squarings + 10 mul) | 60,200 |
| **K3** F_{p^3} inversion via norm (adjugate + F_p inversion) | 72,097 |
| **K3** F_{p^3} inversion with a witnessed norm inverse (+8 B) | 12,943 |
| **K3** F_{p^3} witnessed inverse, check a·inv = 1 (+24 B) | 8,623 |
| **K3** DEEP denominator 1/(x − z), x ∈ F_p, per-proof norm/adjugate polynomials, witnessed norm inverse (+8 B) | 13,366 |
| **K4** 7·ω_N^v: binary unrolled / 4-bit windows (P100, 21 bits) | 30,290 / 16,022 |
| **K4** same for P128 (19 bits) | 27,543 / 13,224 |
| **K5** digest → F_{p^3} challenge (incl. its SHA-256) / → query index / grinding check | 3,735 / 1,427 / 1,342 |
| **K9** full transcript of SPEC §3.4 (14 F_{p^3} challenges, grinding, s indices), P100 / P128 | 129,412 / 164,175 (146 / 167 iterations) |
| **K9** read 1,000 B from a 10,000-byte sibling input | 21,805–27,805 |
| **K9** code load of 2,000 / 4,000 / 8,000 B (read, SHA-256 check, OP_DEFINE), libauth; BCHN-adjusted | 13,318 / 25,270 / 49,366; 15,318 / 29,270 / 57,366 |
| **K9** 768 values pushed as numbers, bound by hashing the own unlocking region | 37,546 |
| **K12** the same 768 values parsed from a 6,144-byte blob | 610,544 |
| **K10** DEEP value f0 at one point (inverses given) | 42,359 |
| **K11** fold arity 4: IDFT + Horner / 2 binary folds | 57,213 / 58,559 |
| **K11** fold arity 8: IDFT + Horner / 3 binary folds | 174,270 / **134,686** |
| **K11** fold arity 16: IDFT + Horner / 4 binary folds (C100 only) | 587,617 / 287,741 |
| **K11** O1 splice of a derived value into a leaf | 3,564 |
| **K12** final polynomial, 256 F_{p^3} coefficients at a base point (best: component-major, coefficients PICKed, reduce every 3 steps) | **706,281** |
| **K12** same, 32 coefficients | 87,162 |
| **K13** AIR identity at z, cross-multiplied (16 F_{p^3} squarings, P_c, constraints, boundaries) | 334,043 |
| **K14** loop iteration / function call / skipped instruction | 405 / 201 / 100 |

### Per-query composition, P128 shape (sum of kernels, not a measured verifier)

This is a sum of the kernels above for k0 = 4, folds 4, 8, 8, final degree < 2^8, h = 32 and b = 8 levels in the query blob. Details are in [results/RATIOS.md](results/RATIOS.md).

| step | op-cost |
|---|--:|
| query index, x0 and x0^−1 | 27,875 |
| 4 leaf hashes + parses | 70,446 |
| 32 Merkle levels in the query blob | 62,010 |
| 8 DEEP denominators (witnessed norm inverses) | 106,925 |
| 4 DEEP values | 169,438 |
| folds 4 + 8 + 8 | 326,584 |
| final polynomial (256 coefficients) | 706,281 |
| **total** | **1,469,558** |

- The total leaves out loop glue, fold consistency compares and the multiproof above the cap.
- **Layout (b), P128, one input.**
  - Projected total: 43 queries × 1.41M (without the in-blob levels) + ≈ 2,134 multiproof nodes × 5.1k + 0.54M fixed (transcript, AIR at z, final-polynomial binding) ≈ **71.9M**.
  - That is 94.0% of the TXv5-as-written budget (76.5M at base 41) and 85.1% of bch-spec's.
- **Layout (a).** A query input has measured fixed work of 0.83M: transcript, code load, reading the PT, and parsing the final polynomial from it.
  - Under the 94% rule 4 queries fit, which is 6.7 KB of query blobs.

## The page's "BCH VM fit" column against the measurements

| row (page text) | measured | verdict |
|---|---|---|
| Miden: "emulated RPO costs far more than its bytes buy"; comment: RPO ~100× | RPO 194× per 32-byte digest (41× if the x^(1/7) are witnessed, at +672 B per hash) | **holds**; the factor is about 2× the page's, not 100× |
| Triton: "Tip5 emulated with field math"; comment: Tip5 ~100× | 24× | direction holds; **the factor is about 4× too high**. Tip5 is the cheapest emulated hash measured, because its lookup S-boxes avoid the x^(1/7) chain |
| Stwo: "Blake2s emulated with bitwise ops, likely needs padding"; comment: Blake2s ~10–30× | 33× (unrolled), 38× (function) | holds; slightly **above** the range. "Likely needs padding" stands: a Merkle node needs 33× the op-cost its bytes buy |
| Magnetar: "GF(2^128) math emulated and costly"; text: "tens to over a hundred times the op-cost of a prime-field multiply of the same size" | 36× (holes) / 81–95× (windowed) / 373× (bit-serial) a 128-bit prime mulmod; 12× a Goldilocks^2 mul | **holds** as written |
| text: "each 32-byte node it carries buys 16 hash iterations, and checking it with native SHA-256 costs 2" | 2 iterations per node; op-cost 680 per node, 1,938 per path level with index bit (2.7% / 7.6% of 25,600) | **holds** |
| text: "that should cover the hashing with room to spare and the field arithmetic of folding and out-of-domain checks too" | hashing: yes, about 13× room. Field arithmetic: at P128 the kernel sum is ≈ 94% of a TXv5-as-written input's budget, about half of it the final polynomial | **partly**: hashing is cheap; the folding / final-polynomial arithmetic roughly fills, not "covers with room", the byte-tied budget at 128 bits |
| Lattice Jolt: "transcript hash and lattice-check cost not yet assessed" | not measured (K18 was optional and is not done) | open |

## Implications for the Build phase

These are measured design choices; each one names the cheaper option.

1. **Final polynomial.**
   - Push the 768 coefficient values as minimal number pushes and bind them by hashing the own unlocking region: 37.5k, against 610.5k to parse them from a blob.
   - In layout (a), only the input that holds the coefficients can do this. The others must parse.
   - Evaluate component-major with coefficients PICKed at constant depths: 0.71M per query evaluation.
   - The final degree is the main op-cost knob. Degree < 2^5 makes it 87k per query.
2. **DEEP denominators.** Use per-proof norm and adjugate polynomials of (x − z) with a witnessed norm inverse: 13.4k and +8 B per denominator. A computed F_{p^3} inversion costs 72k.
3. **Folding.** Fold arity 8 as three binary folds (135k, against 174k for IDFT + Horner), with β, β², β⁴ as per-proof constants. Arity 16 is 2.2× arity 8 at best.
4. **Merkle.** Push siblings as separate items and take the bit branchless (`<bit> OP_ROLL`). For multiproofs, keep entries as stack items (5.1k per node), not in blobs (13–16k).
5. **Domain points.** 4-bit windowed table blobs: 13–16k per point and its inverse table, against 28–30k binary.
6. **h = 25 at P100 saves bytes only.** It costs slightly more op-cost per level than h = 32.
7. **SPEC §6.4 and the layout model.** Replace OPC with these numbers:
   - base_mulmod 600 → 569;
   - ext_mul 5,400 → 8,064 (7,449 packed);
   - merkle_level 1,300 → 1,938;
   - parse_elem 350 → about 740–820;
   - exp_base 20,000 → 13,224 (windowed);
   - inv(3) 110,000 → 72,097 (or 12,943 witnessed);
   - final polynomial 0.46M → 0.71M per query.
   - With these, op-cost binds per input at P128 in layout (a) and nearly binds in layout (b).

## Limits

- **Upper bounds, not lower bounds.** These are our implementations. Cheaper ones may exist: a SWAR Blake2s, a better Tip5 lookup, an even sparser GF(2^128) split. No lower bound is claimed.
- **libauth only.** BCHN time per op-cost was optional and was not measured; it applies to the BCHN rig of research/opcost-timing. BCHN-adjusted op-cost is computed, not run on BCHN.
- **Grinding test target.** The grinding kernels use an 8-bit target so that test cases can be ground in JS. The script differs only in the mask constant, so the cost is the same as for 28 bits.
- **Projections are sums of kernels.** The per-query, layout (a) and layout (b) figures are not a measured verifier. They omit loop glue and consistency compares, so they are slightly low.
- **K8 stack assumption.** The item-based multiproof kernel needs the proof siblings at the bottom of the stack (`OP_DEPTH OP_1SUB OP_ROLL`). A full verifier must arrange for that or pay a fixed depth offset.
- **Out of scope.** K18 (lattice step) was optional and is not done. Zero-knowledge is out of scope for the design: there is no masking.
- **Constructive only.** The kernels are honest computations with correctness checks. There is no attack construction.

## Reproduce

```
cd research/pq-hash/kernels
node run.mjs            # all kernel files -> results/*.json (TRIALS=n to override trial counts)
node table.mjs          # results/RESULTS.md
node ratios.mjs         # results/RATIOS.md
```

Requires the repository's pinned dependencies (`pnpm install`; libauth 3.1.0-next.8). A full run takes a few seconds.

**Files.**

| file | contents |
|---|---|
| `lib/asm.mjs` | assembler, symbolic stack |
| `lib/slp.mjs` | straight-line program compiler with last-use moves |
| `lib/measure.mjs` | marker-based measurement, real-VM check |
| `lib/fp3.mjs` | F_{p^3} program builder and reference |
| `lib/ref-field.mjs` | field references |
| `lib/ref-rpo.mjs` | RPO reference |
| `data/rpo-constants.json`, `data/tip5-constants.json` | constants and test vectors, with provenance |
| `k-hash.mjs` | K5–K8, K17 |
| `k-field.mjs` | K1, K2, K19 |
| `k-gf128.mjs` | K15 |
| `k-blake2s.mjs`, `k-rpo.mjs`, `k-tip5.mjs` | K16 (k-rpo.mjs also holds the K4 exponentiation chain) |
| `k-stark.mjs` | K3, K4, K9–K14 |