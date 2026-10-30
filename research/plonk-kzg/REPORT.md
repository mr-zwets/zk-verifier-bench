# Tracks 6 and 7: a universal-setup PLONK/KZG verifier on CashVM (gnark, BN254, SHA-256 transcript)

Status: research. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json, and the website is unchanged.

- **Track 7** (2026-10-30, first part below) makes the verifier usable for real circuits: a public ceremony SRS, gnark's BSB22 commitments, and a cheaper verifier (GT folding plus a redesigned today's-rules chain).
- **Track 6** (2026-10-29, second part) is the first build. Its text is kept as it was, except where Track 7 resolves a caveat; those places are marked **Track 7:**.

---

## Track 7 (2026-10-30): a verifier for real circuits

Two internal reviews ran on the integrated build: protocol/soundness (fix: 1 major, 5 minors) and measurement (fix: 1 blocker, 4 minors). A fix phase resolved every finding. A re-review of the fixes passed with six minor findings, and those were applied too (§T7.6).

The verifier sources are on groth16_cashscript `main` (merged at f4fb374, branch head 4d0cfc7). The integrated summary is copied here as [results/verifier-summary-track7.json](results/verifier-summary-track7.json).

### T7.1 What changed

Track 6 left three gaps between the verifier and a real deployment. Track 7 ran one branch per gap, then integrated them into one default build.

| | Track 6 (main) | Track 7 (integrated) |
|---|---|---|
| SRS | unsafe test SRS (τ = SHA256(seed)) | Aztec Ignition ceremony, loaded and checked |
| BSB22 commitments (`api.Commit`) | refused by the generator | one commitment per circuit, all three regimes |
| fixed MSM bases | in the G1 MSM; table TF published in the chain | GT-folded into the pairing; TF gone |
| chain hand-over | Track 6 layout | cheaper table reads, three-piece quotient, BCHN-safe FILL |
| circuits | mul2, merkle16 | mul2, merkle16, range64, merkle16rc |
| bch-spec / 100 KB / today (mul2) | 66.3 / 69.8 / 92.8 KB | 59.3 / 63.3 / 83.2 KB (lower bounds) |

The Track 6 build is still available as `FOLD=0`, and its chain and redeem bytes are unchanged.

### T7.2 Ceremony SRS: Aztec Ignition

The vectors now use **Aztec Ignition (MAIN IGNITION)**:
- 176 participants (2019-10-25 to 2019-12-17), then a sealing step by Aztec.
- Every transcript is public.
- Its final [x]_2 equals the manifest's `crs.t2` and the point hardcoded in barretenberg's Solidity verifier and independent ports.
- 100.8M G1 powers, so circuits up to n = 2^26.

Ignition stores raw points at fixed offsets, so HTTP byte ranges are enough. About 13 MB was downloaded; it is cached locally and not committed. A new tool, `prover/ceremony/main.go`, downloads, checks and writes a gnark-crypto SRS file. Its record is committed as `prover/srs/ignition_bn254_65539.json`.

**What is checked:**
- the manifest sha256 (d231a1de…41b8), and its `crs.t2` against the pinned [x]_2;
- every transcript header, and every point canonical, on the curve and in the subgroup;
- the chain of first powers over all 176 contributions plus the seal: e([x_k]_1,[1]_2) = e([1]_1,[x_k]_2) and e([x_k]_1,[1]_2) = e([x_{k-1}]_1,[z_k]_2);
- all 65,538 sealed powers used, by one random-linear-combination pairing check. A control run with [1]_2 in place of [x]_2 fails, as it should;
- the same points in barretenberg's `monomial/transcript00.dat` and `flat/g1.dat`.

**What is not checked** (it would need about 1.1 TB of downloads): consistency of all 100.8M powers in every participant's transcript, the BLAKE2b checksums of the full files, and the participants' signatures.

**In the prover and verifier:**
- `prover/srs.go` (`-srs FILE`) pins the derived SRS file's sha256 (ee63bf8e…bb85). It re-checks [1]_1, [1]_2 and [x]_2, and re-runs the power check on the n+3 points each circuit uses.
- `-unsafe-test-srs` still builds the Track 6 vectors.
- The VK is reproducible: rerunning setup from the SRS file gives identical keys.
- `verifier/srs-check.mjs` checks the constants baked into every build against the ceremony: the VK's [1]_1, [1]_2 and [x]_2; all 22 [x]_2 slope pieces in each single-input redeem; the slice hashes in each chain; the six number pushes of [x]_2 and ψ([x]_2). A control G2 point's constants must be absent, and are. It passes for all four circuits.

**Size cap:** n ≤ 2^16 with the committed settings (65,539 points); `-log 22` reaches 2^22 from one transcript file; the full ceremony allows 2^26.

Only [x]_2 and the VK commitments changed. Redeem sizes are byte-identical to the test-SRS build, and the Ignition re-run of Track 6 moved scores only within the proof-to-proof spread.

### T7.3 BSB22 commitments

gnark's `api.Commit` is used by `std/rangecheck` and lookup gadgets, so most real circuits need it. Track 7 supports **one commitment per circuit (m = 1)**, as gnark v0.16.4 verifies it. Per commitment j:

| object | where | what the verifier does |
|---|---|---|
| Qcp_j, row index cci_j | VK | bound into γ after Qk, before the public inputs |
| Bsb22_j | proof (64 B) | bound into α before Z |
| hc_j = hash-to-field(Bsb22_j) | computed | RFC 9380 expand_message_xmd, SHA-256, DST "BSB22-Plonk", 48 B mod r: 3 SHA-256 calls |
| hc_j·L_{k+cci_j}(ζ) | PI(ζ) | denominator joins the one batched inverse |
| qcp_j(ζ) | proof scalar | Lin += qcp_j(ζ)·Bsb22_j; KZG fold adds Qcp_j with v^(6+j) |

- The proof grows from 768 B to 864 B (MarshalSolidity layout: 768 B, then m scalars, then m points).
- In the folded build, Qcp_j is a VK constant, so it becomes a 10th GT-folded base. Bsb22_j is an 11th variable base.
- **One deviation from gnark:** Bsb22 at infinity is rejected; gnark accepts it. Honest commitments are blinded, so this loses completeness only with probability 1/r.
- **k ≥ 1 is now required.** L_1(ζ) is read from the ω⁰ denominator. With k = 0 and a commitment, that entry would be the commitment's, and the check would differ from gnark's. `parseVK` now refuses k = 0 in all builds, with a clear error.

**New circuits** (Ignition SRS, `std/rangecheck`, one commitment each):

| circuit | public inputs | statement | constraints | n | tampered vectors |
|---|--:|---|--:|--:|--:|
| range64 | 1 | a·a = n0, 0 ≤ a < 2^64 | 129 | 2^8 | 86 |
| merkle16rc | 3 | merkle16 with a private 64-bit amount in the leaf | 15,680 | 2^14 | 91 (13 on the commitment) |

- `verify.mjs` passes 351/351 cases over the four circuits.
- On every valid proof, hc equals gnark-crypto's Go value, and the recomputed `lin` equals gnark's ClaimedValues[0].
- gnark's own Verify rejects every tampered case its structures can hold (37 + 38 + 44 + 47).

**Cost of one commitment** (merkle16rc against merkle16, same k and n, integrated build):

| regime | merkle16 | merkle16rc | delta |
|---|--:|--:|--:|
| bch-spec | 60,567–61,306 (J = 23) | 64,957–65,760 (J = 21) | +4.4 KB |
| one 100 KB input | 64,631–65,355 | 68,764–69,363 | +4.0 KB |
| today, 10 inputs | 85,369–85,537 | 89,531–89,864 | +4.2–4.3 KB |

Nearly all of it is the two extra bases. Bsb22 costs about 1.6 KB of slopes and 2.1M op. Qcp costs 65 nibble bytes, about 10.8k op per Miller event and about 25 more quotient words. The hash-to-field, the longer transcripts and the Fr term cost about 0.12M op together.

At bch-spec the BSB22 circuits use J = 21 instead of 23. J = 23 leaves only 0.9% (range64) / 1.4% (merkle16rc) BCHN-adjusted margin; J = 21 gives 3.4% / 3.9% for about 0.9 KB more.

On its own branch (no fold, test SRS), the BSB22 chain **did not fit**: 103.7–104.1 KB in 11 inputs, with TV at 10,560 B over the 10,000 B item limit. The integrated build fits (§T7.4).

### T7.4 Chain redesign and GT fold

Track 6's main negative result was the chain: 22–25 KB above the design model, because the MSM tables had to be published and reloaded in every MSM input (§4 of Track 6). Track 7 measured the alternatives with a new function-level profiler, then built the two that helped.

**Hand-over alternatives:**

| idea | result | why |
|---|---|---|
| disjoint base subsets per input, hand over partial sums | negative | each subset needs its own 255 doublings: ≥ 8.2 KB, against ~1.3 KB for the shared-doubling hand-over |
| recompute tables locally | negative | 270 slope additions per input: +5.3M op, +8.6 KB |
| fixed-base tables as redeem constants | negative | paid in every input; same bytes as publishing (the fold then removed this table) |
| balanced SPLIT tree to read published tables | **kept** | table reload 1.055M → 0.649M op per MSM input |
| SI loop state on the altstack | **kept** | −0.3M op per SI role (ROLL costs item length plus depth) |

**GT fold.** The fixed bases (Ql, Qr, Qm, Qo, Qk, S1–S3, [1]_1, and Qcp_j) leave the G1 MSM. Their contribution e(s_i·B_i, [1]_2) is folded into the pairing's SI loop instead:
- baked Miller values R_{i,j} of each base and its Frobenius images;
- per-event nibble bytes (65 per base) select which factors multiply in;
- an exact binding mod r ties the nibbles to the scalar s_i.

The argument is SOUNDNESS.md Lemma 4. With 10 folded bases the quotient cap is 420 words and the SI error is 2^-243.63. The total bound stays about 2^-64 beyond gnark's own PLONK+BSB22 soundness.

**A soundness gap was found and closed while writing Lemma 4.** The first folded build did not range-check the nibble bytes. An out-of-range byte would make a table lookup read another stack item, decoupling the factors from the binding. The check `NB & 0x0f…0f == NB` now runs on every nibble byte, and out-of-range manipulations are rejected.

**Chain layout** (10 inputs, 1 transaction, one shared redeem of 154 B, code in three hash-checked blobs; merkle16rc has a fourth blob and a 205 B redeem):
- mul2 / merkle16: MJ(50..42, C0) · ST · MJ(41..39, TV) · MA(38..26 + TV2, 25..13, 12..0 + WQc) · SI(0–16 + GZ + C1, 16–34 + C2, 34–52 + WQa, 52–65 + WQb).
- BSB22 circuits: MJ(50..42, C0) · ST · MJ(41..39, TV) · MA(38..25 + TV2, 24..12, 11..0 + WQc) · SI(0–16 + GZ + C1, 16–36 + C2, 36–52 + WQa, 52–65 + WQb). merkle16rc also puts blob C3 in input 4, where it replaces FILL bytes.
- MJ/MA are Jacobian and affine MSM windows, ST is the statement and transcript, and SI the pairing roles.

**Further chain changes:**
- **TF is gone:** the fixed bases are folded.
- **TV/TV2 split:** with 11 variable bases, TV is split. TV keeps 9 bases (input 2) and TV2 holds 2 (input 3). Each host checks its own entries. Since the re-review, mul2 and merkle16 split too (Wζω alone in TV2), to give input 2 room.
- **GZ:** one SI role publishes R_{i,j}(±z), and the others read it.
- **Three-piece quotient:** WQa (4,096 B, input 8), WQb (input 9) and WQc (input 5, the last MA role). ST never joins them. It hashes each and derives z = H(h0 ‖ ρRaw ‖ H(WQa) ‖ H(WQb) ‖ H(WQc)). This was a review fix (§T7.6).
- **BCHN-safe FILL:** FILL is sized on the filled transaction and includes BCHN's OP_DEFINE bytes, so every input fits BCHN's budget by construction. Its 64 B slack is capped so it never takes an input over the 10,000 B standard limit.
- **MJ headroom:** the MSM work is balanced so that every input fits for any digit pattern. A digit stress (all digits −15) leaves the worst MJ input 772 / 539 / 379 / 339 B under 10,000 B (mul2 / merkle16 / range64 / merkle16rc), and every MA input 810 B or more (§T7.6).

Of the chain gain, about 3.7 KB comes from the hand-over work and about 7.5 KB from the fold. With the hand-over work alone (FOLD=0), mul2 / merkle16 unlocking is 88,640 / 91,364 B.

**Assembler bug.** `arrange()` kept an in-place prefix with foreign items above it. It is fixed in the verifier's asm.mjs, and every Track 6 build is byte-identical with the fix. The same pattern exists in the reviewed `sound-si-gls` and `bn-native-sound` assemblers. A follow-up check ([arrange-check](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/arrange-check), groth16_cashscript 014b529) applied the fix to every assembler copy: every reviewed entry rebuilds byte-identical.

### T7.5 Numbers

Score = unlocking + 35 B locking per input + transaction overhead. Ranges are over the 5 valid proofs per circuit, all on Ignition, accepted proofs only. Op-cost is libauth 3.1.0-next.8 standard mode; consensus mode is about 0.15% lower. BCHN-adjusted adds the OP_DEFINE body bytes: +2,539 to +2,635 per single-input spend, and +34.4k to +38.6k per chain input.

| circuit / regime | inputs (txs) | score (B) | tx bytes | op-cost std (M) | BCHN-adj. (M) | worst margin (BCHN) |
|---|--:|--:|--:|--:|--:|--:|
| mul2 / bch-spec, J = 23 | 1 (1) | 59,291–60,669 | – | 53.41–53.84 | 53.41–53.85 | 3.21% |
| mul2 / 100 KB input, J = 14 | 1 (1) | 63,276–64,622 | – | 50.50–50.90 | 50.50–50.91 | 0.10% (pad per proof) |
| mul2 / today, standard | 10 (1) | 83,238–83,521 | 82,888–83,171 | 63.54–63.99 | 63.89–64.34 | 0.80% per input |
| merkle16 / bch-spec, J = 23 | 1 (1) | 60,567–61,306 | – | 54.49–54.94 | 54.50–54.94 | 3.33% |
| merkle16 / 100 KB input, J = 14 | 1 (1) | 64,631–65,355 | – | 51.61–51.97 | 51.61–51.97 | 0.09% (pad per proof) |
| merkle16 / today, standard | 10 (1) | 85,369–85,537 | 85,019–85,187 | 65.17–65.51 | 65.53–65.88 | 0.00% per input |
| range64 / bch-spec, J = 21 | 1 (1) | 64,510–65,311 | – | 57.49–58.02 | 57.49–58.02 | 3.43% |
| range64 / 100 KB input, J = 14 | 1 (1) | 68,985–69,553 | – | 55.09–55.55 | 55.09–55.55 | 0.09% (pad per proof) |
| range64 / today, standard | 10 (1) | 89,259–89,500 | 88,909–89,150 | 69.45–69.78 | 69.83–70.17 | 0.41% per input |
| merkle16rc / bch-spec, J = 21 | 1 (1) | 64,957–65,760 | – | 57.36–57.86 | 57.36–57.86 | 3.87% |
| merkle16rc / 100 KB input, J = 14 | 1 (1) | 68,764–69,363 | – | 54.91–55.39 | 54.92–55.40 | 0.09% (pad per proof) |
| merkle16rc / today, standard | 10 (1) | 89,531–89,864 | 89,181–89,514 | 69.60–69.97 | 69.98–70.36 | 0.69% per input |

- **Every circuit fits every regime in one transaction.** The largest chain, merkle16rc, leaves 10.5 KB under the 100,000 B standard transaction limit.
- **The chain margins are small by construction:** FILL is sized per proof, and the BCHN adjustment is already inside them. The 0.00% is merkle16's input 6, whose pushes alone just cover its op-cost; a proof that needs more gets a FILL.

**Against Track 6** (max score; Track 6 from main, test SRS):

| circuit | bch-spec | 100 KB input | today |
|---|--:|--:|--:|
| mul2 | 66,549 → 60,669 (−8.8%) | 69,919 → 64,622 (−7.6%) | 93,095 → 83,521 (−10.3%) |
| merkle16 | 68,655 → 61,306 (−10.7%) | 72,438 → 65,355 (−9.8%) | 95,985 → 85,537 (−10.9%) |
| merkle16rc | BSB22 branch 72,760 → 65,760 (−9.6%) | 77,720 → 69,363 (−10.8%) | did not fit (≥ 103.7 KB) → 89,864 |

Op-cost fell too: mul2 bch-spec went from 58.0–58.3M to 53.4–53.8M, and mul2 today from 70.6–71.0M to 63.5–64.0M.

**Tests** (all 12 suites, consensus and standard mode, 0 unexpected; every verdict matches `verify.mjs`; every rejection comes from a verifier check, none from the op budget):

| | mul2 | merkle16 | range64 | merkle16rc |
|---|---|---|---|---|
| valid accepted (each regime) | 5/5 | 5/5 | 5/5 | 5/5 |
| tampered rejected (each regime) | 76/76 | 78/78 | 86/86 | 91/91 |
| manipulations, single input | 34/34 | 34/34 | 35/35 | 35/35 |
| manipulations, chain | 40/40 | 40/40 | 41/41 | 42/42 |
| fresh review proofs, all regimes | 5/5 | 5/5 | 5/5 | 5/5 |
| chain fits the structural max quotient n_q | 348 (tx 84,603) | 384 (tx 87,417) | 420 (tx 92,090) | 420 (tx 92,384) |
| chain digit stress: worst MJ headroom | 772 B | 539 B | 379 B | 339 B |
| honest n_q, 1M sampled proofs | 198–294 | 216–315 | 231–345 | 234–351 |

The new manipulations cover:
- nibble bytes out of range;
- a folded Qcp nibble encoding s + 1;
- TV2 entry flips;
- WQc word flips, wrong sizes, and 128 B moved between WQb and WQc;
- the G0 s_0 flip;
- re-witnessed variants, with the transcript recomputed so that the named check must reject: a zero word added to WQb or WQc (same polynomial, z recomputed) fails only in ST, at the size rule; a nibble byte 0x10 (h0 recomputed, factors as for 0) fails only in the binding role, before the binding loop, at the nibble check (chain and single input).

**Per-phase op-cost** (bch-spec, proof 0, standard):

| phase | mul2 Track 6 | mul2 Track 7 | merkle16rc Track 7 |
|---|--:|--:|--:|
| decode + curve checks | 0.44M | 0.33M | 0.36M |
| transcript, hash-to-field, Fr, v/u/t' | 0.34M | 0.34M | 0.48M |
| MSM tables | 6.09M | 3.40M | 3.73M |
| P_right | 2.16M | 2.18M | 2.14M |
| P* MSM | 36.84M | 26.47M | 27.52M |
| SI setup | 0.34M | 1.90M | 2.29M |
| Miller events + boundaries (with GT factors) | 11.04M | 16.67M | 18.03M |
| terminal, quotient, final identity | 0.95M | 2.42M | 3.10M |
| **MSM share** | 75% | 60% | 58% |

The fold moves about 13M op out of the G1 MSM and adds about 9M to the pairing.

**Bytes** (mul2 bch-spec):
- **Redeem:** 23,021 B, against 18,016. The code grows from 6.2 to 11.2 KB: GT tables, R constants and the fold loop.
- **Witness:** slopes fall from 38.6 to 21.3 KB. The SI states grow from 6.5 to 7.0 KB, now with nibble bytes, and the quotient from 1.9 to 7.2 KB.

### T7.6 Reviews and fixes

**Measurement review: blocker.** The mul2 chain rejected an honest fresh proof with n_q = 264 quotient words. The GT binding sat in ST (`bindST`) and left room for only about 30 more words.

Fixing it exposed two caps that applied to every circuit:
- ST joined WQa ‖ WQb into one item, which went over the 10,000 B stack item limit from n_q = 310;
- input 9 capped n_q at about 340, below the honest tail of the BSB22 circuits (max 345 / 351 in 1M samples).

The fixes:
- `bindST` is dropped for mul2.
- The quotient is in three pieces, never joined (§T7.4).
- A new `liveness.mjs` check shows that a proof with the **structural maximum** n_q fits every input, every budget and the transaction.

So no honest proof can be rejected for its quotient size any more. The fixes cost mul2 +0.2 to +1.1 KB in the chain, and the other circuits +0.06 to +0.2 KB. The single-input builds are byte-identical.

**Protocol review: major.** k = 0 with a commitment computed the wrong L_1(ζ). It is now refused at build time (§T7.3).

**Minor fixes:**
- **SOUNDNESS.md wording:** length typing per VK, function names in place of line numbers, the WQ rule.
- **SRS checks:** srs-check covers the number pushes, and `srs.go` pins the file sha and re-checks the powers.
- **Code:** FIXED bases built per VK; summary ranges over accepted proofs only; BCHN op-cost written per chain input.
- **Defaults and packaging:** PROVER_DIR and J defaults, a `package.json`, and the reproduce docs.

**Re-review of the fixes: pass, six minor findings, all applied** (HEAD 4d0cfc7):
- **WQc host misdocumented:** SOUNDNESS and README named input 4, but the BSB22 plans put it in input 5. It is now input 5 (the last MA role) in every plan, and the docs say so.
- **FILL slack could break the standard limit:** the 64 B slack is now min(need + 64, 10,000 − unfilled size − 2) when the need fits.
- **No digit stress:** the MJ inputs' op-cost depends on the digits, and the worst case was not tested. A new stress re-witnesses every MSM role for all digits −15. Under it the old plans left input 2 only 84 B (merkle16). The plans now move one or two MSM windows from the MJ inputs to the MA roles, split TV for every circuit and, for merkle16rc, add a code blob C3 in input 4. The worst MJ input now keeps 339–772 B. The chain costs +0.5 KB (mul2) and +0.8 KB (merkle16), and 0.3–0.5 KB less for the BSB22 circuits.
- **Budget rejections counted as passes:** `test.mjs` now pads every case to its own witness's need, and an op-cost or density error fails the test. The 3 / 10 / 37 budget rejections of the 100 KB suite are gone.
- **"Only the final identity fails" was not checked:** the n_q stress now requires the last input to fail at its last check (in the role body, with no check after the failing instruction).
- **Size rule and nibble check reached only through hash mismatches:** the re-witnessed variants above now reach those checks directly.

The 20 fresh review proofs were re-run on the new plans and all are accepted (tx 82,989–89,540 B).

### T7.7 Comparison with Groth16 and the design model

| regime | PLONK/KZG Track 7 | Groth16 reference | ratio (Track 6) | design estimate (GT fold) |
|---|--:|--:|--:|--:|
| bch-spec | 59.3–65.8 KB | 21,915 B (sound-si-gls) | 2.7–3.0× (3.0–3.1×) | 55.1 KB |
| 100 KB input | 63.3–69.4 KB | 29,294 B (si-gls TXv5) | 2.2–2.4× (2.4–2.5×) | 60.2 KB |
| today, standard | 83.2–89.9 KB, 10 inputs | 27,624 B, 3 inputs (sound-native) | 3.0–3.3× (3.4–3.5×) | 66.0 KB, 7 inputs |

Ranges span all four circuits. Against sound-si-gls-dproj (16,571 B, bch-spec only), the ratio is 3.6–4.0×.

- **Single input:** the build is now close to the design's GT-fold estimate: mul2 is +7.6–10.1% at bch-spec and +5.1–7.3% at 100 KB.
- **Today's regime is still 17.2–17.5 KB above the model** (mul2). Two costs remain:
  - each of the 4 SI roles rebuilds the GT tables (about 0.95M op each);
  - the code blobs total about 17 KB, of which 3.2–3.6 KB are per-circuit R constants.

**The price of a universal setup is now about 2.2–3.3× a Groth16 verifier's bytes.** A circuit with range checks costs about 4–5.6 KB more than one without.

### T7.8 Caveats (Track 7)

- **Liveness is stress-tested, not proved.** 10 real proofs per circuit pass (5 committed, 5 fresh from the review). Two stress tests cover what varies per proof:
  - the quotient size, at the structural maximum n_q;
  - the MSM digits, with every digit nonzero: the worst MJ input keeps 339 B (merkle16rc) to 772 B (mul2) under 10,000 B.
- **Thin margins:** bch-spec 3.2–3.9%. The 100 KB pad and the chain FILL are sized per proof (0.00–0.80% per input).
- **m ≥ 2 commitments** are built by the same code but untested. For m ≥ 3, the γ and v hash lengths can coincide (SOUNDNESS §8).
- **k = 0 is refused,** not supported. Supporting it needs the ω⁰ denominator as an extra batch-inverse entry.
- **SRS:** Ignition is verified as far as the verifier relies on it. The full transcripts (about 1.1 TB) and the signatures were not checked. Builds above n = 2^22 need the tool to read further transcript files.
- **No BCHN node run.** The BCHN op-cost is modelled from the DEFINE body bytes, not measured.
- **Reviewed once:** the review fixes passed a re-review, including the three-piece quotient argument (SOUNDNESS §0, §1, Lemma 3). The re-review's own six minor fixes (plans, stress tests, test rules) were not reviewed again.

### T7.9 Sources

groth16_cashscript `main`:
- [`research/plonk-kzg/prover/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/plonk-kzg/prover):
  - `ceremony/main.go` (Ignition download and checks), `srs.go`, `srs/ignition_bn254_65539.json`;
  - `circuits.go` (range64, merkle16rc);
  - FORMAT.md (SRS, BSB22 commitments, k ≥ 1), PROTOCOL.md (BSB22 commitments);
  - `vectors/{mul2,merkle16,range64,merkle16rc}.json`.
- [`research/plonk-kzg/verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/plonk-kzg/verifier):
  - `gt.mjs` (fold), `plonk.mjs`, `si.mjs`, `script.mjs`, `multi.mjs`, `chain.mjs`, `plans.json`;
  - `srs-check.mjs`, `liveness.mjs`, `test.mjs`, `chaintest.mjs`, `summary.mjs`, `plan.mjs`, `fprof.mjs`, `sweep.mjs`;
  - `results/`, README.md (Track 7 sections).
- [SOUNDNESS.md](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/plonk-kzg/verifier/SOUNDNESS.md): Lemma 4 (GT fold), §8 (BSB22), Lemma 3 (chain, Track 7 version).

Development branches:
- groth16_cashscript `wip/plonk-usable-srs` a6ea9a8, `wip/plonk-usable-bsb22` 1a6bf9a, `wip/plonk-usable-msm` e980aa6;
- `wip/plonk-usable-verifier` 4d0cfc7, the integration of all three plus the review and re-review fixes, merged to `main` at f4fb374.

**Reproduce** (`research/plonk-kzg/verifier` on groth16_cashscript `main`):

```sh
npm install
cd ../prover && SRS_CACHE=/path/cache ./gen-vectors.sh   # Ignition download + checks, vectors, verify.mjs
cp vectors/*.json ../verifier/vectors/ && cd ../verifier
SRS_CACHE=/path/cache node srs-check.mjs
for c in mul2 merkle16; do nice node test.mjs $c spec 23 && nice node test.mjs $c txv5 14 && nice node chaintest.mjs $c; done
for c in range64 merkle16rc; do nice node test.mjs $c spec 21 && nice node test.mjs $c txv5 14 && nice node chaintest.mjs $c; done
for c in mul2 merkle16 range64 merkle16rc; do nice node liveness.mjs $c 1000000; done
node summary.mjs
```

The full 12-suite matrix takes about 34 min (`chaintest.mjs` 4.6–6.4 min per circuit); `liveness.mjs` takes about 3–4 min per circuit.

---

## Track 6 (2026-10-29): the first build

Date: 2026-10-29. Status: research. **Not a leaderboard entry.** Nothing is in REGISTRY, results.json or score-history.json, and the website is unchanged. Two internal reviews were done: protocol/soundness (pass, 1 major, 3 minors) and measurement (pass, 7 minors). No fix phase ran; the major item (a written soundness argument) was done afterwards, see §6. Every finding is therefore stated below, either as a corrected figure or as a caveat. The figures in this report already include the measurement review's corrections, so a few of them differ from the verifier README on its wip branch.

## 1. Question

Groth16, which every verifier on the leaderboard uses, needs a trusted setup **for every circuit**. A BCH developer who writes a new circuit must run a ceremony, or trust whoever ran it. PLONK with KZG commitments needs one **universal** setup instead: a powers-of-tau ceremony such as Aztec Ignition or the perpetual powers of tau. Every circuit up to the ceremony's size reuses it. A verifier for such proofs would let a developer take standard tooling, compile any circuit and verify its proofs on BCH without running a ceremony.

Track 6 asks:

1. Can CashVM verify proofs from an off-the-shelf PLONK prover, unchanged, for more than one circuit?
2. What does it cost in each regime, and how does it compare with our Groth16 verifiers?
3. Does the key structural difference help? In KZG both G2 pairing arguments are fixed setup points. In Groth16 one of them is the prover's B.

Regimes:
- **Today's standard rules:** 10,000 B unlocking per input, 201 B P2S locking, 100,000 B per transaction, base 41. Multi-input chain, like sound-native.
- **100 KB inputs:** TXv5, with 100,000 B scripts, base still 41, padded to buy op-cost (the chunked/txv5-pad pattern).
- **bch-spec:** base 10,000, one input.

BCHN-adjusted op-cost adds the OP_DEFINE body bytes, which BCHN charges and libauth does not. Op-cost is libauth standard mode unless marked. Consensus mode is about 0.1% lower.

## 2. Prover and setup

**Prover.** gnark **v0.16.4** with gnark-crypto **v0.21.1-0.20260913224755-1409fe592052**. That is the version gnark v0.16.4's go.mod requires, and both are pinned in the prover's go.mod. Go 1.27.1, run under nice with GOMAXPROCS=4.

**Why gnark.** gnark's default `ChallengeHash` and `KZGFoldingHash` are SHA-256, which CashVM hashes natively. The whole PLONK transcript is 6 SHA-256 calls (37 compression blocks with our u challenge), about 7k op, or 0.03M in situ. snarkjs PLONK uses Keccak-256 instead. That needs about 17 Keccak-f permutations, emulated with 64-bit lanes. Our rough estimate is about +24M op, comparable to a third of the whole verifier. It was **not measured**.

**Circuits** (both without gnark's BSB22 `api.Commit` commitments; the generator refuses keys that have them; **Track 7:** supported, §T7.3):

| circuit | public inputs | statement | constraints | domain n | proving time |
|---|--:|---|--:|--:|--:|
| mul2 | 2 (n0, n1) | a·b = n0, a + b = n1 | 4 | 2^3 | ~2 ms |
| merkle16 | 3 (root, nullifierHash, context) | depth-16 MiMC Merkle membership + nullifier | 15,110 | 2^14 | ~205 ms |

mul2 stands in for the bench's Groth16 statement, which has 2 public inputs. The bench's Groth16 fixtures are synthetic and prove no circuit, so mul2 is the closest real statement with the same interface. merkle16 is shaped like an application.

**Sizes.** A proof is **768 B**: 9 G1 points and 6 scalars, in gnark's `MarshalSolidity` layout. The 7th claimed value, `lin`, is fully determined, so the verifier recomputes it. The verifying key is 944 B, and each public input is 32 B.

**Vectors.** Each circuit has 5 valid proofs plus tampered variants: 76 for mul2 and 78 for merkle16, 164 cases in all. An independent BigInt reference verifier (`verify.mjs`, with @noble/curves 2.2.0 only for curve and pairing operations) gives the expected verdict on all 164. On every valid proof, its recomputed `lin` equals gnark's `ClaimedValues[0]`. gnark's own `Verify` rejects all 75 tampered variants that its proof structures can represent. A clean regeneration (`gen-vectors.sh`) reproduces the keys byte for byte.

**The SRS story.** One ceremony serves every circuit:
- [1]_1, [1]_2 and [τ]_2 are shared by both circuits, and the generator asserts this.
- The rest of each verifying key (the selector and permutation commitments) is derived from the circuit with no secret.
- On chain, the verifier bakes three kinds of constant:
  - the [1]_2 Miller slopes, which are universal (5,632 B);
  - the [τ]_2 slopes, which are fixed per ceremony and shared by every circuit on it (5,632 B);
  - the circuit's VK points and Fr constants, about 0.5 KB plus a few hundred bytes.
- **The vectors use an unsafe test SRS**, with τ = SHA256(seed) mod r. Anyone can forge proofs for these keys.
- A deployment would load a public ceremony instead. Aztec Ignition's 100.8M powers allow n ≤ 2^26; the BN254 scalar field caps n at 2^28. **Loading a real ceremony file was not tried.**
- **Track 7:** done. Every vector now uses Aztec Ignition, loaded and checked (§T7.2). `-unsafe-test-srs` still rebuilds the Track 6 vectors.

**Not bound by the transcript.** gnark's γ binds the VK points and the public inputs, but not n, ω, the coset shift or the SRS. The script bakes these as constants under the P2SH32 commitment, so the locking script binds them.

## 3. Verifier design

The design document is [DESIGN.md](DESIGN.md). It contains a cost model ([model.mjs](model.mjs)), VM-measured kernels ([kernels.mjs](kernels.mjs) → [kernels.json](kernels.json)) and a Go reference verifier ([gnark-ref/](gnark-ref/)). The build implements the design's **simpler variant: plan B, no GT folding**.

**Protocol as built.** It follows gnark's `backend/plonk/bn254/verify.go`, with two verifier-side substitutions:

1. **Decode.** The 9 proof points and the witnessed Λ' must be canonical (< p) and on the curve. BN254 G1 has cofactor 1, so this is gnark's subgroup check. The curve check also rejects (0,0), so infinity is rejected; gnark accepts it. Scalars and public inputs must be < r.
2. **gnark's transcript**, byte-exact: γ, β, α, ζ. Then the Fr block: ζⁿ by log2 n squarings, one witnessed batch inverse checked as Π(ζ − ωⁱ)·inv ≡ 1, then PI(ζ), α²L1, `lin` (recomputed), s1c, s2c and the ζⁿ⁺² terms.
3. **v** from gnark's `kzg.FoldProof` transcript, which hashes Λ'. Then **our** challenge `uRaw = SHA256("u" ‖ v_raw ‖ W_ζ ‖ W_ζω)`. It gives `u = u1 + λ_GLV·u2` (u1, u2 64-bit) and a 128-bit `t'`.
   - gnark's Go verifier draws u at random. Its Solidity verifier hashes a different preimage. **u and t' are a CashVM-specific choice that no vector pins.**
   - Agreement with gnark is claimed only for γ, β, α, ζ, v, `lin` and the pairing equation.
4. **Plan B: witnessed Λ'.** The linearised commitment Λ is hashed into v, so the verifier needs its affine coordinates before the MSM. The prover supplies Λ', and one MSM computes `P* = P_left + (1 + t')(Λ' − Λ)`. If Λ' ≠ Λ, the pairing check passes for at most one t' mod r.
5. **One G1 MSM** over 18 bases (19 for merkle16; mul2's Qk is the point at infinity and is dropped).
   - Signed base-32 windows. The digits are **extracted on-chain with OP_RSHIFTNUM** from s + Σ16·32ⁱ, with no digit witness; this saved 3.9M op.
   - Tables of 16 affine multiples per base, built with witnessed slopes.
   - The first J windows run in Jacobian coordinates (no witness bytes). One witnessed inverse switches to affine. The rest are affine additions with witnessed 32-byte slopes.
   - J = 13 on bch-spec and 8 at 100 KB.
   - **No GLV in the main MSM:** doubling the tables would exceed the 1,000-item stack limit. GLV is used only for u.
6. **P_right** = −(W_ζ + u1·W_ζω + u2·φ(W_ζω)), over 14 windows.
7. **Pairing** e(P*, [1]_2)·e(P_right, [τ]_2) = 1, with the SI method of sound-si-gls:
   - two baked slope chains of 88 steps each (2 × 5,632 B), both asserted against noble at build time;
   - one residue root, 33 monic states, and an odd quotient of at most 60 words;
   - **no G2 walk and no final exponentiation.**

**Today's regime** follows the SI-MX3 pattern of `chunked/bn254/bn-native-sound`:
- **Shared redeem.** Every input uses one 102-byte redeem. It loads two hash-checked code blobs by OP_INPUTBYTECODE: C0 is 7.3–7.6 KB and C1 is 3.6 KB.
- **Graph pin:** TXINPUTCOUNT = 10, and every UTXO bytecode equals the input's own.
- **Remote reads** sit at fixed offsets, pinned by each owner's size and DEPTH checks and the minimal-push rule, so the push headers need no separate check.
- **Hand-overs** between inputs are byte-exact canonical words.
- **Roles:** MSM Jacobian ×3; statement/transcript ×1; MSM affine ×4; SI pairing ×2.
- **Published tables.** The MSM tables cannot be handed between inputs, so they are published. The variable-base tables (TV, 9.6 KB) are checked by chord/tangent equations in their host input. The fixed-base tables (TF, 7.7 / 8.6 KB) are a SHA-256-checked VK constant.

**Did the key observation hold?** Yes, but it does not decide the cost.
- Both G2 points are fixed, so one Miller event, covering both chains and the F update, costs 101.4k op. A Groth16 SI-GLS event costs 192–234k.
- With the state boundaries, the whole pairing is 12.3M op (21% of the total).
- **The G1 MSM is 75% of the op-cost**, and Groth16 has nothing comparable: its vk_x MSM has 2 public inputs.

## 4. Measurements

Score follows the bench convention: unlocking + 35 B P2SH32 locking per input + transaction overhead (63 B, plus 43 B per further input). Ranges are over the 5 valid proofs per circuit. The data is in [results/verifier-summary.json](results/verifier-summary.json), a copy of the verifier branch's `results/summary.json`. The VMs are libauth 3.1.0-next.8, consensus and standard.

| circuit / regime | inputs (txs) | score (B) | tx bytes | op-cost (std) | BCHN add-on | worst margin |
|---|--:|--:|--:|--:|--:|--:|
| mul2 / bch-spec (J = 13) | 1 (1) | 66,290–66,549 | – | 58.04–58.34M | +1,405 | 4.35% |
| merkle16 / bch-spec (J = 13) | 1 (1) | 68,494–68,655 | – | 60.42–60.72M | +1,405 | 3.3% |
| mul2 / 100 KB input (J = 8) | 1 (1) | 69,757–69,919 | – | 55.40–55.70M | +1,405 | 0.32% (pad sized per proof) |
| merkle16 / 100 KB input (J = 8) | 1 (1) | 72,188–72,438 | – | 57.60–57.85M | +1,405 | 0.09% (pad sized per proof) |
| mul2 / today, standard | 10 (1) | 92,845–93,095 | 92,495–92,745 | 70.65–71.00M | +21,686 per input | 0.14% per input |
| merkle16 / today, standard | 10 (1) | 95,637–95,985 | 95,287–95,635 | 73.17–73.49M | +22,210 per input | 0.14% per input |

- **The BCHN adjustment fits everywhere.** In the chain, the measured per-input slack after the libauth figure is at least about 32k op, which covers the 21.7k / 22.2k add-on. On a single input the add-on is under 0.003%.
- **merkle16 in today's regime has 4.4–4.7 KB of headroom** under the 100,000 B standard transaction limit.
- **Consensus op-cost** is in the summary for the single-input regimes. The chain summary records standard only.

**Tests** (verdicts identical in consensus and standard mode):

| | bch-spec | 100 KB | today |
|---|---|---|---|
| valid proofs accepted | 10/10 | 10/10 | 10/10 |
| prover-track tampered vectors rejected | 154/154 | 154/154 | 154/154 |
| witness manipulations rejected | 56/56 | 56/56 | 42/42 |

- **Adaptive re-witnessing.** Tampered proofs that still decode are re-witnessed with consistent slopes, Λ', inverses, states and quotients. The script therefore reaches its final checks.
- **The manipulations** cover:
  - slope flips and p-aliases;
  - cut, dropped and extra slope pieces;
  - inverse aliases;
  - state and quotient flips;
  - Λ' = 2Λ, Λ + G and −Λ;
  - a statement swap;
  - in the chain: hand-over, table and code-blob flips, swapped, extra, foreign or dropped inputs, and nonzero FILL.
- Every verdict matches the JS reference verifier, which in turn matches `verify.mjs` and gnark.

**Per-phase op-cost** (bch-spec, proof 0, standard):

| phase | mul2 | merkle16 |
|---|--:|--:|
| decode + curve checks | 0.44M | 0.46M |
| gnark transcript (γ..ζ) | 0.03M | 0.03M |
| Fr / public inputs | 0.14M | 0.21M |
| v, u, t', MSM scalars | 0.17M | 0.18M |
| MSM tables (270 / 285 witnessed additions) | 6.09M | 6.42M |
| P_right (14 windows) | 2.16M | 2.18M |
| P* MSM (51 windows, 13 Jacobian) | 36.84M | 38.77M |
| SI setup | 0.34M | 0.34M |
| Miller events (two fixed chains) + 33 state boundaries | 11.04M | 11.04M |
| terminal, quotient, final identity | 0.95M | 0.96M |

**What is circuit-specific** (mul2 bch-spec redeem, 18,016 B):

| part | bytes | scope |
|---|--:|---|
| [1]_2 chain slopes | 5,632 | universal |
| [τ]_2 chain slopes | 5,632 | per ceremony |
| VK points + "gamma" tag | 517 | per circuit |
| Fr constants (ωⁱ, n⁻¹, k, ω, squarings) | a few hundred | per circuit |
| code and the rest | 6,235 | generic |

The witness dominates the score. For mul2 at J = 13 it is slopes 38.6 KB, SI states 6.5 KB, quotient 1.9 KB and proof 768 B. Today's regime adds the TF table, 7,680 / 8,640 B per circuit.

**Against the design model** (plan B, no GT fold; DESIGN.md §8):

| regime | model | mul2 | merkle16 |
|---|--:|--:|--:|
| bch-spec | 61,948 | +7.0–7.4% | +10.6–10.8% |
| 100 KB input | 67,390 | +3.5–3.8% | +7.1–7.5% |
| today | 71,293 (8 inputs) | +21.6 KB (10 inputs) | +24.7 KB (10 inputs) |

- **Single input:** the build lands 3.5–10.8% above the model. The model was run for 2 public inputs and log2 n = 16, so merkle16 (3 public inputs, plus Qk) is not a like-for-like comparison. It ends up just outside the model's stated ±10%.
- **Today's regime missed the model by 22–25 KB.** The model assumed the MSM state could be handed between inputs. In practice the 576–608 table items must be published (about 17 KB), and every MSM input pays about 1.5M op to reload them. This is the main negative result. **Track 7:** reduced to 16.7–17.0 KB for mul2 by cheaper table reads and the GT fold, which removes TF (§T7.4, §T7.7).

## 5. Comparison with Groth16

| regime | PLONK/KZG (this build) | Groth16 reference (bench main) | ratio | design estimate, recommended (GT fold) |
|---|--:|--:|--:|--:|
| bch-spec | 66.3–68.7 KB | 21,915 B (sound-si-gls)¹ | 3.0–3.1× | 55.1 KB (2.5×) |
| 100 KB input | 69.8–72.4 KB | 29,294 B (si-gls TXv5 padded) | 2.4–2.5× | 60.2 KB (2.05×) |
| today, standard | 92.8–96.0 KB, 10 inputs | 27,624 B, 3 inputs (sound-native) | 3.4–3.5× | 66.0 KB, 7 inputs (2.4×) |

¹ The bench also holds sound-si-gls-dproj at 16,571 B on bch-spec. It cannot be padded for TXv5. Against it, the ratio is about 4.0–4.1×.

**The price of a universal setup is about 2.4–3.5× the bytes of a Groth16 verifier**, in exchange for needing no per-circuit ceremony. The cost is nearly independent of circuit size: merkle16, with 15,110 constraints, costs only 2–3% more than mul2. The added cost comes from a third public input and Qk, not from n. (**Track 7:** 2.2–3.3×, §T7.7.)

**Where the difference comes from:**
- PLONK checks 9 proof commitments plus 8–9 fixed selector and permutation commitments in one G1 MSM of about 45M op. That is roughly two Groth16 verifiers' worth by itself.
- The fixed-G2 pairing is cheaper than Groth16's: 12.3M op, against about 18M for the 88 SI-GLS events. That saving is real, but small next to the MSM.

**What would close part of the gap:**
- **GT folding** of the fixed bases: the design estimates about −6 KB single-input. In the chain it also removes the TF table and part of the per-input reload. (**Track 7:** built; −5.3 to −7.3 KB single-input, −10.1 to −11.2 KB in the chain together with the hand-over work.)
- **Choosing J per circuit** from a liveness sweep.
- **Cheaper table sharing** in the chain. (**Track 7:** the SPLIT-tree read is kept; the other alternatives were negative, §T7.4.)
- **fflonk** would shrink the MSM, but gnark does not implement it.

**What still fits:**
- Every regime fits in **one transaction**.
- Today's standard rules need 10 inputs and leave only 4.4 KB for merkle16. A circuit with a few more public inputs or fixed bases may need an 11th input and could exceed 100,000 B. (**Track 7:** the unfolded BSB22 chain did exceed it, at 103.7 KB; the folded build fits it at 89.2–89.5 KB tx.)

## 6. Caveats

- **Soundness argument.** The verifier deviates from gnark in three places: the t'-fold of the witnessed Λ', the batching with u = u1 + λu2, and the chain's hand-over and graph argument. Each is proved in [SOUNDNESS.md](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/plonk-kzg/verifier/SOUNDNESS.md) next to the verifier, and an independent review passed it. On top of PLONK's own soundness (gnark's Fiat-Shamir instantiation, AGM/q-DLOG, honest SRS) the added error is at most Q·2^-128 plus negligible terms, about 2^-64 for Q ≤ 2^64 hash queries. The scope is VKs without BSB22 commitments. The kernel formulas are tested, not proved. **Track 7:** SOUNDNESS.md now also covers the GT fold (Lemma 4), BSB22 commitments (§8), the Ignition SRS and the Track 7 chain (Lemma 3). The bound is unchanged at about 2^-64 beyond gnark's PLONK+BSB22 soundness. The Track 7 additions were reviewed once, and the review fixes were re-reviewed (pass, six minors, applied).
- **Unsafe test SRS.** No real ceremony file was loaded. Proofs for these keys can be forged by anyone who recomputes τ. **Track 7: resolved.** Aztec Ignition, checked as described in §T7.2. Full transcripts and signatures not checked.
- **Thin liveness margins, tested on 5 proofs per circuit.**
  - bch-spec margins are 3.3–4.35% at J = 13; a 6th proof could need J = 12.
  - The 100 KB pad and the chain FILL are sized per proof, down to 0.09% and 0.14%.
  - No large sweep was run.
  - **Track 7:** partly resolved. A 1M-sample quotient-size sweep and a stress test at the structural maximum n_q show that the quotient no longer limits liveness. 10 real proofs per circuit pass every regime. A digit stress now shows that every MSM input fits for any digit pattern (§T7.8).
- **A test-hygiene gap in the 100 KB suite.** Adaptive tampered cases reuse the valid proof's pad.
  - For merkle16, 6 of the 78 rejections came from the op-cost budget, not from a verifier check: R+G, −R, H1+G, H2+G, Z+G and s1(ζ)+1.
  - The measurement review re-ran these 6 with the pad sized to each witness (292–414 B). All 6 were then rejected by the final check in both modes, so the verdict holds.
  - The committed results JSON still records the budget errors. The suggested test fix (pad per witness, and fail on budget errors) has not been applied.
  - **Track 7: resolved.** `test.mjs` sizes the pad per witness and counts an op-budget rejection as a test failure; no rejection comes from the budget any more.
- **Chain tests record standard-mode errors only.** For example, "extra input with the same locking" records the standard size error. The consensus VM also rejects that case, but its error is not recorded.
- **Unsupported cases:**
  - gnark circuits that use BSB22 commitments (`api.Commit`, used by range-check and lookup gadgets); each would add about 4–5 KB by design estimate. **Track 7: resolved for one commitment** (+4.0–5.6 KB measured, §T7.3); two or more are untested.
  - Circuits with zero public inputs: the build asserts at build time, with no clear error. **Track 7:** `parseVK` now refuses k = 0 with a clear error; still unsupported.
- **Overstated claim in PROTOCOL.md.** It says ζ in the domain is rejected. Only ζ = ωⁱ for i < k (the public-input points) is rejected; elsewhere in the domain verification continues, as in gnark. The probability is about n/r, so soundness is unaffected.
- **Not done:**
  - no BCHN node run (the BCHN figures are computed); **Track 7:** still not done;
  - GT folding not built; **Track 7:** built (§T7.4);
  - the snarkjs/Keccak variant not built;
  - the bch-spec model not re-run for 3 public inputs.
- **Assembler.** One bug fix in the verifier's copy of asm.mjs: roll() across a sized pile. The reviewed sound-si-gls asm.mjs is unchanged. **Track 7:** a second fix, `arrange()`; every reviewed assembler was since checked and rebuilds byte-identical with it (§T7.4).
- **Known malleability, no soundness impact:** how the slope stream is cut into pieces, and the pad and FILL lengths.
- **Corrections to the verifier README** (wip branch; this report uses the corrected values):
  - merkle16 today: tx 95.3–95.6 KB, not 95.6–96.0 (that range is the score);
  - merkle16 BCHN add-on: 22,210 per input, not 21,686;
  - FILL slack: about 32k op, not 51k;
  - model deviation: 3.5–10.8%, not 4–7%;
  - chaintest: about 2 min per circuit, not 25.

## 7. Sources

groth16_cashscript (verifier sources):
- [`research/plonk-kzg/prover/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/plonk-kzg/prover) on main:
  - the gnark prover: main.go, circuits.go, encode.go, go.mod;
  - `verify.mjs` reference verifier;
  - FORMAT.md, PROTOCOL.md;
  - `vectors/{mul2,merkle16}.json`.
- [`research/plonk-kzg/verifier/`](https://github.com/mr-zwets/groth16_cashscript/tree/main/research/plonk-kzg/verifier) on main:
  - plonk.mjs, si.mjs, math.mjs;
  - script.mjs, witness.mjs, single.mjs (single input);
  - multi.mjs, chain.mjs (today);
  - test.mjs, chaintest.mjs, profile.mjs, summary.mjs;
  - results/.

zk-verifier-bench (this directory):
- [DESIGN.md](DESIGN.md);
- [model.mjs](model.mjs), [model-output.txt](model-output.txt), [model-result.json](model-result.json);
- [kernels.mjs](kernels.mjs), [kernels.json](kernels.json);
- [gnark-ref/](gnark-ref/), with the Go reference verifier and fixture.json;
- [results/verifier-summary.json](results/verifier-summary.json) (Track 6) and [results/verifier-summary-track7.json](results/verifier-summary-track7.json) (Track 7).

Reused Groth16 work:
- `chunked/bn254/sound-si-gls`: the SI pairing, residue root and asm.mjs;
- `chunked/bn254/bn-native-sound` and `research/sound-bn254-native`: the multi-input pattern;
- `chunked/txv5-pad`: the pad slot.

External:
- gnark v0.16.4: `backend/plonk/bn254/verify.go`, `ecc/bn254/kzg/kzg.go`, `fiat-shamir/transcript.go`;
- Aztec Ignition, as the example of a universal ceremony (**Track 7:** loaded, §T7.2).

**Reproduce** (verifier worktree, node_modules linked to a bench pnpm install; **Track 7:** after the integration, the Track 6 numbers need `FOLD=0` and the test-SRS vectors from `-unsafe-test-srs`):

```sh
node single.mjs mul2 spec 13      # bch-spec
node single.mjs merkle16 txv5 8   # 100 KB input
node chain.mjs merkle16           # today's rules, 10 inputs
nice node test.mjs mul2 spec 13   # suites; chaintest.mjs <circuit> takes about 2 min
node summary.mjs
```

The prover's `node verify.mjs` prints "OK: 164 cases, 0 unexpected". Run `./gen-vectors.sh` with GOMAXPROCS=4 under nice.
