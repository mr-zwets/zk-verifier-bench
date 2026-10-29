# Track 6: a universal-setup PLONK/KZG verifier on CashVM (gnark, BN254, SHA-256 transcript)

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

**Circuits** (both without gnark's BSB22 `api.Commit` commitments; the generator refuses keys that have them):

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
- **Today's regime missed the model by 22–25 KB.** The model assumed the MSM state could be handed between inputs. In practice the 576–608 table items must be published (about 17 KB), and every MSM input pays about 1.5M op to reload them. This is the main negative result.

## 5. Comparison with Groth16

| regime | PLONK/KZG (this build) | Groth16 reference (bench main) | ratio | design estimate, recommended (GT fold) |
|---|--:|--:|--:|--:|
| bch-spec | 66.3–68.7 KB | 21,915 B (sound-si-gls)¹ | 3.0–3.1× | 55.1 KB (2.5×) |
| 100 KB input | 69.8–72.4 KB | 29,294 B (si-gls TXv5 padded) | 2.4–2.5× | 60.2 KB (2.05×) |
| today, standard | 92.8–96.0 KB, 10 inputs | 27,624 B, 3 inputs (sound-native) | 3.4–3.5× | 66.0 KB, 7 inputs (2.4×) |

¹ The bench also holds sound-si-gls-dproj at 16,571 B on bch-spec. It cannot be padded for TXv5. Against it, the ratio is about 4.0–4.1×.

**The price of a universal setup is about 2.4–3.5× the bytes of a Groth16 verifier**, in exchange for needing no per-circuit ceremony. The cost is nearly independent of circuit size: merkle16, with 15,110 constraints, costs only 2–3% more than mul2. The added cost comes from a third public input and Qk, not from n.

**Where the difference comes from:**
- PLONK checks 9 proof commitments plus 8–9 fixed selector and permutation commitments in one G1 MSM of about 45M op. That is roughly two Groth16 verifiers' worth by itself.
- The fixed-G2 pairing is cheaper than Groth16's: 12.3M op, against about 18M for the 88 SI-GLS events. That saving is real, but small next to the MSM.

**What would close part of the gap:**
- **GT folding** of the fixed bases: the design estimates about −6 KB single-input. In the chain it also removes the TF table and part of the per-input reload.
- **Choosing J per circuit** from a liveness sweep.
- **Cheaper table sharing** in the chain.
- **fflonk** would shrink the MSM, but gnark does not implement it.

**What still fits:**
- Every regime fits in **one transaction**.
- Today's standard rules need 10 inputs and leave only 4.4 KB for merkle16. A circuit with a few more public inputs or fixed bases may need an 11th input and could exceed 100,000 B.

## 6. Caveats

- **Soundness argument.** The verifier deviates from gnark in three places: the t'-fold of the witnessed Λ', the batching with u = u1 + λu2, and the chain's hand-over and graph argument. Each is proved in [SOUNDNESS.md](https://github.com/mr-zwets/groth16_cashscript/blob/main/research/plonk-kzg/verifier/SOUNDNESS.md) next to the verifier, and an independent review passed it. On top of PLONK's own soundness (gnark's Fiat-Shamir instantiation, AGM/q-DLOG, honest SRS) the added error is at most Q·2^-128 plus negligible terms, about 2^-64 for Q ≤ 2^64 hash queries. The scope is VKs without BSB22 commitments. The kernel formulas are tested, not proved.
- **Unsafe test SRS.** No real ceremony file was loaded. Proofs for these keys can be forged by anyone who recomputes τ.
- **Thin liveness margins, tested on 5 proofs per circuit.**
  - bch-spec margins are 3.3–4.35% at J = 13; a 6th proof could need J = 12.
  - The 100 KB pad and the chain FILL are sized per proof, down to 0.09% and 0.14%.
  - No large sweep was run.
- **A test-hygiene gap in the 100 KB suite.** Adaptive tampered cases reuse the valid proof's pad.
  - For merkle16, 6 of the 78 rejections came from the op-cost budget, not from a verifier check: R+G, −R, H1+G, H2+G, Z+G and s1(ζ)+1.
  - The measurement review re-ran these 6 with the pad sized to each witness (292–414 B). All 6 were then rejected by the final check in both modes, so the verdict holds.
  - The committed results JSON still records the budget errors. The suggested test fix (pad per witness, and fail on budget errors) has not been applied.
- **Chain tests record standard-mode errors only.** For example, "extra input with the same locking" records the standard size error. The consensus VM also rejects that case, but its error is not recorded.
- **Unsupported cases:**
  - gnark circuits that use BSB22 commitments (`api.Commit`, used by range-check and lookup gadgets); each would add about 4–5 KB by design estimate.
  - Circuits with zero public inputs: the build asserts at build time, with no clear error.
- **Overstated claim in PROTOCOL.md.** It says ζ in the domain is rejected. Only ζ = ωⁱ for i < k (the public-input points) is rejected; elsewhere in the domain verification continues, as in gnark. The probability is about n/r, so soundness is unaffected.
- **Not done:**
  - no BCHN node run (the BCHN figures are computed);
  - GT folding not built;
  - the snarkjs/Keccak variant not built;
  - the bch-spec model not re-run for 3 public inputs.
- **Assembler.** One bug fix in the verifier's copy of asm.mjs: roll() across a sized pile. The reviewed sound-si-gls asm.mjs is unchanged.
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
- [results/verifier-summary.json](results/verifier-summary.json).

Reused Groth16 work:
- `chunked/bn254/sound-si-gls`: the SI pairing, residue root and asm.mjs;
- `chunked/bn254/bn-native-sound` and `research/sound-bn254-native`: the multi-input pattern;
- `chunked/txv5-pad`: the pad slot.

External:
- gnark v0.16.4: `backend/plonk/bn254/verify.go`, `ecc/bn254/kzg/kzg.go`, `fiat-shamir/transcript.go`;
- Aztec Ignition, as the example of a universal ceremony.

**Reproduce** (verifier worktree, node_modules linked to a bench pnpm install):

```sh
node single.mjs mul2 spec 13      # bch-spec
node single.mjs merkle16 txv5 8   # 100 KB input
node chain.mjs merkle16           # today's rules, 10 inputs
nice node test.mjs mul2 spec 13   # suites; chaintest.mjs <circuit> takes about 2 min
node summary.mjs
```

The prover's `node verify.mjs` prints "OK: 164 cases, 0 unexpected". Run `./gen-vectors.sh` with GOMAXPROCS=4 under nice.
