# Public-input binding and the maintainer red-team gate

A Groth16 verifier proves a statement: "this proof is valid **for these public
inputs**". Checking the pairing equation is only half of it. The verifier must
also compute, or soundly check, `vk_x = IC0 + n0*IC1 + n1*IC2` from the public
inputs it claims. If `vk_x` is not tied to those inputs, anyone holding one valid
proof can claim it proves any statement they like.

## The PairFold finding (Oct 2026)

The PairFold family does not compute `vk_x` in-script. Its genesis input takes
`vk_x` as a witness, together with a 704-byte auxiliary polynomial blob, and checks
a log-derivative ("rational differential") identity at a Fiat-Shamir point. That
identity holds for **arbitrary multiplicities**, so passing it does not imply that
`vk_x` equals `IC0 + n0*IC1 + n1*IC2` for the claimed `n0, n1`.

kallisti found this while rebuilding the densless entry and withdrew that
submission (bench PR #36, groth16_cashscript PR #17). The merged entries share the
same genesis predicate. On their exact committed bytes, the following transaction is
accepted on the consensus and standard VMs:

- the real proof (A, B, C) and the **true** `vk_x`, so the pairing still holds;
- **forged** claimed public inputs (e.g. `n0 + 2`), with the auxiliary pushes
  rebuilt for them.

| entry | solver | score | forged runs accepted |
|-------|--------|------:|:--------------------:|
| `bch-groth16-intratx-pairfold5-densless` | Toorik | 33,179 | 3/3 |
| `bch-groth16-intratx-pairfold5-pevalfuse` | kallisti (rebuild) | 36,836 | 3/3 |
| `bch-groth16-intratx-pairfold5` | Toorik | 44,968 | 3/3 |
| `bch-groth16-intratx-pairfold7` | Toorik | 54,483 | 3/3 |

As a control, the same claimed inputs with `vk_x` honestly recomputed for them
(which no longer matches the proof) are rejected. So the hole is specifically that
the claimed inputs are not bound to `vk_x`.

The affected original claims remain withdrawn or held. Rejecting these runs
is necessary evidence for the public-input/MSM subclaim, but does not restore
full-verifier qualification. A corrected successor needs a new equation review
and an exact-artifact disposition; historical measurements remain history.

See the upstream maintainer discussions in [issue #28](https://github.com/mr-zwets/groth16_cashscript/issues/28)
and [issue #32](https://github.com/mr-zwets/groth16_cashscript/issues/32).

<a id="a-repaired-entry"></a>

## Historical MSM repair and later full-verifier withdrawal

`bch-groth16-intratx-pairfold5-densless-msm` kept the reconstructed densless
verifier, sliced the dead predicate out of its genesis, and added two inputs that recompute
`vk_x = IC0 + n0*IC1 + n1*IC2` from the claimed public inputs (GLV Straus); the terminal requires
the genesis `vk_x` to equal their result. Its red-team file (written by the source's
`redteam.mjs`, since the PairFold generator here no longer matches its layout) rejects forged
public inputs, adaptive forgeries with a valid MSM witness for the forged inputs, a pad-shift
forgery found in review, and invalid proof points. This demonstrates a public-input/MSM repair
only; it does not establish the soundness of the complete pairing verifier. The later F6 review
withdrew the full-verifier claim, so this entry must not be cited as a confirmed sound
submission. Source:
`chunked/bn254/densless-msm` in groth16_cashscript.

## The red-team gate

Submitters write their own `invalid` vectors. That leaves the negative set under
the submitter's control, and weak negatives (such as tampering only the P2SH
redeem push) can make a broken verifier look sound. The red-team gate adds
attacks written by the maintainers against the exact reviewed bytes:

- `src/bch/redteam/<id>.json` holds concrete attack runs against an entry's exact
  bytes. Each run is the entry's valid run with some unlockings replaced. Every
  run must be **rejected**.
- `src/harness/redteam.ts` evaluates them inside `benchmark()`. Any accepted run
  sets the verdict to the existing `FAIL (maintainer red-team attack accepted)`;
  in `results.json` this shows up as `correctness.verdict: "fail"`, with
  `correctness.redTeam` and a `failures` entry.
- The file pins the `sha256` of every locking it targets. If the entry is
  resubmitted with new lockings, the file is reported **stale** and not counted.
  Regenerate it to re-test the new bytes.

Regenerate the PairFold files (self-contained; finds the genesis input and the
public inputs from the entry's own pushes and checks the honest rebuild first):

```sh
pnpm exec tsx --max-old-space-size=8192 tools/forge-public-inputs.mts [id ...]
```

## For a fixed resubmission

A fix has to make the genesis check imply the group relation for the **claimed**
scalars, for example by explicit scalar multiplication or by a predicate whose
multiplicities are pinned to the claimed inputs. Before opening the PR:

1. regenerate the red-team file for your id with the command above;
2. confirm `pnpm benchmark <id>` reports `red-team: all N maintainer attack
   run(s) rejected`;
3. document the full equation argument and independent review in the claim
   [sheet](submission-claims.md). Passing these checks alone is necessary evidence, not a universal
   theorem.

If your construction changes the genesis layout so the tool no longer finds the
auxiliary blob, say so in the PR. The maintainers will then write an attack for
the new layout.

## Generic gates

The red-team gate needs an attack written for each layout. Two generic checks in
`src/harness/gates.ts` run on every entry:

- **Public-input binding.** An entry that declares `publicInputs` gets its claimed
  inputs re-encoded with other values (+1, -1, 0, swapped, n + r, preferring
  length-preserving encodings). Any accepted transaction fails the entry. This is a
  necessary condition only: the PairFold entries reject these naive mutations and
  still accept the adaptive forgery above.
- **Layout review.** <a id="layout-review"></a>For intra-tx entries every all-zero pad
  push is lengthened by 32 attacker-chosen bytes. If the input still accepts but a
  sibling now rejects, that sibling depends on the padded input's layout past a
  free-length push. This flags the pad-shift forgery found in review of the first
  `pairfold5-densless-msm` (input 6 read input 5's witness at a fixed offset behind a
  pad whose length nothing checked); a sibling that pins the whole unlocking triggers
  it too, so it is reported for review rather than failed.

## Coverage

Only the entries above have red-team files. The tool also matches
`bch-groth16-intratx-general`, which rejected the forgery during the
investigation; it has no file yet because that result has not been confirmed as
real input binding rather than a layout mismatch. Entries with other `vk_x`
mechanisms (crown8, the residue family, the singletons, BLS12-381) have not been
attacked this way. A missing red-team file means "not attacked", not "proven
sound".
