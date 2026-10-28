# Contributing a verifier entry

External submissions are welcome and have already shaped the leaderboard: the
covenant-threaded chunked verifiers, the residue variants, and the genpow
singletons all arrived as pull requests. This guide documents the submission
recipe those PRs established.

## The short version

A submission is a PR containing three things:

1. **Vectors JSON** in `src/bch/` — the compiled bytecode your entry actually
   runs, committed as hex (see *Vector files* below).
2. **An implementation module** in `src/implementations/bch-<id>.ts` — loads
   the vectors, declares the entry's metadata, and carries your construction
   notes and provenance in the header comment.
3. **One line in `REGISTRY`** in `src/harness/benchmark.ts`.

Include the [claims and assumptions sheet](docs/submission-claims.md) in the
implementation header or PR. A reviewed disposition additionally requires the
independent constructive review described below.

Do **not** regenerate `results.json` / `score-history.json` — the maintainer
re-exports them on merge (`pnpm benchmark:json`).

Before opening the PR:

```
pnpm benchmark <your-id>    # your entry passes: valid accepted, ALL invalid rejected
pnpm typecheck
```

## Your contract source can stay private

The harness grades **behavior, not source**. What must be public is the
bytecode (the vectors) and an honest description of the construction; how you
produced it — your CashScript source, your own compiler fork, a bytecode
optimizer — can stay closed. Several listed entries were built with private
tooling.

The harness supplies fixture and deployment evidence; it is not, by itself, a
universal correctness proof. A reviewed entry must also state the mathematical
claim and assumptions in [docs/submission-claims.md](docs/submission-claims.md):

- the valid run must be ACCEPTED, and every invalid run REJECTED, on the
  loosened BCH 2026 VM;
- for `proofBinding: 'runtime'` entries whose setup permits minting, supply
  `extraValidProofs` — distinct proofs under the same VK and ordered programs.
  The harness executes the supplied runs; the submitter and reviewer must
  check program identity, step counts and proof distinctness. It does not
  enforce those comparisons. If only one proof is available, disclose that
  coverage limit rather than claiming empirical generality;
- adversarial `invalidInputs` (off-curve / out-of-subgroup points) must be
  rejected if you claim input validation. Rejection alone does not identify
  the rejecting predicate or prove that a domain check exists;
- for chunked entries whose op-cost depends on the proof, supply a
  valid `worstCaseProof` (dense, near-r public inputs). It is a measured case,
  not a universal worst-case theorem; that supplied run must accept.

What you should publish even when the build is closed:

- **the sha256 of each locking bytecode** in the module header, so the listed
  artifact is pinned;
- **a precise construction description** — which equation the script enforces,
  what is witnessed vs computed on-chain, and the soundness argument (why a
  forged proof cannot satisfy it), including the declared domain and auxiliary
  existence assumptions;
- **a claims/assumptions sheet** covering binding ownership, Fiat-Shamir query
  order/error bounds, and script-enforced versus deployment premises;
- optionally, **a public reproduction path**. Reviewers still need access to
  reconstruct and rebuild the artifact. Byte-exact reproducibility from source
  (even source that lives in your own repo) is a stronger claim than a bare
  hash and is called out on the entry — see `bch-groth16-singleton-genpow.ts`
  for the pattern (baseline compile → deterministic transform chain → asserted
  final sha256).

## What your entry must verify

For a BCH-native full Groth16 submission, use the published benchmark VK for
the selected curve, BN254 or BLS12-381, with two public inputs and
`vk_x = IC0 + in0·IC1 + in1·IC2`. Name that exact VK in the claim sheet;
reference baselines may use different keys or statements. Label any restricted input
or proof domain and give its soundness argument. Cofactor-equivalent handling
is acceptable when stated; strict-subgroup enforcement is not a prerequisite.
The trusted setup, canonical proof, and the multiproof/worst-case
minting tools live in the companion repo
[`groth16_cashscript`](https://github.com/mr-zwets/groth16_cashscript) (and
`pnpm gen:multiproof[-bls]` here) — mint your extra proofs from there rather
than inventing a new statement, or your entry can't be compared.

## Metadata to get right

See `Implementation` in `src/harness/types.ts` for the full contract
(`docs/benchmark.md` walks through it). The fields that decide how you're
ranked:

- **id / naming** — follow `bch-groth16[-bls12381]-<structure>[-<variant>]`.
- **`structure` + step contexts** — bare single-tx steps, `covenant`
  (NFT-commitment thread), `intraTx` (linked inputs of one tx), or `grouped`
  (the standard-relayable hybrid). The harness builds the matching synthetic
  transactions; nothing to implement on your side beyond the step contexts.
- **`proofBinding`** — `'runtime'` (proof in the witness; one deployment
  claims to verify any proof in its declared VK/domain) vs `'baked'` (proof
  compiled into the chunks). Claiming `runtime` without surviving the supplied
  multiproof sweep will be exposed by that coverage check.
- **`vm`** — `'bch-2026'` (default) or `'bch-spec'` for entries targeting the
  proposed 100 kB-script VM; spec entries rank in their own category.
- **`tokenSafetyEnforced`** — for covenant entries, only set true if the
  covenant genuinely pins category/capability continuity (and you provide the
  supporting rejection vectors and owner argument).

The score is total on-chain bytes (locking + unlocking + serialized-tx
overhead); all-zero padding pushes count toward it and are reported as dead
weight. Don't bother gaming the accounting — it's structural, not declared.

## Vector files

There is no single schema — the shape follows the structure. Copy the closest
existing template:

| structure | template |
|-----------|----------|
| singleton | `groth16-singleton-genpow-vectors.json` (+ `-multiproof-vectors.json`) |
| covenant chain | `groth16-chunked-covenant-residue-vectors.json` (per-step `covenant` context) |
| intra-tx | `groth16-intratx-residue-vectors.json` |
| grouped | `groth16-grouped-residue-vectors.json` |

Every file commits, at minimum, the valid run and the tampered
(`invalidUnlocking`) variants. Keep vectors deterministic — they are the
reviewable artifact.

## Review

What the maintainer checks on a PR, roughly in order: the harness passes for
your id (fixture and deployment evidence), the metadata claims match what the
vectors demonstrate, and the claims sheet's equation and composition argument
holds up. A reviewed disposition requires a written argument plus independent
constructive review: rebuild the exact bytes, pin their hashes, and check the
owner of every acceptance-dependent value, including multi-input bindings.
The same pipeline or agent's agreement is not independent assurance; ordinary
field and hash assumptions may still be shared. Any verifier-program byte,
VK, domain, or deployment-premise change requires a new review. Update pins
when the bytes change.
The entry should not require harness changes (if it does — a genuinely new
structure or grading dimension — expect that part to get real review, like any
code change).

The maintainers may also add red-team checks against your exact bytes
(`src/bch/redteam/<id>.json`); every supplied run must be rejected. A verifier must
bind `vk_x` to the public inputs it claims: a real proof with forged public inputs
has to fail. See [docs/public-input-binding.md](docs/public-input-binding.md).

Declare where your claimed public inputs live with `publicInputs` on your
`Implementation` (input index, push index within that input's unlocking, and a
name; list every copy under the same name). The harness re-encodes them with
other values and the transaction must reject. Ship every valid proof so that it
passes the standard VM; standardness is graded on all of them. If one input reads
another input's unlocking at a fixed offset, make sure every push before that
offset has a pinned length, or carry the data in a push the producing input pins;
the harness lengthens zero pads and flags siblings that break.
