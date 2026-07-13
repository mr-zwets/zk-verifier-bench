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

That works because correctness is enforced empirically, not by review of your
source:

- the valid run must be ACCEPTED, and every invalid run REJECTED, on the
  loosened BCH 2026 VM;
- if you claim `proofBinding: 'runtime'`, supply `extraValidProofs` — distinct
  proofs under the same VK — and the harness verifies your one fixed locking
  accepts all of them (a baked program can't fake this);
- adversarial `invalidInputs` (off-curve / out-of-subgroup points) must be
  rejected if you claim input validation;
- for chunked entries whose op-cost depends on the proof, supply a
  `worstCaseProof` (dense, near-r public inputs) so your op-cost claim holds at
  the worst case.

What you should publish even when the build is closed:

- **the sha256 of each locking bytecode** in the module header, so the listed
  artifact is pinned;
- **a precise construction description** — which equation the script enforces,
  what is witnessed vs computed on-chain, and the soundness argument (why a
  forged proof cannot satisfy it);
- optionally, **a reproduction path**. Byte-exact reproducibility from source
  (even source that lives in your own repo) is a stronger claim than a bare
  hash and is called out on the entry — see `bch-groth16-singleton-genpow.ts`
  for the pattern (baseline compile → deterministic transform chain → asserted
  final sha256).

## What your entry must verify

All entries verify the same fixed Groth16 statement as the existing BCH-native
entries (two public inputs, `vk_x = IC0 + in0·IC1 + in1·IC2`), on BN254 or
BLS12-381. The trusted setup, canonical proof, and the multiproof/worst-case
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
  verifies any proof) vs `'baked'` (proof compiled into the chunks). Claiming
  `runtime` without surviving the multiproof sweep will be caught.
- **`vm`** — `'bch-2026'` (default) or `'bch-spec'` for entries targeting the
  proposed 100 kB-script VM; spec entries rank in their own category.
- **`tokenSafetyEnforced`** — for covenant entries, only set true if the
  covenant genuinely pins category/capability continuity (and you provide the
  rejection vectors to prove it).

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
your id (correctness gates), the metadata claims match what the vectors
demonstrate, the header comment's soundness argument holds up, and the entry
doesn't require harness changes (if it does — a genuinely new structure or
grading dimension — expect that part to get real review, like any code change).
