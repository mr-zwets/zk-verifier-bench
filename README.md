# zk-verifier-bench

A benchmark harness for **Groth16 proof verifiers on the Bitcoin Cash VM**.
Executable entries run on their applicable BCH virtual machines (libauth);
profile-only entries receive size measurements without execution. For
executable entries, the harness

1. **checks fixtures** — the valid and supplied worst-case proof runs
   are ACCEPTED, while supplied tampered and adversarial-input runs are
   REJECTED;
2. **measures cost** — total on-chain bytes (the score), op-cost, serialized-tx
   overhead, and dead-weight padding; and
3. **checks deployability** — consensus limits, mempool standardness, and
   packaging on the real BCH VMs.

Results are exported (`pnpm benchmark:json`) as `results.json` +
`score-history.json`, which feed a public leaderboard website. The verifier
contracts themselves — the CashScript source, the chunk generators, and the
design writeups — live in the open-source companion repo
[`groth16_cashscript`](https://github.com/mr-zwets/groth16_cashscript).

## Why

BCH keeps Bitcoin's per-input consensus limits: a 10,000-byte script-size cap
and an op-cost budget of `(41 + unlockingLength) × 800` (≈8M for a max-size
input). A full Groth16 pairing check — the Fp→Fp2→Fp6→Fp12 field tower, the
Miller loop, the final exponentiation — does not fit in one input, so a
deployable verifier must be split across many inputs and/or transactions.
There are several ways to do that split, and several ways to shrink each piece.
This harness grades all of them on a level field: one primary score (total
on-chain bytes — bytes are fees), evidence gates, and secondary columns for
op-cost and deployability. A mathematical soundness disposition for the exact
artifact requires the written claim and independent constructive review in
[`docs/submission-claims.md`](docs/submission-claims.md); fixtures support that
disposition but do not establish it alone.

Groth16 itself is not the end goal — it requires a circuit-specific trusted
setup and, being pairing-based, is not post-quantum safe. But it is the
industry-standard succinct verifier (smallest proofs, cheapest verification),
which makes it the right first target: building it tests the practical
viability of ZKPs on BCH and surfaces the BCH-specific problems any proof
system will hit — chunking, multi-tx state hand-off, op-cost padding — along
with the tooling to solve them.

Two real BSV mainnet verifiers (`nchain`, BLS12-381; `scrypt-bn256`, BN254) are
included as reference baselines — they established the starting point and show
that a monolithic single-tx verifier cannot run within BCH's limits — but the
benchmark's focus is the BCH-native entries competing below them.

## Quick start

```
pnpm install
pnpm fetch            # download the reference verifier artifacts from WhatsOnChain
pnpm benchmark        # run the leaderboards
pnpm benchmark:json   # export results.json + score-history.json (incremental, see below)
```

`pnpm benchmark` takes positional substring filters on the entry id
(`pnpm benchmark genpow`, `pnpm benchmark singleton chunked`); `--demos`
includes the demo entries.

### Incremental export

`pnpm benchmark:json` is incremental: it re-runs only the entries whose inputs
changed and carries every other row of the existing `results.json` forward
unchanged. Each row stores an `inputHash` (`src/harness/input-hash.ts`), a
SHA-256 over

- the implementation module, with comments, formatting and the `name`,
  `source` and `reviewStatus` values stripped (it is hashed as printed AST);
- any local module it imports (outside `src/harness`); an imported non-code
  module (e.g. a JSON import) is hashed as raw bytes;
- every `src/...` / `data/...` file named by a string literal in those
  modules (the vectors JSON, the reference tx hex), byte for byte. A `data/`
  file listed in its folder's committed `SHA256SUMS` is hashed through that
  pinned digest (and must match it when present);
- its red-team file `src/bch/redteam/<id>.json` (its absence too);
- the **harness fingerprint**, computed automatically: the printed AST of every
  code file under `src/harness` (recursively) except `review-status.ts`,
  `export-json.ts`, `input-hash.ts` and `audit-deps.ts`, plus every local module
  those files import, transitively and wherever it lives, plus every repo file
  they name by literal path (in `benchmark.ts` the implementation imports and
  the `REGISTRY` list are left out, so registering an entry re-runs only that
  entry). The row builder `entryOf` lives in `entry.ts` and is covered;
- the toolchain: the installed versions of every dependency and build tool in
  `package.json` (libauth, `@noble/curves`, typescript, tsx; not `@types/*`),
  `sha256(pnpm-lock.yaml)` (every transitive version, e.g. the esbuild that tsx
  transpiles with), `sha256(tsconfig.json)`, the Node.js version, and
  `HARNESS_VERSION`.

So any code edit to the measurement harness (VM wrapper, benchmark, gates,
red-team, adversarial, tamper, row shape, or a helper they import), any lockfile
change and any Node.js upgrade re-runs every entry, with no version bump to
remember. A typescript upgrade also re-runs everything, because the normalized
code is the typescript printer's output. `HARNESS_VERSION` remains as a manual
knob for a change none of these can see. `export-json.ts` is excluded because it
only plans the export and recomputes the frontier and history from the rows on
every run.

The implementation modules and their vectors are loaded before the hashes are
computed, so the export refuses to write (exit 1, files untouched) if any file
that went into a hash was modified after the export process started.

Metadata is never an input: renaming an entry, editing its source text or
comments, or changing `review-status.ts` re-attaches the new metadata to the
carried row without a re-run. The frontier (leader / current) and the score
history are recomputed from the merged rows, and rows are always emitted in
registry order. A no-op run leaves `results.json` untouched, including
`generatedAt`.

| variable | effect |
|----------|--------|
| (none) | re-run new entries, rows without `inputHash`, and rows whose hash changed (the slow SKIP_IMPLS entries included) |
| `FULL=1` | re-run every entry, except SKIP_IMPLS entries whose hash still matches; not combinable with `ONLY_IMPLS` |
| `ONLY_IMPLS=a,b` | re-run exactly these ids (exact match; bypasses SKIP_IMPLS; an unregistered or `FEED_OMIT` id is an error) and carry every other row. A carried row whose inputs changed is **STALE** (see below) |
| `SKIP_IMPLS=genpow` (default) | the slow entries (BLS12-381 genpow takes about 16 min). `FULL=1` does not force them, but like every other entry they are re-run whenever they are new, their row has no `inputHash` (a legacy row, inputs unknown) or their inputs changed (including any harness or toolchain change). They are never dropped and never silently carried out of date. `SKIP_IMPLS='' FULL=1` forces them too |
| `DEFER_SKIPPED=1` | do not wait for those SKIP_IMPLS re-runs: carry the old row instead, marked **STALE** (see below). A SKIP_IMPLS entry with no previous row fails the export. Not combinable with `ONLY_IMPLS` |
| `ALLOW_DROP=1` | one-off escape hatch for an `ONLY_IMPLS` run where an entry has no previous row: write the artifact without it; history and frontier are frozen so no false point enters the append-only `score-history.json`, frozen-frontier ids without a row are named, and the export **exits 2**. Never publish from it, and never use it as a standing omission (that is `FEED_OMIT`) |
| `ALLOW_MISSING_DATA=1` | under `FULL=1`, carry an unchanged row whose `data/` file is missing instead of failing |
| `SKIP_DEPS_AUDIT=1` | skip the dependency audit that `pnpm benchmark:json` runs first |

A **STALE** row is carried although its inputs changed (`ONLY_IMPLS`,
`DEFER_SKIPPED=1`). It is marked in the artifact itself: the row gets a
`stale` field with the reason and keeps its old `inputHash`, so the next default
run re-runs it (and a current row never has the field). The artifact is
written, but the history and frontier are frozen at their previous values and
the export exits 2. Never publish such an artifact.

`SKIP_IMPLS='' FULL=1 pnpm benchmark:json` is the old complete export. A publish
uses the default (or `FULL=1`) mode, never `ONLY_IMPLS`, `DEFER_SKIPPED` or
`ALLOW_DROP`; its exit status is 0.
(`STAMP_HASHES`, the one-time bootstrap that adopted hashes without re-running,
was removed; setting it is an error.)

**Deliberate omissions (`FEED_OMIT` in `export-json.ts`).** A registered entry
can be kept out of the feed on purpose: it gets no row and no history point, is
never run by the export, is not counted as missing, and is logged as `omit` on
every export (`ONLY_IMPLS` refuses it). Each id carries its reason:

| id | reason |
|----|--------|
| `bch-vkx-scalarmult` | site-exclude: a single scalarMult sub-step on the old EC codegen, still benchmarked by `pnpm benchmark` |

**Experiments.** `pnpm benchmark:json <outfile>` writes its history next to the
outfile: `results.json` uses `score-history.json` in the same directory; any
other name, e.g. `scratch.json`, uses `scratch.score-history.json`, seeded
read-only from `./score-history.json`, so an experiment never appends to the real
history.

Rows are never dropped silently, and the score history only ever gets points
computed from a complete, current row set. A row whose id is no longer
registered leaves the feed (logged). An entry whose `data/` file is missing (the
gitignored nChain / sCrypt mainnet tx hex; `pnpm fetch` restores it and checks
the pinned digest) is carried forward only while its hash, computed through the
pinned digests, still matches its row; if anything else about it changed, or
with no previous row, the export fails and asks for `pnpm fetch`. A load failure
during a re-run aborts the export and leaves `results.json` untouched.

A merge conflict in `results.json` (two branches both re-exported) is resolved
by taking either side and running the default export: rows whose stored
`inputHash` does not match the merged sources (or that have none) are re-run,
so no side's stale row survives.

`pnpm benchmark:json` first runs `pnpm benchmark:deps`, the dependency audit: it
traces every file the implementations actually read or list (at import and in
`load()`: `readFileSync`, `openSync`, `readFile`, `createReadStream`,
`fs.promises.readFile` / `open`, and directory listings) and fails if any read
is missing from that entry's input hash, for example a file opened through a
computed path. Every read made from an implementation frame is checked, wherever
the file lives (an absolute or `../groth16_cashscript/...` path) and whatever its
type (a `.ts` / `.mjs` read as text too); only a package's own reads inside
`node_modules` are ignored. Reads by the ESM loader (JSON imports) are not
traced; those are hashed statically.

## Leaderboards

Entries are grouped by **category** and **curve**; the score is **total
on-chain bytes** (locking + unlocking + serialized-tx overhead, with dead-weight
zero-padding reported separately). Lower is better. Current numbers live in
`results.json` — the README deliberately doesn't hard-code them.

Fifteen original implementations are held or withdrawn from their claimed
full-verifier or connected-component qualification and the default registry: the BN42, authenticated42, grouped42, grouped26, BLS24, PairFold-5,
PairFold-5 pevalfuse, PairFold-5 densless, three densless-MSM variants,
PairFold-7, the BLS chunked-covenant vk_x component, the BLS residue-large
verifier, and the partial pairing intra-tx component. See [benchmark issue
#49](https://github.com/mr-zwets/zk-verifier-bench/issues/49) and [source issue
#32](https://github.com/mr-zwets/groth16_cashscript/issues/32). The current feed
excludes those fifteen observations. The BLS12-381 genpow descriptor now
identifies the corrected artifact from [PR
#48](https://github.com/mr-zwets/zk-verifier-bench/pull/48) (source #31), and the
feed carries its measurement (5,965 B, reviewed 2026-10-27 with a cofactor-equivalent G2 domain). The corrected BN254
genpow observation from merged [PR
#47](https://github.com/mr-zwets/zk-verifier-bench/pull/47) is retained at
4,613 B. The three separately corrected standalone descriptors retain distinct
IDs and their stated mathematical scope, but remain outside the default
registry until qualified. No replacement score is inferred. All original numerical measurements remain in
the [immutable historical export](https://github.com/mr-zwets/zk-verifier-bench/blob/86820022643b8832c4818967666c8cdaaaaa3b6e/results.json),
and score-history points are retained as historical measurements, not current
qualification. Separately corrected standalone profiles retain their stated
scope and resource holds and are not registered by their presence on disk.
As of the 2026-10-27 export the feed names `bch-groth16-singleton-genpow`
as the 4,613 B leader (not BCH-compatible, reviewed 2026-10-27) and
`bch-groth16-bn254-sound-native` as the 27,624 B BCH-compatible current anchor
(independently reviewed).

Each entry carries a `reviewStatus` (see `src/harness/review-status.ts`):
`reviewed`, `unreviewed` (the default), `withdrawn`, `baseline` (the nChain and
sCrypt third-party references), `demo` (the harness self-test), `component`
(the partial pairing / vk_x checkpoints) or `archived` (the superseded legacy
large chains: BN254 chunked and chunked-covenant, BLS12-381 intratx, grouped,
chunked and chunked-covenant). Archived rows stay in `entries[]`, but like
withdrawn ones they never count for the frontier or new history points.
Withdrawn implementations leave the registry, so their rows leave the feed; the
website keeps a frozen copy of the last rows of the removed ids (the fifteen of
the reset, plus `bch-groth16-bls12381-grouped-residue`, withdrawn by the
2026-10-27 review for an unpinned token-category hand-off). The `withdrawn`
status remains for a finding that applies before its descriptor is removed.

| category | meaning |
|----------|---------|
| `full` | a complete Groth16 verifier |
| `partial` | a sub-verifier milestone (`vkx-*`: the public-input MSM; `pairing-*`: the pairing check) |
| `spec` | a full verifier targeting the **proposed** bch-spec VM (see below), kept out of the current-BCH ranking |
| `demo` | toy entries validating harness mechanics |

Both curves are covered throughout: **BN254** (32-byte field elements) and
**BLS12-381** (48-byte), so each reference verifier has same-curve BCH
counterparts.

## Why these measures

Bytes rank because they are what a user pays in fees, but two secondary
measures carry the project's findings:

- **Op-cost.** The per-input budget scales with script length, so entries buy
  compute with zero-padding, and the smallest-byte builds are only small
  because they ignore compute. Reporting op-cost keeps the byte score honest
  and shows what a budget-formula change would save.
- **The consensus / standard / bch-spec categories.** Each rule set has a
  different optimal design, so each is benchmarked in its own right: intra-tx
  bundles are best when the complete graph fits one standard transaction, the
  grouped form preserves standard relay for graphs that exceed that limit, and
  the proposed bch-spec limits admit a much flatter split. Comparing the
  winners shows what each rule change is worth.

## Entry families

~40 entries are registered (`REGISTRY` in `src/harness/benchmark.ts`); they
factor into families along two axes — *deployment structure* and *optimization
variant*:

| family | ids | structure |
|--------|-----|-----------|
| references | `nchain`, `scrypt-bn256` | real BSV mainnet verifiers, single-tx; fail BCH limits |
| singletons | `bch-groth16[-bls12381]-singleton[-opcode-optimized\|-genpow\|-minop]` | full verifier in ONE script — runtime-general correctness oracles; exceed one input's op-cost budget on current BCH |
| chunked / covenant | `…-chunked`, `…-chunked-covenant[-residue]` | computation split into chunks; state threaded through an NFT commitment across a chain of transactions |
| intra-tx | `…-intratx[-residue]` | all chunks are inputs of ONE transaction, binding each other via `OP_INPUTBYTECODE`; the BN254 quotient-torus fixture is below standard policy's 100 kB transaction limit |
| grouped | `…-grouped` | the hybrid: intra-tx binding inside a handful of standard (<100 kB) transactions, with NFT hand-off between them; standard-relayable for graphs that exceed one standard transaction |
| spec | `…-intratx-residue-large` | 100,000-byte-script builds for the proposed bch-spec VM |
| partials | `bch-vkx-*`, `bch-pairing-*` | vk_x MSM and pairing-check milestones in the same structures |
| demo | `bch-multistep-demo` | hash-chained multi-tx demo |

Optimization variants, roughly in the order they were developed:
**opcode-optimized** (size-golfed codegen), **genpow** (smallest
source-reproducible singleton), **minop** (op-cost-minimized, trading bytes for
budget), **residue** (replaces the final-exponentiation hard part with a
witnessed `c^λ` residue check — the single biggest score win), and **GLV**
(endomorphism-split vk_x MSM inside the residue builds).

## How it works

The unit of execution is a `Step` (one locking + unlocking pair = one input's
script evaluation). A single-tx verifier is one step; covenant, intra-tx, and
grouped entries are ordered step lists whose cross-step continuity the harness
reproduces faithfully (synthetic token-carrying transactions for covenants, a
real shared transaction for intra-tx/grouped inputs). See `docs/benchmark.md`
for the full contract.

Five VMs (`src/harness/vm.ts`):

- **loosened** BCH 2026 VM — every resource ceiling lifted; executes fixtures
  and measures op-cost even for oversized entries;
- **real** BCH 2026 VM — consensus limits; decides `BCH compatible`;
- **standard** BCH 2026 VM — mempool-relay policy; decides standardness;
- **real + standard bch-spec VMs** — the proposed upgrade (100,000-byte
  scripts, op-cost budget `(10,000 + len) × 800`); grades `vm: 'bch-spec'`
  entries only.
- **real + standard TXv5 VMs** — TXv5 as written: BCH 2026 rules with
  100,000-byte scripts and stack elements, but the density base stays 41, so
  the budget is `(41 + len) × 800`. bch-spec entries get a second `txv5` grade
  (valid as shipped, or the minimal zero padding and padded score, or not
  paddable as shipped; or measured on the entry's TXv5-grading pad-slot
  variant, `txv5.variant`) for every honest run; the summary is standard only if
  every honest run is; see `docs/benchmark.md` and bench issue #35.

### Grading dimensions

Beyond accept/reject on the committed proof, entries are graded on:

- **proof-generality** — for `proofBinding: 'runtime'` entries the harness runs
  several distinct valid proofs minted under the same verifying key against the
  intended ordered program set (N/N must verify). The harness executes the
  supplied runs; program identity and proof distinctness require review.
  See `docs/proof-generality.md`.
- **worst-case proof** — a dense, near-r-input proof run through the same
  locking. It must be a valid proof and be accepted; it is a measured dense
  case, not a universal worst-case bound.
- **input validation** — supplied off-curve or out-of-subgroup witnesses test
  claimed EIP-197-style validation. The harness counts whole-run rejection;
  the existence and ownership of a domain check require separate review. A
  cofactor-equivalent domain does not imply strict subgroup rejection.
- **standardness** — does every step also relay (`fitsBchStandardness`), or is
  the entry consensus-valid but non-standard (e.g. bare intra-tx bundles)?
- **secure packaging** — P2SH20-packaged entries are flagged (collision-attack
  surface).
- **honest byte accounting** — all-zero padding pushes (bought op-cost budget)
  and per-structure serialized-tx overhead are folded into the score so
  single-tx, covenant-chain, and grouped entries compare fairly.

## Not every Groth16 is alike

Cross-entry totals mix factors that have nothing to do with implementation
quality:

- **Curve.** BLS12-381 field elements are 1.5× BN254's; bigger curve, bigger
  scripts. Compare within a curve line first.
- **Statement.** Native Groth16 entries use the published benchmark VK and two
  public inputs for their curve. Reference baselines may use other keys and
  input counts. These synthetic equation fixtures do not establish circuit
  knowledge; compare the exact statement and domain before comparing totals.
- **Deployment model — proof at runtime vs baked per-proof.** A
  *runtime-general* entry receives its proof at spend time and is intended to
  verify any proof in its declared VK/input domain. An *instance-specific*
  entry specializes its scripts to a proof, so a different proof requires
  regenerating them. This distinction depends on the entry's `proofBinding`,
  not whether it is singleton, chunked, intra-tx or grouped. Both can verify
  on-chain under their declared equations and assumptions; the harness reports
  their supplied multi-proof coverage separately.

So a cross-entry "N× larger" on totals is indicative, not a clean benchmark;
per-milestone comparisons are normalized instead (same scalar, fixed-iteration
loops — see `docs/checkpoints.md`).

## Scripts

| script | what |
|--------|------|
| `pnpm benchmark [id-filter ...]` | run entries and print the leaderboards |
| `pnpm benchmark:json` | export `results.json` + `score-history.json` (incremental; `FULL=1`, `ONLY_IMPLS=a,b`, see above) |
| `pnpm benchmark:deps` | check that every file an entry reads is covered by its `inputHash` |
| `pnpm gen:multiproof` / `gen:multiproof-bls` | mint extra distinct valid proofs under the fixed VK (proof-generality) |
| `pnpm checkpoints` | compute/validate the BN254 golden checkpoints (vk_x + Miller boundary) |
| `pnpm checkpoints:pairing-gen` / `checkpoints:pairing` / `checkpoints:pairing-basis` | pairing-milestone vectors, grading, Fp12-basis probe |
| `pnpm bch:fp-mul` | measure a single BN254 field multiply's op-cost |
| `pnpm bch:vkx` / `bch:vkx-scalarmult` / `bch:vkx-scalarmult-sweep` | standalone vk_x measurements |
| `pnpm fetch[:nchain\|:scrypt-bn256]` | download reference artifacts from WhatsOnChain |
| `pnpm nchain:extract` / `nchain:run` / `nchain:verify` | reference verifier tooling |
| `pnpm scrypt-bn256:extract` / `:run` / `:verify` / `:find-vkx` | reference verifier tooling |
| `pnpm typecheck` | `tsc --noEmit` |

## Layout

```
src/harness/          types, VMs, tamper, benchmark runner, JSON exporter
src/implementations/  one module per entry (registered in benchmark.ts)
src/bch/              BCH-native vectors (committed JSON) + primitive measurements
src/checkpoints/      off-chain BN254 golden checkpoints (vk_x, Miller boundary, pairing)
src/nchain/           nChain reference extract/run/verify
src/scrypt-bn256/     sCrypt reference extract/run/verify
data/<impl>/          SOURCE.md provenance (raw hex is gitignored, re-fetchable)
docs/                 benchmark.md, checkpoints.md, proof-generality.md,
                      public-input-binding.md, submission-claims.md,
                      pairing-checker.md, scrypt.md
results.json          committed leaderboard export (consumed by the website)
score-history.json    committed per-run score history
```

The current challenge covers the declared fixed-VK pairing equation, using the
published benchmark setup for each native curve. It
does not certify circuit knowledge soundness, application-level zero knowledge
or state binding, arbitrary verifying keys, independent setup, or live relay
guarantees. Application ZK and VM-cost/TXv5 work are welcome as companion
research tracks; `bch-spec`'s larger limits and its separate TXv5-as-written
grade are distinct models.

## Contributing

External verifier submissions are welcome — several leaderboard entries
arrived as PRs. A submission is vectors JSON + an implementation module + a
one-line registry edit; your contract source and build tooling can stay
private, provided the exact bytecode is pinned and a byte-identical rebuild
method is reviewed. The harness grades declared behavior and deployment
evidence; see the claim sheet and
[CONTRIBUTING.md](CONTRIBUTING.md).

## Related repos

- [`groth16_cashscript`](https://github.com/mr-zwets/groth16_cashscript) —
  the verifier contracts (CashScript source, `singleton/` and `chunked/`
  generators) and the design docs (`verifiers.md`, compiler-fork and
  stack-rescheduler writeups). This repo consumes its generated vectors.
- The leaderboard website that renders `results.json` (closed source).

## Notes

- libauth `@bitauth/libauth@3.1.0-next.8` provides the BCH 2023/2025/2026 VMs
  and the bch-spec VM; `@noble/curves` provides the off-chain BN254/BLS12-381
  references.
- A step can be tagged `checkpoint: "<label>"`; the benchmark then reports the
  cumulative op-cost + bytes to reach it (`docs/checkpoints.md`).
- Large raw-hex and disassembly artifacts are gitignored; each `data/<impl>/`
  folder keeps a `SOURCE.md` with provenance and the commands to regenerate.
