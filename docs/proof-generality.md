# Proof generality: runtime-general vs instance-specific

A Groth16 verifier on-chain can bind the proof to the program in one of two ways,
and the difference matters more than raw byte counts:

- **runtime-general** — the proof `(A, B, C)` and public inputs arrive *push-only*
  in the unlocking (witness) script at spend time. One deployed locking script
  is intended to verify any valid proof in its declared verifying-key (VK) and
  input domain. This is how the
  references (`nchain`, `scrypt-bn256`) and our **singleton** verifiers work.
- **instance-specific** — the proof is **baked into the locking program**. Some
  chunked constructions commit each step's carried state (`hash256` of the
  intermediate Miller / final-exp values) into the chunk scripts, so the program is
  specialized to one proof; a different proof needs the chunks regenerated.

Deployment structure alone does not determine this property: chunked,
intra-transaction and grouped constructions may also be runtime-general.
Read the entry's `proofBinding` and its exact construction argument.

Both can verify on-chain under their declared equations and assumptions. A
soundness argument, rather than the fixture sweep alone, establishes what an
invalid proof cannot satisfy. The deployment models differ, so their byte
totals are not directly comparable — see
"Not every Groth16 is alike" in the [README](../README.md).

Fixture acceptance supports a finite claim; it does not prove correctness for every
proof or establish that proof data is actually consumed by the verifier. Those are
separate mathematical review obligations.

## How the harness checks it

`Implementation.proofBinding` declares runtime or baked binding. Before executing
or measuring a scenario, the harness requires:

- a nonempty primary run;
- every extra and supplied worst-case run to have the same step count, ordered
  locking bytecode, context kind, transaction topology, and successor programs;
- intra-transaction/grouped sibling scripts to match the actual run being evaluated.

Proof-dependent token commitments and unlocking witnesses may change. These checks
establish program/context consistency, not enforcement of cross-transaction state
continuity by the scripts themselves. A malformed honest-run contract throws before
VM execution; the exporter cannot silently treat it as a successful measurement.
The CLI reports the error and exits with a nonzero status.

Distinctness additionally requires reviewed `Implementation.proofInputs` locators:

```ts
proofInputs: [
  { input: 0, push: 2 }, // VM-number value, normalized across push encodings
  { input: 0, push: 3, encoding: 'bytes', offset: 0, length: 48 },
]
```

Indices are zero-based unlocking instruction positions (as with `publicInputs`).
Declare genuine proof components only: exclude public scalars, pads, auxiliary
roots, carried state and redeem scripts. A differing component establishes distinct
encoded proofs only when its field ownership and encoding are reviewed. Numeric
pushes compare decoded VM-number values. Packed byte fields require explicit,
bounded, canonical slices. These locators do not validate curve points, subgroups,
canonical field encodings, or consumption by the verifier.

Missing locators mean identity is unknown: accepted extra runs still contribute to
`proofsTested`/`proofsPassed`, but cannot earn `runtimeGeneral`. Duplicate declared
fingerprints and malformed locators are explicit contract errors. The worst-case
run may reuse an honest proof, but must match the same program and locator layout.

`runtimeGeneral` requires runtime binding, declared-distinct extra proofs, and
acceptance of every supplied primary/extra run. It is finite fixture evidence,
never a universal theorem. A rejected extra is a completeness failure in both the
CLI and JSON correctness verdict. Profile-only entries execute zero runs.

The four affine BN254/BLS12-381 baseline and opcode singleton descriptors declare
proof-coordinate pushes 2–9. Other layouts remain identity-unconfirmed until their
owners supply reviewed locators; a different full witness alone is insufficient.

Multi-input intra-transaction seam checks require an accepted, qualified distinct
extra. Missing evidence is reported as untested (`bound: null`, correctness
`valid-only`), rather than credited as a passing seam check. Bundles with fewer than two named checkpoint boundaries have no seam to sample; the check is not applicable to them, as for covenant/grouped chains. A finite set of rejected seams does not prove universal
stage binding. Covenant/grouped state continuity remains outside this seam check.

The independently callable TXv5 grader also enforces honest-run program/context
consistency, separately within shipped and pad-slot variant programs. It does not
infer proof distinctness or mathematical soundness from those resource measurements.

## Input-domain observations

`inputValidation.tested`/`rejected` report only whole-run outcomes of supplied
`invalidInputs`. They do not identify an isolated rejecting predicate: an equation,
resource limit, or unrelated stage may reject. The legacy `enforced` field remains
false, with `evidence: 'run-rejection-only'` (or `not-executed` for profile-only).
This means **not demonstrated by this metric**, not that domain checks are absent.
The actual accepted domain and its enforcement require independent review of the
exact verifier bytes and argument.

## Checking the contracts

Run `pnpm test:scenario-contract` and `pnpm typecheck`. The focused tests reuse
archived fixture byte arrays and alter only run/locator/context metadata. They do
not generate proofs, run negative VM cases, or invoke benchmark gates. The full
benchmark retains its existing VM/gate behavior; these tests are a separate check.

## How the extra proofs are minted

The generators are
`groth16_contract/singleton/bn254/gen_multiproof.mjs` (BN254) and
`groth16_contract/singleton/bls12-381/gen_multiproof.mjs` (BLS12-381).

The key idea: **hold the VK fixed so the locking is unchanged, and only vary the
proof.** Because the singleton locking bakes the VK (`alpha, beta, gamma, delta,
IC`) and nothing else, every minted proof reuses the *byte-for-byte same*
`lockingOK` — only the unlocking witness (`A, B, C, in0, in1`) differs. That is
exactly the runtime-general property under test.

We do not need a real circuit or prover, because we know the trusted-setup scalars
(the same ones `src/checkpoints/gen-pairing-vectors.ts` / the BLS `bls_instance.mjs`
used to construct the committed instance). These are synthetic equation-valid
fixtures, not application-circuit proofs. They establish no circuit knowledge,
setup integrity, or application-level zero-knowledge claim. The Groth16 pre-final-exp product is

```
e(-A,B)·e(alpha,beta)·e(vk_x,gamma)·e(C,delta)
  = e(g1,g2) ^ ( -a·b + alpha·beta + vkx·gamma + c·delta )      (scalars mod r)
```

so `finalExponentiate(product) == 1` iff that exponent ≡ 0 (mod r). To mint a fresh
valid proof under the fixed VK we pick new public inputs and a new random `a, b`,
then **solve for the one remaining scalar** in the exponent so the sum is zero:

- **BN254** (`gen_multiproof.mjs`): pick `in0, in1, a, b`; with
  `vkx = ic0 + in0·ic1 + in1·ic2`, solve
  `c = (a·b − alpha·beta − vkx·gamma) · delta⁻¹ (mod r)`.
  Materialize `A = [a]G1, B = [b]G2, C = [c]G1`.
- **BLS12-381** (`gen_multiproof.mjs`): the committed instance fixes `B = 1·G2`, so
  we pick `in0, in1, c` and solve `A` instead:
  `A = alpha·beta + vkx·gamma + c·delta (mod r)`, with `B = G2`, `C = [c]G1`.

Each minted proof is checked **two ways** before it is written:

1. in `@noble/curves` (the oracle) — `pairingBatch(..., true) == Fp12.ONE`, and the
   tampered variant (`in1 + 1`) must *not* verify;
2. on the **loosened BCH 2026 VM**, executed against the actual committed
   `lockingOK` — the witness must be ACCEPTED and the tampered witness REJECTED.

The generators also re-derive the VK from the scalars and assert it equals the
committed VK, so a mismatch (which would mean the locking is for a different VK)
fails loudly rather than silently producing a proof the locking can't verify.

Output (read by the singleton implementations):
`src/bch/groth16-singleton-multiproof-vectors.json` and
`src/bch/groth16-bls12381-singleton-multiproof-vectors.json` — each a shared
`lockingOK` plus a `proofs[]` array (`proofs[0]` is the committed instance;
`proofs[1..]` the minted extras). PRNGs are seeded deterministically, so the output
is reproducible.

## Regenerating

```sh
# from the groth16_contract repo (writes into ../verifier/src/bch/)
node singleton/bn254/gen_multiproof.mjs              # EXTRA_PROOFS=3 by default
node singleton/bls12-381/gen_multiproof.mjs

# then, from the verifier repo
pnpm benchmark          # see the "proof generality" lines
pnpm benchmark:json     # refresh results.json (adds the generality block)
```

Set `EXTRA_PROOFS=N` to mint more/fewer (each extra proof is a full singleton VM
evaluation, ~3.5–4 s, so the default of 3 keeps the benchmark snappy while still
sampling at least two proofs).
