# Submission claims and assumptions

This is the authoritative claim sheet for a reviewed entry. It describes what
the shipped, byte-pinned artifact establishes; it does not add a leaderboard
category or require a proof assistant.

## Separate claims

Every submission should state these claims separately:

- **Fixture-compatible:** the supplied valid and invalid fixtures execute as
  expected. Fixtures are supporting evidence, not the admission basis.
- **Equation-reviewed:** acceptance of the exact shipped artifact implies the
  fixed-VK Groth16 equation below, over the declared input and curve domain,
  under the named assumptions and with any stated probabilistic error. This
  requires a written argument and an independent constructive review.
- **Application/protocol claims:** circuit knowledge soundness, zero knowledge
  for an application transcript, independent setup, application state binding,
  or live relay guarantees are separate claims and are outside this
  leaderboard's current challenge. They need a separately scoped companion
  track.

For soundness, say what an accepted execution implies. For completeness, say
that every valid supported proof has an auxiliary witness whose complete
execution accepts. A fixture pass does not prove either universal statement;
nor does “valid input” mean that every auxiliary representation is accepted.
State the supported domain and the existence of the auxiliary values required
by the construction.

For two public inputs, the fixed-VK equation to state is

```text
e(-A, B) · e(alpha, beta) ·
e(IC0 + n0·IC1 + n1·IC2, gamma) · e(C, delta) = 1
```

in the target pairing group, with scalar arithmetic modulo the curve order.
The domain assumptions must identify the curve and encoding rules, canonical
scalar/public-input ranges, how neutral points are handled, and the stated
subgroup/cofactor policy. Restricted domains are acceptable when the argument
proves soundness on that declared domain; a cofactor-equivalent policy need not
be relabeled as strict-subgroup enforcement.

## Required claim sheet

Copy this checklist into the implementation's provenance/header or PR:

```text
Artifact: ordered locking/redeem/imported-code hashes; fixture vector IDs/hashes
Dependencies: exact VK and preprocessing/table commitments; compiler revision
              and build flags; VM/libauth and harness revisions
Equation/VK: fixed verifying key and the equation above, with its exact
           point/scalar encoding and neutral-point checks
Domain: curve, scalar encoding, public-input range, neutral-point policy,
        subgroup/cofactor policy, and any restricted proof/input domain
Soundness: accepted execution => [equation], except for any explicitly bounded
           probabilistic error, with assumptions listed
Completeness: every [valid supported proof] has an auxiliary witness whose
              complete execution accepts
Binding map: every acceptance-dependent value and its owner/consumer
Composition: script-enforced premises versus deployment/publisher premises
Fiat-Shamir: transcript commit order, challenge inputs, error bound per query,
             and whether queries are adaptive
Generality: runtime or baked; multiproof coverage and supplied dense case
Deployment: VM/relay/transaction/state assumptions and measured limits
Review: pending, or byte-identical rebuild method, owner checks, reviewer/date
Re-review: any verifier-program byte change, changed cryptographic premise or
           domain, or changed deployment assumption; update hashes only when
           the pinned bytes change
```

The binding map must include every value acceptance depends on, including
multi-input state and public-input copies. Typical owners are public inputs →
`vk_x`, slope/endpoint → the corresponding group operation, table entry → its
evaluation, and carried state → the predecessor/transition/terminal check.
Witnessing an intermediate is not a proof that it equals the intended value;
the map must name the check that establishes that relation.

For Fiat-Shamir or polynomial-identity reductions, record the supplied
intermediate's commit order and the error bound for each oracle query. Define
the query budget, including final verification queries or guessing terms, and
explain why the bound survives the stated adaptive query strategy. Separate
the script's algebraic checks from deployment premises such as a publisher
having supplied a particular state, a transaction layout, or a trusted setup.

## Artifact and review discipline

The claim is about the exact byte-pinned artifact. A closed source or private
build is acceptable; public source is not required. The submitter must provide
the reviewer enough access to reconstruct the artifact and document the
byte-identical rebuild method. The reviewer checks ownership for every
acceptance-dependent value. Independent assurance means independent reasoning
and constructive checks, not different choices of ordinary field/hash
assumptions; agreement from the same pipeline or agent alone is insufficient.
Any verifier-program byte change requires a new review and updated hashes,
including code imported from unlocking data. New ordinary proof/witness values
within an already reviewed domain are not program changes; identify and
validate the changed fixture corpus separately. Changes to code or framing
cannot be treated as ordinary witness variation.
Changed cryptographic premises, domains, or deployment assumptions require a
new review, but do not change byte hashes unless the bytes change.

For `proofBinding: 'runtime'`, distinguish supplied multiproof coverage from a
universal claim. Check equal ordered programs and step counts plus actual proof
distinctness; current harness acceptance counts do not enforce these facts.
The dense `worstCaseProof` is a measured case and must be a
valid proof that the verifier accepts; it is not a universal worst-case bound.
State a universal bound only when the mathematics and resource analysis prove
one. A baked verifier is instance-specific by construction.

## Scope and companion tracks

The current challenge grades each declared fixed-VK equation; BCH-native
Groth16 submissions use the published benchmark setup for their curve. It
does not grade arbitrary verifying keys, circuit knowledge soundness, an
application's state machine, or live BCH relay behavior beyond the measured VM
and transaction checks. Research into a real application-level ZK system and
into VM cost changes or TXv5 is welcome as companion work. The `bch-spec`
model's larger limits are a distinct model; its separate TXv5-as-written grade
must not be represented as a claim about the current BCH VM.
