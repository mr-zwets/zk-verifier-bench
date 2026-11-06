# C-first prefix-extraction: repository contribution claims

This is the substantive public claims sheet for the C7553/R61 packet. It
remains unadmitted: external qualification, score, upstream admission, official status,
production, application, privacy, relay, and publication decisions are false.
All claims below are conditional on the named source, lowering, caller, fixed-VK,
finite-domain, and typed-random-function premises. Public source, vectors,
patches, and the proposed registry projection are present in this packet;
registered CLI/typecheck evidence is recorded in the public export; the
local conditional gate is closed for the named artifact. The ordinary raw-Miller
certificate action also passed for the same fixed tables, as recorded in
`docs/public-evidence/public-execution-summary.json`. Maintainer recheck,
external constructive assurance, admission, official status, and publication
remain pending.

## Artifact identity and wire encoding

The implementation artifact is the compiled code `C_code`, redeem program
`R`, and P2SH32 locking script. In this sheet `C_code` never means the
Groth16 proof point `C_proof`: `C_proof` is the third G1 element of
`proof={a,b,c}` decoded by `protocol.mjs` `proveCore`, while `C_code` is the
compiled program emitted by `script.mjs` `buildProgram` and split into the two
host code pieces. The current hashes are:

```text
C_code (7553 bytes) 63f12474082916e22ab62faf6c6f0483bedcbb08a9700e4d7eb02415c9d8c242
R (61 bytes)         0563cd756e2d300b7653e10fd2e39ba5951e404210ba78f18d8ba4549719a030
P2SH32 locking       a32303cca71026a88ad8cd74bf38c6c8f6a8794cfa3065af7e7e207d8cf9d2c7
```

The statement constructor in `sound-si-gls/protocol.mjs` and the native
`protocol.mjs` serialize the first eight coordinates as 32-byte little-endian
words: `A=(xA,yA)` occupies 64 bytes, `B=(xB0,xB1,yB0,yB1)` occupies 128
bytes, and `C_proof=(xC,yC)` occupies 64 bytes. Thus the coordinate prefix is
256 bytes. `n0` is at byte offset 256 and `n1` at offset 288, both 32-byte
little-endian words, so the proof/public statement prefix through both public
scalars is exactly 320 bytes. The native source exports
`STMT_LAYOUT={n0:256,n1:288,N0:320,N1:385,tau:450,sc:482}` and `STMT_SIZE=674`.
The 130-byte `G` encoding begins at offset 320 and is nibble-masked; `tau`
begins at 450 and the six `sc` words begin at 482. This is a wire-layout
statement, not a claim that a proof object itself is 320 bytes.

The three role layouts are source-owned by `roleProgram` in `script.mjs`:
role 23 consumes `C,S,DS,FILL`; role 24 consumes
`C,S,HAND,DS,FILL`; role 25 consumes
`DG,STMT,S,HAND,DS,FILL,WQ`. `genBody` defines role IDs as
`ROLE_ID+i`; the reviewed catalog binds the emitted IDs to 23, 24, and 25.
The seven HAND words are `(X0,X1,Y0,Y1,Fp,Fm,R)`, each canonical 32-byte
field output, for exactly 224 bytes. `DS` and `DG` are 96-byte delta/digest
objects. `S`, `STMT`, `D`, `DS`, `WQ`, and HAND are checked at their role
boundaries and successor handovers; a fixture hash alone is not treated as a
relation proof.

## Fields, curve domain, and fixed VK

The source binds `p=Fp.ORDER` and `r=Fr.ORDER` in
`sound-si-gls/math.mjs`, rather than treating these as interchangeable:

```text
Fp p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
Fr r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

The primary library/source binding is the `bn254.fields` object imported by
that file; the same constants are independently present in the pinned
BN254 field implementation. Field coordinates and `Fp` tables use `p`.
Groth16 public scalars and the final GLS binding use `r`. `n0` and `n1` are
decoded by `STMT` and checked against `r`; `RD` checks field words against
`p`.

The fixed synthetic VK is identified by digest
`181aeefd9c0ce8d103ad084f4ef8174546852b0af46ac58a8061d4f38d346a6e`.
`protocol.mjs` constructs that digest from the little-endian coordinates in
the order `alpha.x, alpha.y, beta.(x.c0,x.c1,y.c0,y.c1), gamma.(...),
delta.(...), IC[0..].(x,y)`. This exact order, the coordinate encoding, and
the digest are separate obligations from the proof equation. The transcript
tag is the 19-byte ASCII prefix `BNMX3/DEGREE6-EVAL1` followed by that 32-byte
VK digest, 51 bytes total.

The mathematical target is BN254 with finite canonical G1 `A,C` and a
non-neutral prime-order G2 `B`; algebraically neutral `vk_x` is allowed. The
source checks G1 curve residuals in `G1C`; role 23 checks the four Fp2 twist
residual words using `B_TWIST=3/(9+u)`; role 25 constructs `psi(B)` from the
source `PSI[0]` constants and the endpoint checks compare the terminal point
with `-psi^3(B)`. These are source predicates and named domain premises, not
an assertion that six fixture rejections alone prove universal subgroup or
cofactor membership. The exact supported-domain theorem and any cofactor or
odd-order converse must be published with the portable mathematical notes.

## Concrete acceptance binding map

The following map names the code predicate and its consumer. “Witness” means
only that a byte is supplied; acceptance requires the listed predicate.

| Value or relation | Exact source owner and predicate | Binding consequence |
| --- | --- | --- |
| `A`, `C_proof` | `protocol.mjs:proveCore` decodes `g1(proof.a/c)`; `script.mjs:G1C` checks each affine curve residual with NOT/VERIFY | Proof points are finite, canonical source inputs; `C_code` remains separate. |
| `B` | `proveCore:g2(proof.b)` plus role-23 twist residual kernel | Fp2 coordinate order is x.c0,x.c1,y.c0,y.c1; the curve predicate is consumed before the walk. |
| `n0,n1` | `STMT` decodes words at offsets 256/288, checks `<r`; final `binding` computes exact integer GLS accumulators and reduces mod `r` | Public scalars are Fr values, not Fp words; `vk_x` is the source-computed IC combination. |
| `vk_x` | `SETUP`/`TA` table construction and final `binding` in role 25 | The fixed IC table and scalar relation are consumed, not merely catalogued. |
| fixed VK | `protocol.mjs:VK_DIGEST` coordinate list and `TAG`; `SETUP` consumes `VKC` tables and `Rconst` | Digest/tag identifies the exact VK; it does not replace a portable table-relation argument. |
| `S`, `STMT` | `roleProgram` layout; `STMT` decodes eight coordinates, `n0,n1`, G nibbles, tau, and six `sc` words with `RD`/range predicates | Statement bytes, scalar ranges, tau range 1..205, and nibble encoding are acceptance-bound. |
| `DG`, `DS` | `TRANS` consumes `DG`; each role checks its DS hash against the source `DS[i]` bytes | Digest/delta bytes are bound by both size/hash and their source-derived consumers. |
| `rho,z` | `TRANS`: `h0=SHA256(TAG||DG)`, `rhoRaw=SHA256(h0||"rho")`, `zRaw=SHA256(h0||rhoRaw||ZT)`, then Fp reduction | Transcript order and ZT handover are explicit; raw digest versus reduced field value is distinguished. |
| `HAND` | `HDEC` reads seven `<p` words; nonterminal roles `HENC` canonicalize and compare the next role's HAND | X/Y/Fp/Fm/R are successor-bound, not merely supplied state. |
| `D`, slopes, endpoints | `DSTEP`, `BDBL`, `BADD`, `ADDSTEP`, `BNDSTEP`; role 25 `t:endpoint` runs four residual NOT/VERIFY checks | Delta and Miller states are checked through their actual consumers. |
| `S_c` and Frobenius W | role-25 `t:W` invokes `degree6FrobFactorized`, computes both parity products, and updates R | The factorized evaluator is part of the equation path; a source polynomial proof must be portable. |
| `tau`, `sc`, fixed tables | `STMT` range/decode, `SETUP` power kernels, `EA`, `EV`, `TM`, `TA`, and `Rconst` | Tables and slope/endpoint values are checked at the point of use; a fixed-table hash is not a relation proof by itself. |
| quotient `WQ` | role-25 `quotient` checks 32-byte word divisibility/length, decodes four `<p` words per Horner step, and final `fin` residual uses `M(z)=z^12-18z^6+82` | Quotient normalization and final residual are acceptance predicates, not a witness/hash assertion. |
| fillers and raw lengths | `FILL`, `PLEN`, role raw-fixed plus `WQ`/FILL length checks | Canonical producer/resource bounds are separate from arbitrary-advice acceptance. |

The source-level role IDs are 23/24/25, but the public proof must also ship
the catalog/function-ID map and a portable byte decoder. `asm.mjs` applies
explicit function-ID remaps (`18↔0`, `20↔-1`, `15↔21`) and therefore a
hand-written “role number” statement is not enough without the emitted
catalog/prologue evidence.

## Equation, soundness, and random oracle

The intended fixed-VK equation is

```text
e(-A,B) · e(alpha,beta) ·
e(IC0+n0·IC1+n1·IC2,gamma) · e(C_proof,delta) = 1.
```

The conditional soundness claim is for an ordinary accepted execution under
the pinned BN254 field/tower, affine curve/domain premises, primitive Script
VM and generic lowering/caller-frame contracts, authenticated three-role
graph, exact fixed VK/tables, and the typed SHA-256 random-function model.
The recorded error expression is
`min(1,(7 Q_RO^2 + 1848 Q_RO)/2^256)`, where `Q_RO` includes setup, advice,
discarded-attempt, padding-attempt, and final-verification queries. `Q_RO` is
not the quotient polynomial `q(X)`.

This draft does not claim fixed-SHA zero error, arbitrary VKs, arbitrary
point encodings, or an honest-advice premise. It also does not turn the
finite benchmark's run-rejection-only input checks into a universal domain
theorem.

## Completeness, resource, and measurement scope

The intended completeness statement is constructive and conditional: every
valid supported finite-domain proof has a canonical auxiliary execution under
the declared producer, caller, graph, field/group, VM/lowering, and typed-RO
contracts. The canonical resource owner covers all 132 quotient-width rows
with targets `[9964,9875,9907]`, corrected U `[8002502,7930995,7865661]`,
and the named conditional memory bound. This is a canonical-witness
existence statement; it is not a bound on arbitrary oversized advice and does
not claim that the finite fixture corpus proves all valid proofs.

The direct existing-fixture corpus is 108 positive evaluations (54 minimal,
54 uniform) plus 216 case evaluations, 324 total. A separate benchmark made
one unmetered internal benchmark call; it must not be described as 324 inputs.
The benchmark measured 27,682 bytes (27,533 script + 149 overhead, zero
padding), with five ordinary plus one dense positive, 22 ordinary plus two
domain cases, nine public-input, two seam, and three padding checks. It is a
finite measurement, not score/admission/officialness or a universal cost
theorem.

## What is and is not public-proof complete

The packet now names the public owner for each component rather than treating a
private report hash as a proof. The field/tower, G1/G2 intersection, nonzero
Miller-line, and canonical root-class arguments are in
`docs/public-completeness/unit-and-gls-lemmas.md`; its scoped independent peer
review is in `docs/public-completeness/unit-and-gls-peer-review.md`. The fixed
VK/table and `vk_x` relation are covered by `docs/vk-v9/` and its packet-local
v9 wrapper. Degree-six/Frobenius, quotient, literal-zero, and canonical
representative obligations remain in `docs/degree-six-components.md` and the
source/patch lineage. Typed-RO ordering and error accounting are in
`docs/typed-random-function.md`. Canonical producer existence and all 132
resource rows are represented by `docs/resource-argument.md`,
`docs/resource-status.json`, and `docs/canonical-row-table-v2.json`. The
source-to-byte capture is reproduced by `source/reproduce-v2`; identity checks
do not establish generic VM semantics. The static capture transfer and
conditional caller/lowering contracts are stated in
`docs/public-evidence/capture-frame-contract.md`, with the dynamic terminal
join in `docs/public-evidence/dynamic-consumer-v2.md` and canonical memory in
`docs/public-evidence/memory-contract.md`.

These documents state their caller, fixed-VK, finite-domain, typed-RO, and
lowering premises explicitly. The fixed-preprocessing checker is included with
packet-local fixture/certificate/closure paths; its `--check-plan` is safe and
its arithmetic action passed in the separate public execution summary. A written component note,
peer result, or hash is not an admission or a substitute for external review.

## Reproduction, deployment, and review state

The intended public reproduction is a clean baseline plus the fourteen
ordered source patches, with exact source/fixture/dependency/compiler/runtime
pins, then byte-exact C/R/locking/vector checks. The registered CLI/typecheck evidence and finite existing-fixture
measurements are recorded in packet-local public evidence. The local
conditional source/math/resource gate is closed for this named artifact; the
raw-Miller proof action has its separate component scope, and maintainer
recheck, external assurance, admission, official status, score, and publication are not
claimed.

The named deployment model is BCH-2026 Script/VM with the pinned Node/pnpm,
libauth, compiler, runtime closure, transaction, and graph contracts. No
relay/mainnet, application knowledge-soundness, privacy, setup-independence,
production, upstream-maintainer, or official claim is made. Any change to
verifier bytes, imports, VK/domain, graph/deployment, caller/lowering, or
cryptographic premise requires renewed review; evidence hashes change when
the corresponding bytes change, while a documentation-only update does not
retroactively alter executable identity.

This is prepared for submission with public proof notes, a portable source
recipe, local reproduction, and path-sanitized evidence. External constructive
review remains required for an upstream reviewed disposition. Separate local
agent reviews belong to the same pipeline and do not satisfy that requirement.


## Packet-local identities and final review gates

The runtime module in this repository contribution is 3261 bytes, SHA-256
`9efdbbd88add5f2b3d34aabf4b7a050ce600a5b91c453b3659986b4b4d936d56`.
Its two documentation paths are rebased from the standalone module (3181 bytes,
`14e2dc76d0951e5b33410d3416cb3ad4f031ac5abdd58e9869355ccd5330378a`);
reversing exactly those substitutions restores that module byte-for-byte.
Its executable body is bound by the source14 C/R capture and is not re-derived
by this document. The packet
contains the public 8-module/1-fixture source tree, fourteen proper patches,
and `source/reproduce-v2`; the clean baseline is
`974d86d73b16666520eef16404919a836d88ea74`.

The v9 public-input/native-table certificate binds fixed BN254 `p`, `r`, and
`bnX`, the canonical unsigned-LE32 VK digest
`181aeefd9c0ce8d103ad084f4ef8174546852b0af46ac58a8061d4f38d346a6e`, the
51-byte `BNMX3/DEGREE6-EVAL1` tag, all 24 native definitions/tables/GLS rows,
and all three positive-row final-R values. It does not prove the raw
Miller-to-monic relation, VM/compiler equivalence, resource theorem, or
qualification.

The registry patch was applied in an isolated local projection against public
commit `db068eb4be8a096345ddf80494eb0d85b7e18abf` and tree
`702e22ccc243afa203c1f16a175b7c72ec1ef8eb`. The final module passed the declared
package typecheck and registered existing-fixture benchmark with unchanged
inputs. `docs/public-evidence/validation.json` records the final module, registry,
vectors, compiler closure, and finite execution evidence. The frozen 324 direct
evaluations and original benchmark remain separate from three later public
integration benchmark calls; the latter's internal input counts were not
instrumented. A maintainer must independently rebuild/review the exact bytes
and rerun the contribution checks before admission.
