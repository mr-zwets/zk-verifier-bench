# Conditional proof transfer: equation composition and BN domain

This document is an additive transfer of two existing local mathematical
derivations. It does not modify `claims-v2.md`, the package, source, vectors,
ledger, or runtime evidence. It translates the actual composition-b final
proof and the current BN endpoint/affine-domain joins into portable prose;
all limits and model premises remain explicit.

## Scope and exact artifact

The transferred artifact is the current 7,553-byte C body
`63f12474082916e22ab62faf6c6f0483bedcbb08a9700e4d7eb02415c9d8c242`, with
the 61-byte R14 body
`0563cd756e2d300b7653e10fd2e39ba5951e404210ba78f18d8ba4549719a030` and
35-byte P2SH32 locking script
`a32303cca71026a88ad8cd74bf38c6c8f6a8794cfa3065af7e7e207d8cf9d2c7`.
`C_code` here is the executable bytecode body. It is not the Groth16 proof
point `C_proof`; the latter is the 64-byte C coordinate in STMT.

The proof is conditional on the ordinary BCH-2026 Script/VM model, exact
P2SH32 commitment binding, the authenticated three-input caller graph, the
reviewed source-to-byte/lowering/frame contracts, and the typed random
function used by the transcript. It does not assume honest advice, producer
completeness, equal old/new cost counters, or an old R13 execution.

## PUB-PROOF-001: R14/C composition and accepted equation

### C1: exact current redeem bootstrap

For one current transaction, let each accepted unlocking program leave its
literal pushes in order. P2SH32 removes the final pushed redeem item after
checking HASH256 against the current 35-byte locking commitment. Commitment
binding therefore identifies that item as the exact R14 bytes above.

On the remaining stack, R14 reads the host unlocking bytes `U0` and `U1` and
keeps exactly `U0[3:3892]` and `U1[3:3667]`. Each split is valid exactly when
the host length is at least its 3-byte prefix plus the requested length.
The two slices are concatenated. R14 then hashes that concatenation, compares
it with the literal digest of C, defines function 01, and invokes it. The
extraction identity is bytewise for arbitrary host bytes; it does not depend
on a witness constructor.

The C digest comparison identifies the exact current 7,553-byte C body. C
contains 24 distinct body/identifier pairs. `INPUTINDEX`, the literal role
base 23, `ADD`, and `INVOKE` select role `23 + inputIndex` on the residual
stack. The role-local DEPTH, position, size, minimal-push, and raw-boundary
checks therefore apply to each of the three accepted current inputs. The
authenticated role layouts are:

```text
role 23: C, S, DS, FILL
role 24: C, S, HAND, DS, FILL
role 25: DG, STMT, S, HAND, DS, FILL, WQ
```

This establishes the current R14-to-C composition under ordinary P2SH32
execution. It is an acceptance implication, not a packet-construction claim.

### C2: why the current C-only equation proof applies

The C-only accepted-equation proof uses the C program, its checked input
views, and the common authenticated caller relation. Its former R13 entry
was only one way to enter that program. C1 supplies the current R14 entry,
while the C bytes, all 24 function bodies, layout, offsets, kernels, and role
dispatch remain identical to the proof parent.

An independent token scan finds no `ACTIVEBYTECODE` and no signature,
output, or token dependency in C. `GRAPH` checks equality of the three
current locking scripts after the input-count check; it contains no R13
literal. `INPUTBYTECODE` reads use the same fixed offsets and raw-length
equations. The transcript tail is `U2[5039:len(U2)-62]`, so the current
62-byte redeem push is excluded. The data-dependent transcript inputs remain
`TAG || DG`, `H0 || rho`, and `H0 || rhoRaw || ZT`; they depend on the checked
current data owners, not on a stale redeem literal.

Consequently, every ordinary all-three-input accepted R14/C execution
satisfies the exact premises of the C-only equation derivation. The proof
concludes the fixed-VK four-pair equation except

```text
min(1, (7 Q_RO^2 + 1848 Q_RO) / 2^256),
```

where `Q_RO` counts setup, advice, discarded-attempt, padding-attempt, and
final-verification queries and is distinct from the quotient polynomial
`q(X)`. Fixed-SHA zero-error, privacy, knowledge, pricing, canonical
producer success, score, and qualification are outside this implication.

### C2 equation boundary

The existing source composition gives the following mathematical chain. STMT
and RD establish canonical p/Fr words and A/C curve residuals; the B twist
residual and endpoint checks establish the stated Fp2 curve and endpoint
relations; GRAPH, digest, code, and handover predicates bind one graph; SETUP,
DSTEP, BDBL, BADD, ADDSTEP, and BNDSTEP enforce their reviewed recurrence and
line contracts; the terminal binding checks the GLS relation modulo r; and the
quotient/fin checks enforce the Horner/M(z) residual. The typed-RO reduction
then gives the displayed error bound.

This transfer does not silently claim that source predicates are compiled
semantics: the current raw opcode/DAG/caller join remains the explicit
compiled-assurance boundary owned by the compiled-equation peers.

## PUB-PROOF-002: BN domain, affine walk, denominators, and endpoint

### Declared field and twist domain

The mathematical domain is the declared BN254 tower with

```text
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
u = 4965661367192848881
m = 6u + 2 = 29793968203157093288.
```

The field-domain derivation uses `F=Fp[i]/(i^2+1)`, `xi=9+i`, the cubic
extension and `M(X)=X^12-18X^6+82`. Its independent arithmetic checks show
the declared tower is a field, `X^6=9+i`, and the source even-subfield is the
fixed field of `X -> -X`. These are mathematical premises about the declared
BN field, not claims that a finite fixture proves primality or tower
irreducibility.

The source role-0 checks range-decode B coordinates below p and enforce
`y_B^2 = x_B^3 + 3/(9+i)` in Fp2. The source and endpoint owners use the same
`ETA`, `OMEGA=ETA^2`, and PSI constants. Thus source-enforced facts are the
coordinate ranges, twist residual, endpoint residuals, and inverse-norm
guards; finite/non-neutral/prime-order G2 membership and standard BN
field/group/pairing facts are declared mathematical domain premises until the
compiled join is applied.

### Ordinary affine walk

The source NAF has 65 events and 21 nonzero digits, with scalar recurrence
`s -> 2s+d`, `d in {0,+1,-1}`, starting at `[1]B` and ending at
`[m]B`. For a finite non-neutral B of exact odd prime order r, every prefix
is a nonzero scalar multiple of B. The checked ranges exclude `r | 2s`, so a
doubling cannot encounter a y=0 point. For a mixed addition by `+B` or `-B`,
equal x coordinates would imply `[2s]B = +/-B`; the checked pre-addition
scalar ranges exclude both residues. Therefore every ordinary inverse norm is
nonzero, and the inverse-norm equality forces the ordinary affine slope and
group-law output.

The same argument applies to the two terminal additions once the endpoint
operator resultants are used. This is the universal arithmetic statement; it
does not use the six positive fixtures. Its source-to-byte realization remains
a separate compiled-lowering premise.

### PSI endpoint and subgroup result

The source constants give `psi^2 = -g` on the rational twist, where
`g(x,y)=(OMEGA*x,y)`, and the horizontal-chord identity gives
`g^2 + g + id = 0`. Hence `U(psi)=psi^4-psi^2+1=0`. The native terminal
walk and endpoint residuals imply

```text
G(psi)B = 0,
G(T) = T^3 - T^2 + T + m.
```

The exact integer Bezout/resultant certificate proves

```text
Res(U,G) = 36*r,
gcd(Res(U,G), 2*p-r) = 1.
```

On the `(2p-r)`-primary component G(psi) is injective; the BN/Frobenius
eigenvalue gives G(p mod r)=0 on the r-torsion component. Therefore the
rational kernel is exactly the order-r subgroup. With the declared standard
BN twist order, Weil-pairing, and Frobenius premises, an accepted finite
non-neutral endpoint is the canonical prime-order G2 domain and obeys
`psi(B)=[p]B`. The proof uses the direct U/G route, not the optional
characteristic-polynomial norm shortcut or a sampled point.

The affine denominator derivation is intentionally sequenced with these
premises: it proves regularity for exact-r B, while the endpoint/resultant
join identifies the accepted rational kernel. It does not claim that an
arbitrary byte encoding is a valid finite G2 point merely because a fixture
rejected another encoding.

## Remaining boundary after this transfer

PUB-PROOF-001 and PUB-PROOF-002 now have complete conditional local
derivations, with exact source/evidence owners and explicit premises. They
remain conditional for public qualification until the source-to-byte/CashVM
binding and public packaging expose the cited proof text. The following are
not silently closed here: fixed VK/table relation, typed-RO reduction detail,
Frobenius/quotient representative joins, canonical producer completeness,
resource/caller induction, and public source reconstruction.

No source, fixture, proof generator, VM, compiler, benchmark, ledger, or
publication artifact was modified.
