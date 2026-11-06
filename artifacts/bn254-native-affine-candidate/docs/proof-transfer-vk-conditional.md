# Conditional VK, fixed-table, and public-input binding transfer

This document transfers the existing fixed-preprocessing and GLS derivations
for PUB-PROOF-003. It is not a new pairing proof and does not modify source,
catalogs, fixtures, claims-v2, the ledger, or runtime evidence.

## Exact VK serialization

The fixed key is serialized as twenty unsigned 32-byte little-endian field
coordinate words in this exact order:

```text
alpha.x, alpha.y,
beta.x.c0, beta.x.c1, beta.y.c0, beta.y.c1,
gamma.x.c0, gamma.x.c1, gamma.y.c0, gamma.y.c1,
delta.x.c0, delta.x.c1, delta.y.c0, delta.y.c1,
IC0.x, IC0.y, IC1.x, IC1.y, IC2.x, IC2.y.
```

The serialization is 640 bytes. Independent SHA-256 gives

```text
VK_DIGEST = 181aeefd9c0ce8d103ad084f4ef8174546852b0af46ac58a8061d4f38d346a6e.
```

The exact coordinate data is owned by the pinned synthetic public-VK fixture;
the digest is not treated as a replacement for the coordinate order. A public
reproduction must ship that fixture or an equivalent coordinate table and
recompute this digest from the stated order.

## Fixed raw Miller representatives

Let `m(P,Q)` be the raw BN254 Miller value before final exponentiation. The
fixed-preprocessing certificate independently computes the quotient class in

```text
Fp[X] / (X^12 - 18 X^6 + 82),
```

then chooses the monic degree-six representative. It does not use the source
conversion helpers to construct its expectation. The four public-input table
families are

```text
R[k][i]   = monic(m(IC_(k+1), gamma)^(p^i)),  k in {0,1}, i in {0,1},
R[k][i+2] = R[k][i](eta X),                  i in {0,1}.
```

The exact emitted coefficient-string digests are:

```text
R[0][0]  da1e0f3825b1d49b6bb042e49dc1e5f073f772d122e3e72a53c62d0252f9f97e
R[0][1]  76047bcea692a83f62c138ee0cdccb066db95693e19296de605bf13e801114cf
R[1][0]  330fe6e088ef04bd39e8a2e17dc8cd20c9687db32a24973fd019274a7518994e
R[1][1]  d88de8a365643c826c0017d3fcb976f3e7a7506ad9db7e5a1d6b7c71022e52b9.
```

The correction representative is

```text
Rconst = monic(m(alpha,beta) * m(IC0,gamma)
               * prod_(k=1,2; i=0..3)
                   m(IC_k,gamma)^(-2^64 p^i)),
```

with coefficient-string digest
`b6cd472f318146d7743be63b48c1756b995f98c9415bcb496f6c641341448efb`.
The independent checker verifies each raw value is nonzero and that its
product with the conjugate of the monic representative reduces to an even
polynomial. This proves the quotient-class relation, not a claim about the
final-exponent value or arbitrary input validity.

## Emitted literal and source ownership

The fixed-preprocessing certificate parses final instruction boundaries, not
builder call counts. It finds exactly one six-coefficient run for each R
family and one Rconst run in the native emitted bodies. The implicit monic
coefficient is `1`; the six stored coefficients are the values above. The
native final code and catalog are pinned by the fixed-preprocessing owner; its
scope is fixed VK/source/value/emission, not full verifier soundness.

The source composition theorem assigns the consumers as follows:

* `SETUP` consumes the fixed R representatives and produces the ordered EV,
  EA, TM, power, and hot-coordinate values;
* `EV` evaluates fixed monic degree-six representatives while `EA` evaluates
  normalized degree-at-most-six root/state representatives;
* terminal `Rconst`, Frobenius factors, and the final residual consume the
  fixed correction and root factors;
* the GLS binding consumes the 65-bit shifted coefficients and the public
  scalar residues; and
* the final pairing expression uses the fixed alpha/beta/gamma/delta and IC
  terms after the public-input fold.

These are distinct consumers. A VK digest proves identity of the serialized
key; it does not, by itself, prove any table relation or runtime consumer.
The fixed-preprocessing and GLS certificates provide those separate relations.

## Public-input fold and `vk_x`

For each public scalar `n_k`, the universal GLS lattice certificate gives
four integer coefficients `e_i` with `|e_i| < 2^64` and

```text
sum_i e_i * (1, p, p^2, p^3)_i = n_k (mod r).
```

The protocol shifts them by `2^64`, packs the resulting values into the
65-bit nibble schedule, and subtracts the fixed
`PI_SUM_OFFSET = (2^64 * sum_i p^i) mod r`. The source binding therefore enforces the
same residue as the canonical public scalar. The source-level fold is

```text
vk_x = IC0 + n0*IC1 + n1*IC2,
```

and the fixed Rconst correction supplies the corresponding `-2^64` terms.
After bilinearity and final exponentiation, the fixed terms combine as

```text
e(-A,B) * e(alpha,beta)
* e(IC0+n0*IC1+n1*IC2, gamma)
* e(C,delta) = 1.
```

This identity permits algebraically neutral `vk_x`; it does not require a
finite affine decoder for the sum. The domain, field, pairing, line-scaling,
and compiled public-input caller premises remain explicit.

## Exact scope and remaining public supplement

PUB-PROOF-003 is closed as a conditional local transfer: the fixed VK order,
raw table formulas, Rconst correction, emitted coefficient bindings, GLS
lattice identity, offset correction, and `vk_x` relation are all written and
owned by existing certificates.

The public package still needs a self-contained supplementary certificate
containing the actual 20 coordinate words (or a portable fixture), the
independent monic-representative scalar data, and the GLS lattice rows/cofactor
or an equivalent reproducible derivation. The current local proof files pin
these data and their checkers but are not themselves the public package.
This transfer therefore does not upgrade the whole public proof, pairing
implementation, VM semantics, producer completeness, or qualification.
