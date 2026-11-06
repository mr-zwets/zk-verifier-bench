# Units, GLS encoding, and the canonical root class

These component arguments use the declared BN254 field/tower and ordinary
curve/group/pairing identities. Source anchors are `sound-si-gls/math.mjs`,
`bn-native-sound/kernels.mjs`, `protocol.mjs`, and `script.mjs` under the
published `source/chunked/bn254/` tree. They supply mathematical implications,
not a substitute for the separately declared compiled-lowering, caller,
transcript, resource, or external-review obligations.

## Nonzero Miller line factors

Let Phi be p-power Frobenius on the declared curve over Fp12. The declared
G1 group is fixed by Phi and has prime order r. The checked prime-order G2
twist subgroup, after untwisting, has Phi(Q)=[p]Q. If P belongs to both,
then [p-1]P=O and [r]P=O. The fixed BN254 parameters have gcd(p-1,r)=1,
so Bezout's identity implies P=O. Thus G1 and this G2 intersect only at O.

A chord or tangent on a nonsingular Weierstrass cubic meets it at Q1,Q2 and
-(Q1+Q2), counted with multiplicity. If Q1,Q2 belong to G2, all its finite
intersection points belong to G2. The vertical-line case has the same
conclusion, with the third intersection at O. Therefore such a line cannot
vanish at a finite nonidentity G1 evaluation point: that would put the point
in the nonidentity intersection of G1 and G2.

For accepted source executions, inverse-norm predicates force the affine
update denominator to be nonzero; the checked slope/update relations then
implement the ordinary group law without first assuming prime-order B.
The endpoint/twist argument identifies the resulting accepted G2 subgroup.
For constructive completeness, the separate finite prime-order trajectory
proof ensures all those inverse norms exist. These are two different uses
of the slope predicates; membership is not proved by assuming it first.

The runtime B trajectory and fixed delta trajectory therefore supply nonzero
geometric line evaluations at -A and C in the supported finite domain.
The source's scaling factors must also be units; the affine/projective line
and inverse-norm contracts establish those facts. Multiplication by a
nonzero Fp2 scale preserves nonvanishing in Fp12. This argument does not
cover a neutral external A/C encoding; those are outside the declared domain.

The fixed IC points, alpha, beta and gamma are the individually checked
finite nonidentity points of this exact VK. Their raw Miller values and
Frobenius images are units by the same argument and field automorphism
identities. The public fixed-preprocessing check relates these values to
the five stored monic rows. No arbitrary VK is inferred. Even when
IC0+n0*IC1+n1*IC2 is neutral, the implementation evaluates the individual
fixed IC pairing factors and folds their exponents; it does not run an
affine Miller routine on that neutral sum. Thus neutral vk_x creates no
missing line evaluation in this construction.

The variable root/state representatives are normalized degree-at-most-six
polynomials, not the old restricted affine quotient chart. S(tau)=1 makes
each nonzero as a polynomial. Its degree is below the irreducible degree-12
M, so its image in K=Fp[X]/M is a unit. Fixed monic degree-six rows are
nonzero for the same degree reason. Conjugation, Frobenius, and the
eta-substitution automorphism preserve units. These facts combine with the
line-unit argument; they do not infer a unit merely from a fixture pass.

## Exact GLS lattice and the universal coefficient bound

Put x=4965661367192848881 and let the four lattice rows be

    L0=(2x+1, 0,     2x,      1)
    L1=(2x,   x+1,   -x,      x)
    L2=(x+1,  x,      x,     -2x)
    L3=(2x+1,-x,    -(x+1),  -x).

Use pi_i=p^i mod r as the canonical residues, with pi_0=1. The independent
integer certificate checks L*pi=0 modulo r, det(L)=-r, and the cofactor
vector C for the first column. The adjugate identity gives

    C^T L = det(L)*(1,0,0,0).

The absolute column sums are

    34759629570349942170, 14896984101578546644,
    24828306835964244406, 19862645468771395525,

all strictly below 2^65. For any integer n, set

    a_j=n*C_j/det(L), c_j=nearest_integer(a_j),
    e=(n,0,0,0)-cL.

The source `roundDiv` first makes its denominator positive, uses truncating
integer division, and rounds away from zero when the remainder is at least
half a denominator. Thus |a_j-c_j|<=1/2, including ties. Since
(n,0,0,0)=aL, it follows that

    |e_i| <= (1/2)*sum_j |L[j][i]| < 2^64,
    sum_i e_i*pi_i = n (mod r).

This proves the decomposition for every canonical public scalar 0<=n<r;
no sampled scalar set is being substituted for the quantifier.

Set u_i=e_i+2^64. Every u_i is nonnegative and below 2^65, so the 65
MSB-first events 0,...,64 encode all its bits, including bit 64. At event e,
the four bits form a nibble selecting the subset sum of pi_0,...,pi_3.
The exact-integer native Horner accumulation therefore yields

    acc=sum_i u_i*pi_i.

The source constant is precisely

    PI_SUM_OFFSET=(2^64 * sum_i pi_i) mod r.

It is the canonical residue, not the unreduced integer sum and not the
unreduced powers p^i. Hence the terminal predicate

    (acc - n - PI_SUM_OFFSET) mod r == 0

checks the intended scalar congruence. The public fixed-table correction
uses actual raw Frobenius powers p^i; after final exponentiation their
exponents are reduced in the order-r target group, so the congruent pi_i
weights and the shifted-encoding correction implement the same fold.

## Existence of the canonical root class

Let sigma be X->-X in K=Fp12 and E its fixed even subfield. The map

    phi: K*/E* -> K*, [a] -> sigma(a)/a

is injective: its kernel is exactly E*. Write N=(p^6+1)/r. For the source
raw product, the valid fixed-VK equation and GLS fold imply

    FE(raw)=raw^((p^12-1)/r)=1.

As phi([raw])=raw^(p^6-1), this gives phi([raw])^N=1, and injectivity gives
[raw]^N=1. For the exact source exponent

    lambda=6*x+2+p-p^2+p^3,

integer arithmetic checks r divides p^6+1, r divides lambda, and
 gcd(lambda,N)=1. Thus d=lambda^(-1) mod N exists and

    [raw^d]^lambda=[raw]^(1+kN)=[raw].

Only quotient-class equality is asserted. The degree-six homogeneous-kernel
construction then provides nonzero representatives of this root and all 33
boundary classes, with one common tau in 1,...,205. Its normalization and
recurrence proof is in the degree-six component note. Quotient construction
follows rho; filler is fixed before z and HAND is computed after z. The
canonical transport/resource argument must still establish the actual caller
and complete-execution bounds for these values. This note does not assert
that arbitrary supplied advice fits those bounds or that root algebra alone
proves the compiled verifier theorem.
