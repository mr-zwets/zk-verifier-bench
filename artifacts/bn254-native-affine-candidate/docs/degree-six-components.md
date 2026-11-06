# Degree-six representatives and terminal polynomial checks

These are component arguments for the declared fixed-VK BN254 construction.
They do not replace the Miller/group/VK argument, authenticated caller and
compiled-lowering contracts, or the complete canonical resource proof. Public
source anchors below are in `chunked/bn254/sound-si-gls/math.mjs` and
`chunked/bn254/bn-native-sound/{kernels,protocol,script}.mjs`.

## A nonzero representative exists for every required class

Work in the declared field K=Fp[X]/M(X), M=X^12-18X^6+82. Let E be its
six-dimensional even subfield and sigma the conjugation X -> -X. For a
nonzero f in K, form the six columns f*X^(2j) mod M, j=0,...,5. Take rows
7,...,11 to obtain a 5-by-6 matrix over Fp. Its nullspace is nontrivial.
The source `degree6Nullspace` uses invertible row operations, normalizes each
nonzero pivot, and sets one free coordinate to 1. At most five columns pivot,
so the chosen free coordinate exists. Back-substitution sets each pivot
coordinate to minus its row's free entry. This solves the original matrix
and gives a nonzero vector t in E.

Multiplication by f is invertible because K is a field and f is nonzero.
Consequently f*t is nonzero. Its coordinates 7,...,11 vanish by the kernel
construction, so its degree-at-most-six polynomial represents the same class
as f in K*/E*. This needs neither a nonsingular augmented monic solve nor a
search for a particular affine chart. `degree6RawRep` uses padded twelve-word
remainders, so zero high coefficients remain defined.

For canonical producer existence, retain the separately proved premises:
all event factors and raw are units, the valid equation gives FE(raw)=1,
N=(p^6+1)/r, and gcd(lambda,N)=1 for the fixed exponent lambda. The injective
map phi:K*/E* -> K*, [a] -> sigma(a)/a, gives
phi([raw])^N=FE(raw)=1, hence [raw]^N=1. If d=lambda^(-1) mod N, then

    [raw^d]^lambda=[raw]^(1+kN)=[raw].

This is class equality, not literal field-value equality. The canonical
state recurrence starts at sigma(rootBase), squares and multiplies the fixed
nonzero event factors, and uses sigma(rootBase) for a +1 NAF digit or
rootBase for a -1 digit. Squaring, multiplication and sigma descend to
K*/E*, so replacing any representative by an E* multiple preserves every
required class identity. The 33 boundary states plus the root therefore give
34 nonzero classes. Independently normalizing their representatives preserves
the identities; this does not assume the class representatives are equal.

## Common normalization and its native consumer

Each of the 34 nonzero polynomials has degree at most six, so their union of
Fp roots contains at most 204 elements. The 205 distinct candidates 1,...,205
therefore contain a common nonroot tau. The bounded source search terminates
under these premises. Multiplying each representative by the inverse of its
nonzero value at tau preserves its class and gives S(tau)=1.

Serialize the canonical six coefficients c1,...,c6. Reconstruct

    c0=1-sum(j=1..6,cj*tau^j).

This recovers all seven normalized coefficients, including when c6=0.
The native STMT reader enforces tau in 1,...,205 and every serialized field
word below p. In `kDegree6Eval`, separate the even and odd powers:

    E(x)=c0+c2*x^2+c4*x^4+c6*x^6,
    O(x)=c1*x+c3*x^3+c5*x^5.

Its two outputs E(x)+O(x), E(x)-O(x), reduced modulo p, are exactly
S(x), S(-x). The tau powers and all six words are consumer inputs; normalization
is not inferred from a witness file or an honest producer.

## Frobenius and the current characteristic recurrence

Use the declared tower's actual Frobenius coefficients alpha_j,beta_j:

    Frob(X^j)=alpha_j*X^j+beta_j*X^(j+6), 1<=j<=5,
    Frob(1)=1, Frob(X^6)=18-X^6.

Thus

    Frob(S)(x)=B(x)+sum(j=1..5,cj*x^j*Gj(x^6)),
    B(x)=c0+18*c6-c6*x^6,
    Gj(Y)=alpha_j+beta_j*Y.

The source tower identities and coefficient derivation are premises to be
checked against `FROB` in math.mjs; arbitrary coefficients would not suffice.
Since eta^6=1, the same B and Gj factors are used at eta*x; their j-th
contribution is multiplied by eta^j. Because 6 is even, alpha and beta terms
have the same parity. Both must enter the same even/odd bucket. This gives
Frob(S)(x), Frob(S)(-x), Frob(S)(eta*x), Frob(S)(-eta*x).

The current source computes Gj by a characteristic recurrence. Let i^2=-1,
Y=9+i, b=beta_1, a=alpha_1+9*b, and gamma=a+b*i. The tower-derived constants
satisfy trace(gamma)=2*a and norm(gamma)=a^2+b^2=eta. Hence

    gamma^2-(2*a)*gamma+eta=0.

Multiplying this identity by gamma^(j-1) gives the recurrence
G_(j+1)=(2*a)*G_j-eta*G_(j-1), with G0=1 and G1=alpha_1+beta_1*Y.
Each Gj is the canonical linear-in-Y representation. The recurrence uses only
scalar linear combinations, so evaluating those linear polynomials at an
arbitrary Y=x^6 preserves the identity. It does not assume that the evaluation
point x is a root of M. In particular, it does not multiply unreduced
polynomials and then silently treat evaluation as a homomorphism on K.

`degree6FrobFactorized` starts from these G0/G1, uses trace 2*a and the signed
norm representative eta-p, and generates G2,...,G5. Its base expression is

    1-c6*(tau^6+x^6-18)-sum(j=1..5,cj*tau^j)
    =c0+18*c6-c6*x^6.

The function accumulates cj*Gj(x^6) against x^j and (eta*x)^j in their even
and odd buckets. The four reduced outputs therefore have precisely the four
Frobenius meanings above. Reusing x^6 is justified by eta^6=1. At c6=0
nothing is dropped; at x=0 all four outputs equal c0+18*c6.

The terminal source defines

    W(x)=Frob(S_c)(x)*Frob(S_c)(eta*x)
    R <- R*rho+F_plus*W(-z)-F_minus*W(z).

This explains the order and sign of all four consumed outputs. Each
Frobenius polynomial has degree at most 11 and W degree at most 22.

## Signed representatives and the final quotient predicate

Arithmetic congruence modulo the positive p is preserved by addition,
subtraction, multiplication and signed remainder. The source may defer a
MOD or use eta-p for eta. It need not produce the same signed integer as an
older expression. Its signed-range/ScriptNum and compiled-frame checks are
separate required obligations. A final remainder v modulo p satisfies
-p<v<p, so v congruent to zero is equivalent to literal integer zero. The
terminal accumulator is consumed by the final reduced zero predicate; a
serialization or ordering observation of its intermediate representative
would require a different argument.

The complete identity schedule supplies 34 polynomials with the separately
proved bounds deg(P)<=270, odd deg(D)<=275, and deg(D/M)<=263. Given their
zero residues for a valid supported proof, the weighted quotient is odd and
can be written q(X)=X*h(X^2), with h of degree at most 131. Its at-most-132
canonical words are serialized highest first. The zero quotient uses one
zero word; nonzero quotients have a nonzero highest word. These source
producer and parser rules must be joined to the actual accepted bytes.

The native Horner loop prepends at most three zero words to a multiple of
four. It updates

    acc <- acc*z^8+q0*z^6+q1*z^4+q2*z^2+q3

for each four-word block. Induction over highest-first blocks gives h(z^2);
leading zero words leave its value unchanged. RD checks every word below p.
The final source predicate is exactly

    rem_p(R-z*h(z^2)*(z^12-18*z^6+82)) == 0.

No cancellation or division by z occurs. z=0 is included in the sampling
root bound, and the canonical zero quotient remains permitted. This component
argument supplies the representative/evaluation/quotient algebra. Complete
soundness still needs the line/Miller/GLS identity and commit order, and full
canonical completeness still needs every factor, caller/transport, all-width
resource and memory obligation; the finite fixture corpus proves neither.
