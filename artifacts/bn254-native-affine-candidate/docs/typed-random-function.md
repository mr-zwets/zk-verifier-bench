# Degree-six BN254 sampling argument

This is a conditional mathematical lemma for the C7553/R61 fixed-VK verifier.
It supplies the adaptive sampling argument, not the other algebraic, compiled
execution, caller, completeness, resource, or application theorems. Its public
source anchors are `bn-native-sound/protocol.mjs` and `script.mjs` in the
reproduction source tree. The exact artifact identity is given in the claim
sheet. A written lemma and local constructive checks do not confer independent
external review or upstream admission.

## Polynomial premises

Let p be the BN254 base-field prime

    21888242871839275222246405745257275088696311157297823662689037894645226208583

and let M(X)=X^12-18X^6+82. The complete algebraic and acceptance-binding
argument must establish the following premises for every accepted execution;
they must not be inferred from an honest producer or from fixture acceptance.

1. The pre-rho committed data determine exactly 34 identity polynomials
   D_0,...,D_33 in Fp[X], each of degree at most 275. If the declared fixed-VK
   pairing equation is false, at least one residue D_j mod M is nonzero.
2. All three roles consume those same committed data and transcript. Their
   handovers are forced intermediate evaluations, not independently chosen
   post-challenge coefficients.
3. The complete quotient-bearing z-input has one checked parse. It fixes an
   odd polynomial q(X) of degree at most 263, with at most 132 canonical
   coefficient words. The canonical zero quotient is permitted. Acceptance
   implies F(z)=0 for the polynomial F defined below.
4. The digest inputs and source framing bind exactly the source streams and
   STMT. Primitive VM, lowering, authenticated graph, and commitment binding
   outside this experiment remain separately named premises. This lemma does
   not establish them by assuming soundness of the full verifier.

Put R_j=D_j mod M and

    R_rho(X)=sum(j=0..33, rho^(33-j) R_j(X)).

If the residue vector is nonzero, choose a coefficient position at which it
is nonzero. That coefficient in R_rho is a nonzero polynomial in rho of
degree at most 33: the distinct powers have the corresponding residue
coefficients. It therefore vanishes at at most 33 field values. The event
R_rho=0 is contained in that event; no independence of the coefficient
positions is needed.

After rho, q may depend on rho and every earlier oracle reply. Define

    F(X)=sum(j=0..33, rho^(33-j) D_j(X))-q(X)M(X).

When R_rho is nonzero, F is nonzero for every q, because its residue modulo
M is R_rho. Its degree is at most max(275,263+12)=275. Once q and all other
z-input bytes are fixed, at most 275 field elements can make F(z)=0.

## Reduction of a fresh digest

Set N=2^256. Interpret a fresh 256-bit digest as an unsigned little-endian
integer and reduce it modulo p. Since ceil(N/p)=6, every field element has
probability at most 6/N. Thus an eligible fresh rho query has probability at
most 198/N of annihilating a nonzero residue vector; an eligible fresh z
query with nonzero weighted residue has probability at most 1650/N of
hitting an acceptance root. These are unconditional probabilities of the
accepted event. No conditioning on z being nonzero is permitted or needed.

## Actual transcript and experiment

For native roles 0,1,2, the source transcript is

    d0=H(S0), d1=H(S1), d2=H(STMT || S2)
    DG=d0 || d1 || d2
    h0=H(TAG || DG)
    rhoRaw=H(h0 || "rho")
    zRaw=H(h0 || rhoRaw || ZT)

TAG is ASCII `BNMX3/DEGREE6-EVAL1` followed by the exact 32-byte VK digest.
The ASCII portion is 19 bytes; TAG is 51 bytes. The h0 input is 147 bytes,
with digest slots starting at 51,83,115. The rho input is 35 bytes. ZT is
the complete source-defined quotient-bearing tail, including its permitted
filler. rho and z are the reductions of the corresponding raw replies.
These query inputs, and the fixed role-stream parse, must be checked against
the exact source and bytes by the separate composition argument.

Model H as one random function with N equally likely replies. Let Q_RO>=1
bound all distinct oracle queries in the whole experiment, including setup,
precomputation, advice, discarded attempts, padding attempts, and final
verification. Repeated identical queries reuse the recorded reply. Arbitrary
H-dependent advice obtained outside that query accounting is not covered.
Ordinary code/DS commitment binding may instead remain a separate explicit
premise, with any required failure term stated separately. This is not a
zero-error theorem for the fixed SHA-256 function or a theorem conditioned on
one published transcript. Q_RO is distinct from the quotient polynomial q.

## Causal order for adaptive queries and input aliases

For each queried byte string v, record the union of these backward targets:

- its first and second 32-byte words, if len(v)>=64;
- its first 32-byte word, if len(v)=35 and its last three bytes are `rho`;
- its three digest slots at offsets 51,83,115, if len(v)=147 and it begins
  with the exact TAG.

There are at most six targets per query input. Before receiving the t-th
fresh reply, at most 6t targets have been recorded, including those in the
current input. A fresh reply matches one with probability at most 6t/N.
The probability of any backward match is at most

    3 Q_RO(Q_RO+1)/N <= 6 Q_RO^2/N.

Independently of this counting, the probability of a reply collision between
distinct queried inputs is at most Q_RO(Q_RO-1)/(2N).

Outside these events, every required typed dependency in a finally used
transcript points backward in first-query order. For example, if a rho
input had been queried before the input producing its h0, that later h0
reply would equal the earlier rho input's stored prefix, a backward match.
If the two inputs coincide, the current-input target rule covers the
self-edge. The same argument applies to the z input's first two words and
the h0 input's three stream-digest slots. Reply uniqueness supplies a unique
queried preimage for each required digest. Repeated queries do not create
new sampling events. Raw byte-string aliases between protocol uses require
no assumption of independent or disjoint oracles: these same typed edges
must obey the first-query argument.

Consequently, the first query producing a finally used rho has the committed
stream/statement preimages already fixed. The first query producing its z
has rhoRaw and its full quotient-bearing tail already fixed. Stream bytes
may depend on arbitrary earlier replies. q and filler may depend on rho
and all earlier replies. This does not alter their being fixed before the
respective fresh reply. A later reply that happens to equal an arbitrary
suffix is not a retroactive change to that suffix. Such equality is not a
typed dependency needed for the fixed-data inference; any resulting
polynomial coincidence is included in the root bounds above. No recommended
producer query order or honest-advice assumption is used.

## Adaptive union bound

At each fresh query inspect only its input and earlier transcript. A rho
query is eligible if its required committed preimages already exist. If its
residue vector is nonzero, its conditional probability, given that earlier
history and current input, of annihilating it is at most 198/N. Sum over at
most Q_RO such fresh queries to obtain 198 Q_RO/N.

A z query is eligible if its required preimages and complete quotient parse
already exist and the weighted residue is nonzero. Its F is then fixed and
nonzero before the reply, so its acceptance-root probability is at most
1650/N. Summing gives 1650 Q_RO/N. Different attempts may choose different
statements, q, filler, or earlier committed data. Their queries are already
counted in Q_RO; no additional number-of-attempts factor is omitted.

Do not condition either calculation on the absence of future collisions or
backward matches. Instead, any final false-equation acceptance satisfying
the stated owner premises falls in at least one of four counted events:
a backward match, a distinct-input reply collision, an eligible batch
annihilation, or an eligible evaluation root. Hence the total probability
is at most

    [6 Q_RO^2 + Q_RO(Q_RO-1)/2 + 1848 Q_RO] / 2^256
    <= (7 Q_RO^2 + 1848 Q_RO)/2^256,

clipped at 1. The lemma says nothing about circuit knowledge, application
privacy, arbitrary verifying keys, external assurance, or live-network
acceptance. The full verifier claim still needs every polynomial, parser,
commitment, role/caller, and final-residual premise listed above to be proved
for the exact C7553/R61 artifact.
