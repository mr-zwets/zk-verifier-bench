# Dynamic consumer identity — portable v2

Status: `PASS_CONDITIONAL_DYNAMIC_CONSUMER_IDENTITY`.

This portable note closes the dynamic consumer transition from the fixed raw/native table owners into the role-25 consumer. It deliberately separates the two theorem directions:

- Accepted-execution soundness assumes the existing parser/EA/tau/range, field, source-to-byte/lowering, caller, line-factor, and typed-RO contracts. It does not assume honest advice, an honest producer, canonical construction, or a resource bound.
- Canonical completeness/resource existence separately uses the existing normalized finite construction and its all-row resource contracts. That construction premise is not used in the accepted-execution implication.

The portable copy contains no private execution-receipt path. Runtime certificate provenance remains root-owned and separate.

## Source transition

The pinned source constructs `Sc = degree6Poly(rootWords,tau)` and initializes the value fold with `Fp=Sc(-z)` and `Fm=Sc(z)` (`protocol.mjs`, `startState`). `pneg(a)=a(-X)` is the pinned conjugation `sigma=Frob^6`. The accepted chart contract supplies `Sc(tau)=1`, so the class of `Sc` is defined in `K*/E*` for `K=Fp12` and `E=Fp6`.

For every event, `cPoly(sign)` selects `pneg(Sc)` for a positive NAF digit and `Sc` for a negative digit. Under the existing quotient/conjugation contract this contributes `[Sc]^-m`, where the pinned scalar is `m=6u+2`.

There are two distinct source uses of `W`:

1. At a nonterminal `runRange` boundary, the next committed state polynomial is evaluated at `+/-z` and used for the state handover before the next range.
2. At terminal `t:W`, `degree6FrobFactorized` evaluates `Frob(Sc)` at `+/-z` and `+/-eta*z`; the paired products are the terminal Frobenius `W` factors.

Only the second use supplies the exponent `[Sc]^(p+p^3)` in this identity. The first is a boundary-state handover and is not silently conflated with the terminal Frobenius evaluation.

At terminal `Pfin`, `psubst(Sc,ETA)` contributes `[Sc]^(p^2)`. The remaining non-c factors, `Rconst`, and the actual GLS fold are grouped into `g`, the actual raw product including its integer GLS exponents and Rconst correction. No claim identifies `[g]` with a raw pairing element in `K*/E*`.

The accepted constituent identity from the existing quotient-zero/line-factor contracts is therefore

```text
[g] * [Sc]^(-m+p^2) = [Sc]^(p+p^3).
```

Hence

```text
[g] = [Sc]^lambda,    lambda = m + p - p^2 + p^3.
```

For the pinned BN254 values, `lambda mod r = 0` and `p^6+1 mod r = 0`. Since the final-exponent image has order dividing `r`, `FE(g)=1`. The GLS step is used only through its stated integer congruence
`sum_i u_i*pi_i - PI_SUM_OFFSET = n (mod r)`; fixed-VK bilinearity then supplies the four-pair equation. No stronger K*/E* equality is asserted for GLS.

The source spans and shared five-row table inputs are recorded in `report-v2.json`. This proof remains conditional on the named existing contracts and makes no arbitrary-VK/advice, privacy, application, network, maintainer, official, qualification, score, or publication claim.
