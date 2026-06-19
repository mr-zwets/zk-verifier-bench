"""Independent oracle cross-validation of pairing-vectors.json via py_ecc.bn128.

py_ecc.bn128 IS BN254 / alt_bn128 (same p, r, G1, G2 as noble). This script:

  1. Reconstructs the SAME instance from the SCALARS in pairing-vectors.json
     (so it does not trust noble's serialized points — it rebuilds them).
  2. Confirms py_ecc's vk_x affine == noble's golden vkXAffine  (guards the MSM).
  3. Confirms the Groth16 product
        e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta)  == FQ12.one()
     for the VALID instance, and != one() for the INVALID (tampered input).
  4. Also rebuilds points from the SERIALIZED JSON and re-verifies (consistency).

This py_ecc build's pairing() always applies the final exponentiation and exposes
no pre-final-exp flag. The Groth16 check is basis-independent: the PRODUCT of the
four FINAL-exponentiated pairings equals FQ12.one() iff the sum of the pairing
exponents is 0 mod r (the verification equation) — equivalently, the pre-final-exp
Miller product final-exponentiates to 1.

NOTE on Fp12 bytes: py_ecc and noble can differ in internal Fp12 coordinate
bookkeeping, so we DO NOT compare millerHex byte-for-byte here. The basis-
independent invariants cross-checked are: vk_x (a G1 affine, representation-free)
and the verification verdict. See docs/pairing-checker.md for the basis analysis.
"""
import json
import os
import sys

from py_ecc.bn128 import (
    G1, G2, multiply, add, neg, pairing, FQ12, FQ, FQ2,
    curve_order, field_modulus,
)

# py_ecc's FQP.__pow__ is recursive (depth ~ bit length of the exponent, ~2900
# for the final-exp), which blows the interpreter recursion limit. Replace it
# with an iterative square-and-multiply that gives identical results.
from py_ecc.fields import field_elements as _fe


def _iter_pow(self, other):
    if other < 0:
        raise ValueError("negative exponent")
    result = type(self)([1] + [0] * (self.degree - 1))
    base = self
    e = int(other)
    while e > 0:
        if e & 1:
            result = result * base
        base = base * base
        e >>= 1
    return result


_fe.FQP.__pow__ = _iter_pow

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "pairing-vectors.json")

with open(VEC) as f:
    v = json.load(f)

p = field_modulus
r = curve_order
assert str(p) == v["p"], "field modulus mismatch noble vs py_ecc"
assert str(r) == v["r"], "scalar order mismatch noble vs py_ecc"

S = v["scalars"]
alpha_s = int(S["alpha"]); beta_s = int(S["beta"]); gamma_s = int(S["gamma"])
delta_s = int(S["delta"]); ic_s = [int(x) for x in S["ic"]]
a_s = int(S["a"]); b_s = int(S["b"]); c_s = int(S["c"]); vkx_s = int(S["vkx"])
inputs = [int(x) for x in v["publicInputs"]]


def compute_vkx(ic, inputs):
    acc = ic[0]
    for i, x in enumerate(inputs):
        acc = add(acc, multiply(ic[i + 1], x % r))
    return acc


def groth16_check(A, B, alpha, beta, vkx, gamma, C, delta):
    # product of e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) in GT (each
    # pairing() is final-exponentiated). Equals FQ12.one() iff the proof verifies.
    e1 = pairing(B, neg(A))
    e2 = pairing(beta, alpha)
    e3 = pairing(gamma, vkx)
    e4 = pairing(delta, C)
    return e1 * e2 * e3 * e4


def g1_from_json(o):
    return (FQ(int(o["x"])), FQ(int(o["y"])))


def g2_from_json(o):
    # JSON stores Fp2 coords as {c0, c1} == (real + imag*u). py_ecc FQ2 takes a
    # coeffs list [c0, c1] in the SAME (real, imag) order.
    x = FQ2([int(o["x"]["c0"]), int(o["x"]["c1"])])
    y = FQ2([int(o["y"]["c0"]), int(o["y"]["c1"])])
    return (x, y)


_result = {}


def run():
    # rebuild the instance independently from the scalars
    alpha = multiply(G1, alpha_s % r)
    beta = multiply(G2, beta_s % r)
    gamma = multiply(G2, gamma_s % r)
    delta = multiply(G2, delta_s % r)
    ic = [multiply(G1, s % r) for s in ic_s]
    A = multiply(G1, a_s % r)
    B = multiply(G2, b_s % r)
    C = multiply(G1, c_s % r)

    vkx = compute_vkx(ic, inputs)

    # (2) vk_x must match noble's golden, exactly (affine ints)
    nob = v["golden"]["vkXAffine"]
    vkx_x, vkx_y = int(vkx[0]), int(vkx[1])
    assert str(vkx_x) == nob["x"] and str(vkx_y) == nob["y"], (
        "VK_X DISAGREEMENT noble vs py_ecc:\n"
        f"  py_ecc x={vkx_x}\n  noble  x={nob['x']}\n"
        f"  py_ecc y={vkx_y}\n  noble  y={nob['y']}"
    )
    assert multiply(G1, vkx_s % r) == vkx, "vk_x scalar != MSM result (py_ecc)"

    # (3) valid instance: product of pairings == 1
    fe = groth16_check(A, B, alpha, beta, vkx, gamma, C, delta)
    valid_ok = (fe == FQ12.one())
    assert valid_ok, "PY_ECC: valid instance does NOT verify (product != FQ12.one())"

    # (3b) invalid instance: tamper public input -> product != 1
    inv_inputs = [int(x) for x in v["invalid"]["publicInputs"]]
    vkx_inv = compute_vkx(ic, inv_inputs)
    fe_inv = groth16_check(A, B, alpha, beta, vkx_inv, gamma, C, delta)
    invalid_rejects = (fe_inv != FQ12.one())
    assert invalid_rejects, "PY_ECC: invalid (tampered) instance unexpectedly verified"

    # (4) rebuild points from the SERIALIZED JSON and re-verify (consistency)
    A2 = g1_from_json(v["proof"]["a"]); B2 = g2_from_json(v["proof"]["b"]); C2 = g1_from_json(v["proof"]["c"])
    alpha2 = g1_from_json(v["vk"]["alpha"]); beta2 = g2_from_json(v["vk"]["beta"])
    gamma2 = g2_from_json(v["vk"]["gamma"]); delta2 = g2_from_json(v["vk"]["delta"])
    ic2 = [g1_from_json(o) for o in v["vk"]["ic"]]
    vkx2 = compute_vkx(ic2, inputs)
    serialized_vkx_ok = (int(vkx2[0]) == vkx_x and int(vkx2[1]) == vkx_y)
    serialized_valid_ok = (groth16_check(A2, B2, alpha2, beta2, vkx2, gamma2, C2, delta2) == FQ12.one())

    _result.update(
        vkx_x=vkx_x, vkx_y=vkx_y, valid_ok=valid_ok, invalid_rejects=invalid_rejects,
        serialized_vkx_ok=serialized_vkx_ok, serialized_valid_ok=serialized_valid_ok,
    )


run()

R = _result
ok = bool(R) and R["valid_ok"] and R["invalid_rejects"] and R["serialized_vkx_ok"] and R["serialized_valid_ok"]

print("=== py_ecc.bn128 independent cross-validation ===")
print(f"p,r match noble                         : True")
print(f"vk_x (from scalars) == noble golden     : True")
print(f"  vk_x.x = {R['vkx_x']}")
print(f"  vk_x.y = {R['vkx_y']}")
print(f"VALID  : product of pairings == one()   : {R['valid_ok']}")
print(f"INVALID: tampered input rejected        : {R['invalid_rejects']}")
print(f"serialized-point vk_x matches           : {R['serialized_vkx_ok']}")
print(f"serialized-point valid verifies         : {R['serialized_valid_ok']}")
print("\nPY_ECC AGREES WITH NOBLE:", ok)
sys.exit(0 if ok else 1)
