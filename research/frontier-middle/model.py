#!/usr/bin/env python3
"""Track 2 (frontier middle): hint-vs-compute cost model for Groth16 verifiers in BCH Script.

Inputs are the per-component profiles in work/frontier-middle/profile-{bn254,bls12381}
(libauth 3.1.0-next.8 op-cost attribution, static byte attribution). Every measured unit
cost below cites its profile row. Estimated (not measured) unit costs carry a band
(lo, hi multipliers) and are marked EST.

Two architecture families. Components are composable only inside a family:

  F12  "Fp12 world": the accumulator f is a real Fp12 element computed on-chain
       (singleton / minop lineage). Knobs: tower (reduced | lazy), accumulator
       (4 separate loops | 1 shared loop with e(alpha,beta) baked), terminal
       (final exponentiation | residue witness), G2 subgroup (walk | fused endpoint),
       vk_x method, per-pair G2 walk (projective on-chain | witnessed affine slopes |
       baked slope pile | baked lines), layout (rolled | unrolled), outlining.

  ZEV  "evaluation world": SI-GLS. f is never reduced on-chain; the Miller loop runs
       on evaluations at +-z, prover-supplied monic states are checked by one batched
       Schwartz-Zippel identity. Knobs: delta walk (baked slope pile | projective on-chain),
       B walk affine-witnessed segment (BLS) | projective, chunk length m (events per
       committed state), single input (bch-spec) | multi-input (native framing).

Effective size at budget looseness k (bch-2026 density, (41+len)*800*k per input):
    E_k = max(bytes, opCost / (800 k) - 41 * inputs)

Usage: python3 model.py [--json out.json] [--md out.md]
"""
import argparse
import itertools
import json
import math

KS = [1, 2, 5, 10, 25, 50, 100]
TODAY_BEST = {  # KB, from the Track 2 brief (current reviewed entries)
    "BN254": [27.6, 21.9, 21.9, 21.9, 21.9, 19.2, 9.6],
    "BLS12-381": [32.5, 26.5, 26.5, 26.5, 26.5, 24.8, 12.4],
}

# ---------------------------------------------------------------------------
# Unit costs. op in M op-cost, bytes in B. band = (lo, hi) multiplier on op (and
# on bytes where marked). MEAS = profile row; EST = estimate with the reasoning.
# ---------------------------------------------------------------------------
CURVES = {
    "BN254": dict(
        word=32, stmt=272, stmt_ws=320,
        n_dbl=65, n_add=21, n_frob=2, n_res_folds=21,      # NAF(6x+2): 65 doublings, 21 additions, 2 psi steps
        # ---- reduced tower: plain singleton (MEAS, profile-bn254 rows) ----
        red=dict(
            sqr=0.860,       # Fp12 squaring, 223.707M / 260
            dbl=0.276,       # pointDouble, 71.76M / 260
            add=0.381,       # pointAdd + NAF branch, 31.997M / 84
            line_dbl=0.565,  # mul034, 147.0M / 260
            line_add=0.578,  # 48.5M / 84
            frob_pair=2.33,  # final psi steps + per-pair stub, 9.314M / 4
            fp12mul=0.868,
            fe_easy=(5.339, 558), fe_hard=(146.299, 2536),
            subgroup_walk=(49.078, 925),
            inputs=(0.118, 213),
            code_core=770 + 772 + 395 + 194 + 53,  # helpers + millerSingle + line + pointAdd + stubs w/o VK consts
            vk_g2_consts=330,                       # beta, gamma, delta (G2, 3 x 110)
            product_code=204,
            # EST residue terminal in the reduced tower: 21 fp12Mul folds + 3 Frobenius + class compare
            res_fold_per_add=0.868, res_term=(3.0, 900, 384), res_band=(0.7, 1.5),
            pile_step=0.060, pile_band=(0.6, 1.5),
            loop_ev=0.0, loop_code=0,   # loop control already inside the measured rows
        ),
        # ---- lazy tower: minop (MEAS, profile-bn254 minop rows) ----
        lazy=dict(
            sqr=0.1764,          # fp12SqrSigned, 11.47M / 65
            line_unit=0.1387,    # lineUnitDirectInline, 36.59M / 264
            line_gen=0.175,      # EST general (non-unit) 034 sparse product, +~5 Fp2 muls (fp2Mul 12.3k)
            line_gen_band=(0.85, 1.25),
            wit_step=0.0937, wit_hint=66, wit_code=398,   # affine G2 with witnessed slopes, 8.249M / 88
            proj_dbl=0.180, proj_add=0.200, proj_band=(0.8, 1.25),  # EST: singleton 276k/381k x BLS lazy/reduced ratio 0.65/0.53
            proj_code=450, proj_code_band=(0.7, 1.4),
            pile_step=0.035, pile_band=(0.6, 1.6), pile_bytes=64, pile_code=150,
            baked_line_bytes=133,  # 23,420 B / 176 lines (4 Fp words + push headers)
            unit_line_kernel=1092, unit_coords=(0.059, 180, 99),
            gen_line_kernel=1200, gen_kernel_band=(0.8, 1.3),
            sqr_kernel=1239, helpers=423, torus_mul=187,
            res_fold_per_add=0.1806, res_term=(0.777, 1000, 198),
            endpoint=(0.254, 220),
            inputs=(0.082, 230),
            ab_const=(0.18, 198),       # baked e(alpha,beta) torus constant, 1 fp12MulTorus
            vk_g2_consts=256,           # gamma, delta affine G2 starts (EST for on-chain walks)
            unrolled_glue_ev=0.023, unrolled_glue_bytes_ev=195, unrolled_cleanup=(0.363, 3591),
            rolled_ev=0.045, rolled_band=(0.5, 2.0), rolled_code=700, rolled_code_band=(0.7, 1.5),
            rolled_cleanup=(0.05, 10),
        ),
        vkx=dict(
            jac=dict(op=35.533, worst=94.0, code=897, hint=0, hintw=0, band=(1, 1)),          # singleton (MEAS)
            glv_aff=dict(op=1.16, worst=9.16, code=1756, hint=1071, hintw=6787, band=(1, 1)),  # BN minop (MEAS)
            glv_jac=dict(op=1.9, worst=15.3, code=1500, hint=45, hintw=70, band=(0.7, 1.5)),  # EST port of BLS minop vk_x
        ),
        overhead_p2s=87, overhead_p2sh=63 + 35 + 9,
    ),
    "BLS12-381": dict(
        word=48, stmt=397, stmt_ws=448,
        n_dbl=64, n_add=5, n_frob=0, n_res_folds=6,   # |x| = 0xd201000000010000
        red=dict(
            sqr=1.3712, dbl=0.4295, add=0.6251, line_dbl=0.9365, line_add=0.9365,
            frob_pair=2.996,          # per-pair loop control / glue, 11.984M / 4
            fp12mul=1.397,
            fe_easy=(11.466, 568), fe_hard=(223.745, 2327),
            subgroup_walk=(0.0, 0),   # BLS singletons already use the psi endpoint of the (-A,B) walk
            inputs=(0.177 + 0.016 + 0.179, 108 + 194 + 50),
            code_core=714 + 839 + 388 + 189,
            vk_g2_consts=441,
            product_code=227,
            res_fold_per_add=1.397, res_term=(5.0, 1000, 576), res_band=(0.7, 1.5),
            pile_step=0.090, pile_band=(0.6, 1.5),
            loop_ev=0.0, loop_code=0,
        ),
        lazy=dict(
            sqr=0.4232,             # lazy fp12Sqr, 27.08M / 64
            line_unit=0.446,        # BLS minop line kernel is already general (projective lines)
            line_gen=0.446, line_gen_band=(1, 1),
            wit_step=0.190, wit_hint=96, wit_code=400,  # EST (not in the BLS minop)
            proj_dbl=0.2789, proj_add=0.330, proj_band=(1, 1),  # MEAS BLS minop (lazy, projective B walk)
            proj_code=0, proj_code_band=(1, 1),                 # bodies are in the 2,583 B prelude
            pile_step=0.070, pile_band=(0.6, 1.6), pile_bytes=96, pile_code=150,
            baked_line_bytes=294,   # 40,556 B / 138 lines (6 x 48 B + headers)
            unit_line_kernel=0, unit_coords=(0, 0, 0),
            gen_line_kernel=0, gen_kernel_band=(1, 1),
            sqr_kernel=0, helpers=2583, torus_mul=0,  # all 27 kernels in the prelude (MEAS)
            res_fold_per_add=2.494 / 6, res_term=(0.366, 654, 294),
            endpoint=(0.147, 239),
            inputs=(0.152 + 0.0106 + 0.0028 + 0.0416, 221 + 83),
            ab_const=(0.42, 300),   # EST torus constant + fold (BLS minop folds it into Rconst)
            vk_g2_consts=384,
            # unrolled site bytes (MEAS): sqr 20, dbl 16, add 32, runtime line 54, baked line 36 glue
            unrolled_glue_ev=0.0, unrolled_glue_bytes_ev=None, unrolled_cleanup=(0.0, 0),
            rolled_ev=0.060, rolled_band=(0.5, 2.0), rolled_code=900, rolled_code_band=(0.7, 1.5),
            rolled_cleanup=(0.05, 10),
        ),
        vkx=dict(
            straus=dict(op=10.884, worst=73.93, code=981, hint=0, hintw=0, band=(1, 1)),       # singleton (MEAS)
            glv_jac=dict(op=3.607, worst=29.13, code=1961, hint=56, hintw=117, band=(1, 1)),  # BLS minop (MEAS)
        ),
        overhead_p2s=87, overhead_p2sh=63 + 35 + 9,
    ),
}


class Acc:
    """Accumulates op / bytes with nominal, low and high values."""

    def __init__(self):
        self.op = [0.0, 0.0, 0.0]
        self.opw = 0.0  # extra op-cost at the worst-case proof
        self.code = [0.0, 0.0, 0.0]
        self.hint = 0.0
        self.hintw = 0.0
        self.rows = []

    def add(self, name, op=0.0, code=0.0, hint=0.0, band=(1, 1), cband=(1, 1), opw=0.0, hintw=0.0):
        self.op[0] += op
        self.op[1] += op * band[0]
        self.op[2] += op * band[1]
        self.code[0] += code
        self.code[1] += code * cband[0]
        self.code[2] += code * cband[1]
        self.hint += hint
        self.hintw += hintw
        self.opw += opw
        self.rows.append((name, round(op, 3), round(code), round(hint)))


# ---------------------------------------------------------------------------
# F12 family
# ---------------------------------------------------------------------------
def f12(curve, ch):
    C = CURVES[curve]
    T = C[ch["tower"]]
    a = Acc()
    nd, na, nf = C["n_dbl"], C["n_add"], C["n_frob"]
    steps = nd + na + nf
    lines_per_pair = steps
    events = nd + na
    lazy = ch["tower"] == "lazy"

    a.add("input checks", *T["inputs"])
    # G2 subgroup
    if ch["subgroup"] == "walk":
        a.add("G2 subgroup walk", *T["subgroup_walk"])
    else:
        if lazy:
            a.add("fused endpoint G2 check", *T["endpoint"])
        else:
            a.add("fused endpoint G2 check", 0.25 if curve == "BN254" else 0.0, 220 if curve == "BN254" else 0, band=(0.8, 2))
    v = C["vkx"][ch["vkx"]]
    a.add("vk_x " + ch["vkx"], v["op"], v["code"], v["hint"], band=v["band"], opw=v["worst"] - v["op"],
          hintw=v["hintw"] - v["hint"])

    # Accumulator squarings
    nacc = 4 if ch["acc"] == "sep4" else 1
    a.add("Fp12 squarings x%d" % (nd * nacc), nd * nacc * T["sqr"])

    # Pairs: (-A,B) runtime walk, (vk_x,gamma), (C,delta) fixed, and (alpha,beta) if sep4
    pairs = [("B", ch["B"]), ("gamma", ch["gamma"]), ("delta", ch["delta"])]
    if ch["acc"] == "sep4":
        pairs.append(("beta", "proj"))
    need_unit, need_gen = False, False
    for name, mode in pairs:
        if ch["tower"] == "red":
            # reduced tower: lines are general mul034; walks projective or pile
            line_op = nd * T["line_dbl"] + na * T["line_add"]
            if mode == "proj":
                walk_op = nd * T["dbl"] + na * T["add"]
                a.add("pair %s: proj walk + lines" % name, walk_op + line_op + T["frob_pair"])
            elif mode == "pile":
                a.add("pair %s: slope pile + lines" % name, line_op + T["frob_pair"] * 0.5 + steps * T["pile_step"],
                      steps * 64 + 150, band=(0.97, 1.05))
            else:
                raise ValueError("reduced tower supports proj|pile only")
            continue
        # lazy tower
        unit = mode in ("wit", "pile", "baked")
        if unit:
            need_unit = True
            lop, lband = lines_per_pair * T["line_unit"], (1, 1)
        else:
            need_gen = True
            lop, lband = lines_per_pair * T["line_gen"], T["line_gen_band"]
        a.add("pair %s: %d lines" % (name, lines_per_pair), lop, band=lband)
        if mode == "proj":
            a.add("pair %s: projective walk" % name, nd * T["proj_dbl"] + (na + nf) * T["proj_add"], band=T["proj_band"])
        elif mode == "wit":
            a.add("pair %s: witnessed affine walk" % name, steps * T["wit_step"], 0, steps * T["wit_hint"])
        elif mode == "pile":
            a.add("pair %s: slope pile + x/c recursion" % name, steps * T["pile_step"],
                  steps * T["pile_bytes"], band=T["pile_band"])
        elif mode == "baked":
            a.add("pair %s: baked lines" % name, 0, lines_per_pair * T["baked_line_bytes"])
    if lazy:
        if need_unit and T["unit_line_kernel"]:
            a.add("unit line kernel + unit coords", T["unit_coords"][0], T["unit_line_kernel"] + T["unit_coords"][1],
                  T["unit_coords"][2])
        if need_gen and T["gen_line_kernel"]:
            a.add("general 034 line kernel", 0, T["gen_line_kernel"], cband=T["gen_kernel_band"])
        if any(m == "proj" for _, m in pairs):
            a.add("projective G2 kernels", 0, T["proj_code"], cband=T["proj_code_band"])
        if any(m == "wit" for _, m in pairs):
            a.add("affine witnessed G2 kernels", 0, T["wit_code"])
        if any(m == "pile" for _, m in pairs):
            a.add("pile recursion code", 0, T["pile_code"])
        a.add("tower kernels (sqr, helpers, torus mul)", 0, T["sqr_kernel"] + T["helpers"] + T["torus_mul"])
    else:
        a.add("reduced tower code (helpers, miller, line, add)", 0, T["code_core"])

    # alpha-beta and products
    if ch["acc"] == "sep4":
        a.add("product of 4 Miller values", 3 * T["fp12mul"], T["product_code"])
        a.add("VK G2 constants (beta, gamma, delta)", 0, T["vk_g2_consts"])
    else:
        if lazy and ch["gamma"] == "baked" and ch["delta"] == "baked":
            pass  # minop: the e(alpha,beta) fold constant is inside the measured baked-line rows
        elif lazy:
            a.add("baked e(alpha,beta) constant", *T["ab_const"])
        else:
            a.add("baked e(alpha,beta) constant", T["fp12mul"], 12 * C["word"] + 20)
        a.add("VK G2 constants (gamma, delta walk starts)", 0,
              T["vk_g2_consts"] if lazy else T["vk_g2_consts"] * 2 // 3)

    # terminal
    if ch["term"] == "fe":
        a.add("final exp easy", *T["fe_easy"])
        a.add("final exp hard", *T["fe_hard"])
    else:
        rb = T.get("res_band", (1, 1))
        a.add("residue c-folds", C["n_res_folds"] * T["res_fold_per_add"], band=rb)
        a.add("residue terminal", T["res_term"][0], T["res_term"][1], T["res_term"][2], band=rb)

    # layout
    if lazy:
        if ch["layout"] == "unrolled":
            if curve == "BN254":
                a.add("unrolled glue", events * T["unrolled_glue_ev"], events * T["unrolled_glue_bytes_ev"])
            else:  # BLS minop site glue (MEAS per site)
                glue = sum(lines_per_pair * (36 if m == "baked" else 54) for _, m in pairs)
                a.add("unrolled site glue", 0, nd * 20 + nd * 16 + na * 32 + glue + 552)
            a.add("unrolled cleanup", *T["unrolled_cleanup"])
        else:
            a.add("rolled loop", events * T["rolled_ev"], T["rolled_code"], band=T["rolled_band"],
                  cband=T["rolled_code_band"])
            a.add("cleanup", *T["rolled_cleanup"])
    if ch["outline"]:
        # MEAS on the reduced singletons: BN code x0.749 / op +3.7%, BLS code x0.785 / op +0.9%.
        # EST for the lazy kernels (already factored into functions): code x0.85, op +3%.
        s = 0.85 if lazy else (0.749 if curve == "BN254" else 0.785)
        o = 0.03 if lazy else (0.037 if curve == "BN254" else 0.009)
        dcode = [c * (s - 1) for c in a.code]
        a.code = [a.code[0] * s, a.code[1] * (s - 0.05), a.code[2] * min(1.0, s + 0.07)]
        a.op = [a.op[0] * (1 + o), a.op[1] * (1 + o / 3), a.op[2] * (1 + o * 1.5)]
        a.rows.append(("outlining (recompiler)", "x%.3f" % (1 + o), round(dcode[0]), 0))

    overhead = C["overhead_p2sh"] if ch.get("p2sh", True) else C["overhead_p2s"]
    stmt = C["stmt"]
    return finish(curve, "F12", ch, a, overhead + stmt, inputs=1)


# ---------------------------------------------------------------------------
# ZEV family (SI-GLS / native), measured totals plus deltas
# ---------------------------------------------------------------------------
ZEV_BASE = {
    # (op M, bytes, inputs, delta row op, delta row code, n delta dbl, n delta add-like,
    #  B dbl event op, B add event op, boundary op, boundary bytes, n boundaries, quotient words, word bytes)
    ("BN254", "single"): dict(op=23.337, bytes=21915, inputs=1, d_op=4.263, d_code=5858, d_dbl=65, d_add=23,
                              bdbl=0.143, badd=0.185, bnd_op=0.0475, bnd_bytes=192, nbnd=33, nq=114, qop=0.00657,
                              maxdeg_ev=(66, 90), affB=None),
    ("BN254", "native"): dict(op=20.573, bytes=27624, inputs=3, d_op=4.219, d_code=5827, d_dbl=65, d_add=23,
                              bdbl=0.143, badd=0.185, bnd_op=0.0408, bnd_bytes=192, nbnd=33, nq=114, qop=0.00661,
                              maxdeg_ev=(66, 90),
                              # native B walk is affine with inverse-norm witnesses t (65 x 32 + 21 x 32 B);
                              # projective = SI-GLS kernels (BDBL 454 + BADD 590) replacing affine (319 + 296)
                              affB=dict(hint=2080 + 672, op_to_proj=65 * (0.143 - 0.1077) + 21 * (0.200 - 0.1085),
                                        code=-430)),
    ("BLS12-381", "single"): dict(op=26.071, bytes=26484, inputs=1, d_op=5.611, d_code=6769, d_dbl=64, d_add=4,
                                  bdbl=0.2336, badd=0.3326, bnd_op=0.0588, bnd_bytes=288, nbnd=32, nq=47, qop=0.00896,
                                  maxdeg_ev=(60, 84),
                                  affB=dict(hint=1248, op_to_proj=10 * (0.2336 - 0.1526) + 3 * (0.3326 - 0.1535),
                                            code=250)),
    ("BLS12-381", "native"): dict(op=24.040, bytes=34229, inputs=4, d_op=5.604, d_code=7290, d_dbl=64, d_add=4,
                                  bdbl=0.2336, badd=0.3326, bnd_op=0.0545, bnd_bytes=288, nbnd=32, nq=45, qop=0.0094,
                                  maxdeg_ev=(60, 84),
                                  affB=dict(hint=6048 + 480, op_to_proj=63 * (0.2336 - 0.1475) + 5 * (0.3326 - 0.1508),
                                            code=-300)),  # projective kernels added to the blob
}


def zev(curve, ch):
    b = ZEV_BASE[(curve, ch["host"])]
    a = Acc()
    a.add("measured base (%s %s)" % (curve, ch["host"]), b["op"], b["bytes"])
    if ch["delta"] == "proj":
        # A projective delta step = the B event kernel minus the F^2 / S_c parts it does not need.
        dop = b["d_dbl"] * (b["bdbl"] - 0.008 * (1.6 if curve != "BN254" else 1)) + b["d_add"] * (b["badd"] - 0.010)
        a.add("delta: drop baked slope pile", -b["d_op"], -b["d_code"])
        a.add("delta: projective walk on-chain (B kernel reused)", dop, 300, band=(0.85, 1.2), cband=(0.6, 1.6))
        a.add("delta: projective delta lines raise max chunk degree (+~3 quotient words)", 3 * b["qop"],
              3 * (32 if curve == "BN254" else 48))
    if ch["Baff"] == "proj" and b["affB"]:
        a.add("B walk: all projective (drop witnessed affine slopes)", b["affB"]["op_to_proj"], -b["affB"]["code"],
              -b["affB"]["hint"], band=(0.8, 1.2))
    # chunk length m (events per committed state); m = 2 is the shipped design.
    m = ch["m"]
    if m != 2:
        ev = b["d_dbl"]
        dmin, dadd = b["maxdeg_ev"]

        def maxdeg(mm):  # S^(2^mm) * worst arrangement: additions first
            return 6 * 2 ** mm + sum(dadd * 2 ** j for j in range(mm))

        nq_new = b["nq"] * maxdeg(m) / maxdeg(2)
        nb_new = math.ceil(ev / m) + 1
        wb = 32 if curve == "BN254" else 48
        a.add("chunk m=%d: boundaries %d -> %d" % (m, b["nbnd"], nb_new), (nb_new - b["nbnd"]) * b["bnd_op"],
              0, (nb_new - b["nbnd"]) * b["bnd_bytes"])
        a.add("chunk m=%d: quotient %d -> %d words" % (m, b["nq"], nq_new), (nq_new - b["nq"]) * b["qop"], 0,
              (nq_new - b["nq"]) * wb, band=(0.8, 1.2))
    return finish(curve, "ZEV", ch, a, 0, inputs=b["inputs"])


def finish(curve, fam, ch, a, fixed_bytes, inputs):
    bytes_nom = fixed_bytes + a.code[0] + a.hint
    bytes_lo = fixed_bytes + a.code[1] + a.hint
    bytes_hi = fixed_bytes + a.code[2] + a.hint
    d = dict(curve=curve, family=fam, choice=ch, inputs=inputs,
             bytes=round(bytes_nom), bytes_lo=round(min(bytes_lo, bytes_hi)), bytes_hi=round(max(bytes_lo, bytes_hi)),
             bytes_worst=round(bytes_nom + a.hintw),
             op=round(a.op[0], 3), op_lo=round(min(a.op[1], a.op[2]), 3), op_hi=round(max(a.op[1], a.op[2]), 3),
             op_worst=round(a.op[0] + a.opw, 3), rows=a.rows)
    d["eff"] = {k: eff(d["bytes"], d["op"], inputs, k) for k in KS}
    d["eff_hi"] = {k: eff(d["bytes_hi"], d["op_hi"], inputs, k) for k in KS}
    d["eff_lo"] = {k: eff(d["bytes_lo"], d["op_lo"], inputs, k) for k in KS}
    d["per_input_script"] = round(d["bytes"] / inputs)
    d["fits_bch2026_size"] = (d["bytes"] - 98) / inputs <= 10000
    unlock = d["bytes"] - 98 * inputs
    d["k_min_bch2026"] = round(d["op"] * 1e6 / ((41 + unlock / inputs) * 800 * inputs), 2)
    d["k_min_bchspec"] = round(d["op"] * 1e6 / ((10000 + unlock / inputs) * 800 * inputs), 2)
    return d


def eff(b, opm, n, k):
    return max(b, opm * 1e6 / (800 * k) - 41 * n) / 1000.0


# ---------------------------------------------------------------------------
# Measured entries (for validation and the frontier)
# ---------------------------------------------------------------------------
MEASURED = {
    "BN254": [
        ("singleton (plain)", 8206, 771.300, 1, 831.0),
        ("singleton-opcode-optimized", 6237, 800.155, 1, 855.0),
        ("singleton-minop", 58073, 64.840, 1, 72.8),
        ("sound-si-gls-single (bch-spec)", 21915, 23.337, 1, 23.348),
        ("bn254-sound-native", 27624, 20.573, 3, 20.8),
    ],
    "BLS12-381": [
        ("singleton (plain)", 7510, 994.590, 1, 1057.6),
        ("singleton-opcode-optimized", 5999, 1003.512, 1, 1066.3),
        ("singleton-minop", 58841, 145.597, 1, 171.1),
        ("sound-si-gls-single (bch-spec)", 26484, 26.071, 1, 27.484),
        ("bls12381-sound-native", 34229, 24.040, 4, 26.009),
    ],
}

VALIDATE = {
    "BN254": [
        ("singleton (plain)", dict(tower="red", acc="sep4", term="fe", subgroup="walk", vkx="jac", B="proj",
                                   gamma="proj", delta="proj", layout="rolled", outline=False, p2sh=False)),
        ("singleton-opcode-optimized", dict(tower="red", acc="sep4", term="fe", subgroup="walk", vkx="jac", B="proj",
                                            gamma="proj", delta="proj", layout="rolled", outline=True, p2sh=False)),
        ("singleton-minop", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_aff", B="wit",
                                 gamma="baked", delta="baked", layout="unrolled", outline=False, p2sh=False)),
    ],
    "BLS12-381": [
        ("singleton (plain)", dict(tower="red", acc="sep4", term="fe", subgroup="endpoint", vkx="straus", B="proj",
                                   gamma="proj", delta="proj", layout="rolled", outline=False, p2sh=False)),
        ("singleton-opcode-optimized", dict(tower="red", acc="sep4", term="fe", subgroup="endpoint", vkx="straus",
                                            B="proj", gamma="proj", delta="proj", layout="rolled", outline=True,
                                            p2sh=False)),
        ("singleton-minop", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                                 gamma="baked", delta="baked", layout="unrolled", outline=False, p2sh=False)),
    ],
}


def enumerate_designs(curve):
    out = []
    vk = list(CURVES[curve]["vkx"].keys())
    for tower, acc, term, vkx, B, g, dl, layout, outline in itertools.product(
            ["red", "lazy"], ["sep4", "shared"], ["fe", "res"], vk, ["proj", "wit"], ["proj", "pile", "baked"],
            ["proj", "pile", "baked"], ["rolled", "unrolled"], [False, True]):
        if tower == "red" and (B == "wit" or g == "baked" or dl == "baked" or layout == "unrolled"):
            continue
        if tower == "lazy" and (acc == "sep4" or term == "fe"):
            continue  # lazy tower only in the shared/residue form (minop lineage)
        if acc == "sep4" and term == "res":
            continue
        if acc == "sep4" and (g != "proj" or dl != "proj"):
            continue
        sub = "walk" if (curve == "BN254" and term == "fe") else "endpoint"
        ch = dict(tower=tower, acc=acc, term=term, subgroup=sub, vkx=vkx, B=B, gamma=g, delta=dl, layout=layout,
                  outline=outline, p2sh=True)
        out.append(f12(curve, ch))
    for host in ["single", "native"]:
        for d in ["pile", "proj"]:
            for baff in ["keep", "proj"]:
                if baff == "proj" and not ZEV_BASE[(curve, host)]["affB"]:
                    continue
                for m in [1, 2, 3, 4]:
                    out.append(zev(curve, dict(host=host, delta=d, Baff=baff, m=m)))
    return out


def label(d):
    c = d["choice"]
    if d["family"] == "ZEV":
        return "ZEV/%s delta=%s B=%s m=%d" % (c["host"], c["delta"], c["Baff"], c["m"])
    return "F12/%s %s %s vkx=%s B=%s g=%s d=%s %s%s" % (c["tower"], c["acc"], c["term"], c["vkx"], c["B"], c["gamma"],
                                                       c["delta"], c["layout"], " +outline" if c["outline"] else "")


def pareto(points):
    pts = sorted(points, key=lambda p: (p["bytes"], p["op"]))
    front, best = [], float("inf")
    for p in pts:
        if p["op"] < best - 1e-9:
            front.append(p)
            best = p["op"]
    return front


NAMED = {
    "BN254": {
        "T1 SI-GLS + on-chain projective delta walk": ("zev", dict(host="single", delta="proj", Baff="keep", m=2)),
        "T2 rolled lazy-tower residue singleton (all walks projective, GLV-Jacobian vk_x)":
            ("f12", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                         gamma="proj", delta="proj", layout="rolled", outline=False, p2sh=True)),
        "T2+outline (recompiler pass)":
            ("f12", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                         gamma="proj", delta="proj", layout="rolled", outline=True, p2sh=True)),
        "T2 with delta slope pile (build flag)":
            ("f12", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                         gamma="proj", delta="pile", layout="rolled", outline=False, p2sh=True)),
        "R reduced-tower residue singleton (plain singleton minus FE/subgroup walk/4 loops)":
            ("f12", dict(tower="red", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                         gamma="proj", delta="proj", layout="rolled", outline=True, p2sh=True)),
        "native + on-chain projective delta (multi-input, bch-2026 sizes)":
            ("zev", dict(host="native", delta="proj", Baff="keep", m=2)),
        "native + on-chain projective delta + projective B (multi-input, bch-2026 sizes)":
            ("zev", dict(host="native", delta="proj", Baff="proj", m=2)),
        "rolled minop with slope piles (hint-heavy F12)":
            ("f12", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_aff", B="wit",
                         gamma="pile", delta="pile", layout="rolled", outline=False, p2sh=True)),
    },
    "BLS12-381": {
        "T1 SI-GLS + on-chain projective delta walk + all-projective B":
            ("zev", dict(host="single", delta="proj", Baff="proj", m=2)),
        "T1a SI-GLS + on-chain projective delta walk (keep affine B segment)":
            ("zev", dict(host="single", delta="proj", Baff="keep", m=2)),
        "T2 rolled minop: gamma/delta lines computed on-chain (projective)":
            ("f12", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                         gamma="proj", delta="proj", layout="rolled", outline=False, p2sh=True)),
        "T2+outline (recompiler pass)":
            ("f12", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                         gamma="proj", delta="proj", layout="rolled", outline=True, p2sh=True)),
        "R reduced-tower residue singleton":
            ("f12", dict(tower="red", acc="shared", term="res", subgroup="endpoint", vkx="straus", B="proj",
                         gamma="proj", delta="proj", layout="rolled", outline=True, p2sh=True)),
        "native + on-chain projective delta + projective B (multi-input, bch-2026 sizes)":
            ("zev", dict(host="native", delta="proj", Baff="proj", m=2)),
        "rolled minop with baked lines as data (hint-heavy F12)":
            ("f12", dict(tower="lazy", acc="shared", term="res", subgroup="endpoint", vkx="glv_jac", B="proj",
                         gamma="baked", delta="baked", layout="rolled", outline=False, p2sh=True)),
    },
}


def named_section(curve, out, md):
    md.append("### Named designs\n")
    md.append("| design | bytes (lo-hi) | op M (lo-hi) | worst op M | in | per-input script <=10 kB | k_min bch-2026 | k_min bch-spec | " +
              " | ".join("E%d" % k for k in KS) + " |")
    md.append("|---|--:|--:|--:|--:|---|--:|--:|" + "--:|" * len(KS))
    for name, (fam, ch) in NAMED[curve].items():
        d = zev(curve, ch) if fam == "zev" else f12(curve, ch)
        d["label"] = name
        out["named"][curve + ":" + name] = d
        md.append("| %s | %d (%d-%d) | %.1f (%.1f-%.1f) | %.1f | %d | %s | %.2f | %.2f | %s |" % (
            name, d["bytes"], d["bytes_lo"], d["bytes_hi"], d["op"], d["op_lo"], d["op_hi"], d["op_worst"],
            d["inputs"], "yes" if d["fits_bch2026_size"] else "no (bch-spec)", d["k_min_bch2026"], d["k_min_bchspec"],
            " | ".join("%.1f" % d["eff"][k] for k in KS)))
    md.append("")
    for name, (fam, ch) in NAMED[curve].items():
        if not name.startswith(("T1 ", "T2 ")):
            continue
        d = out["named"][curve + ":" + name]
        md.append("#### %s: component rows (op M, code B, hint B)\n" % name)
        md.append("| row | op M | code B | hint B |\n|---|--:|--:|--:|")
        for r in d["rows"]:
            md.append("| %s | %s | %s | %s |" % r)
        md.append("")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--md")
    args = ap.parse_args()
    out = {"validation": {}, "frontier": {}, "best": {}, "named": {}}
    md = []
    for curve in CURVES:
        md.append("## %s\n" % curve)
        md.append("### Validation (model vs measured)\n\n| entry | model B | meas B | model op M | meas op M |\n|---|--:|--:|--:|--:|")
        meas = {m[0]: m for m in MEASURED[curve]}
        for name, ch in VALIDATE[curve]:
            d = f12(curve, ch)
            out["validation"][curve + ":" + name] = d
            md.append("| %s | %d | %d | %.1f | %.1f |" % (name, d["bytes"], meas[name][1], d["op"], meas[name][2]))
        md.append("")
        designs = enumerate_designs(curve)
        pts = designs + [dict(curve=curve, family="MEAS", label=m[0], bytes=m[1], op=m[2], inputs=m[3],
                              op_worst=m[4], bytes_lo=m[1], bytes_hi=m[1], op_lo=m[2], op_hi=m[2],
                              eff={k: eff(m[1], m[2], m[3], k) for k in KS},
                              eff_hi={k: eff(m[1], m[2], m[3], k) for k in KS}) for m in MEASURED[curve]]
        for p in pts:
            p.setdefault("label", label(p) if p["family"] != "MEAS" else p.get("label"))
        front = pareto(pts)
        out["frontier"][curve] = [{k: p[k] for k in ("label", "bytes", "op", "inputs", "bytes_lo", "bytes_hi", "op_lo",
                                                     "op_hi", "op_worst")} for p in front]
        md.append("### Predicted Pareto set (bytes, op-cost), nominal\n\n| design | bytes (lo-hi) | op M (lo-hi) | worst-proof op M | inputs |\n|---|--:|--:|--:|--:|")
        for p in front:
            md.append("| %s | %d (%d-%d) | %.1f (%.1f-%.1f) | %.1f | %d |" % (
                p["label"], p["bytes"], p["bytes_lo"], p["bytes_hi"], p["op"], p["op_lo"], p["op_hi"],
                p.get("op_worst", p["op"]), p["inputs"]))
        md.append("")
        md.append("### Best effective size per k (KB): predicted (pessimistic band) vs today\n\n| k | today | predicted best | design | pessimistic | change |\n|--:|--:|--:|---|--:|--:|")
        best = {}
        for i, k in enumerate(KS):
            p = min(pts, key=lambda q: q["eff"][k])
            today = TODAY_BEST[curve][i]
            v = min(p["eff"][k], today)
            best[k] = dict(design=p["label"], eff=p["eff"][k], eff_hi=p["eff_hi"][k], today=today)
            md.append("| %d | %.1f | %.1f | %s | %.1f | %+.0f%% |" % (k, today, v, p["label"] if p["eff"][k] < today else "(today's entry)",
                                                                  min(p["eff_hi"][k], today), 100 * (v / today - 1)))
        out["best"][curve] = best
        md.append("")
        named_section(curve, out, md)
    if args.json:
        json.dump(out, open(args.json, "w"), indent=1, default=str)
    text = "\n".join(md)
    if args.md:
        open(args.md, "w").write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
