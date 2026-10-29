// Track 6 design probe: a reference re-implementation of gnark v0.16.4's BN254 PLONK verifier (verify.go +
// kzg.FoldProof + kzg.BatchVerifyMultiPoints) written the way the CashVM verifier will compute it:
//   - the SHA-256 Fiat-Shamir transcript rebuilt byte for byte from raw (big-endian) proof/VK bytes;
//   - one witnessed batch inverse for the Lagrange denominators;
//   - KZG multi-point batching with OUR deterministic u = u1 + lambda_GLV*u2 (u1, u2 < 2^64) in place of gnark's
//     verifier-side random number (the prover never sees u, so proofs are unchanged);
//   - plan B: Lambda (the linearised-polynomial commitment) taken as a witness, hashed into v, and its correctness
//     folded into P_left with a 128-bit t: P* = rest + t*MSM_lin + (1 - t)*Lambda';
//   - the final check as ONE 2-pairing product with fixed G2 arguments: e(P_left, [1]_2) e(P_right, [x]_2) == 1.
//
// It proves a toy circuit with gnark (unsafekzg test SRS: toxic waste known, testing only), checks that gnark and
// this reference agree on the honest proof, and that both reject simple tampered proofs (plain rejection tests).
// Output: a JSON fixture (raw proof, VK, public inputs, challenges, MSM scalars, P_left/P_right) on stdout.
//
//	GOMAXPROCS=4 nice go run . > fixture.json
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Toy statement with two public inputs (like the Groth16 fixtures' n0, n1): x^3 + x + 5 == Y and x*Y == Z.
type Circuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(api.Add(x3, c.X, 5), c.Y)
	api.AssertIsEqual(api.Mul(c.X, c.Y), c.Z)
	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func raw(p *curve.G1Affine) []byte { b := p.RawBytes(); return b[:] }
func frb(x *fr.Element) []byte     { b := x.Bytes(); return b[:] }
func hx(b []byte) string           { return hex.EncodeToString(b) }
func cat(parts ...[]byte) []byte {
	var o []byte
	for _, p := range parts {
		o = append(o, p...)
	}
	return o
}
func chal(b []byte) fr.Element { var e fr.Element; e.SetBytes(b); return e } // BE(digest) mod r, as gnark
func msm(pts []curve.G1Affine, sc []fr.Element) curve.G1Affine {
	var r curve.G1Affine
	_, err := r.MultiExp(pts, sc, ecc.MultiExpConfig{})
	must(err)
	return r
}

// GLV constants for BN254 G1: phi(x, y) = (beta x, y) = [lambda](x, y)
func glv() (lambda fr.Element, beta fp.Element) {
	sqrtR := new(big.Int).ModSqrt(new(big.Int).Sub(fr.Modulus(), big.NewInt(3)), fr.Modulus())
	sqrtP := new(big.Int).ModSqrt(new(big.Int).Sub(fp.Modulus(), big.NewInt(3)), fp.Modulus())
	_, _, g1, _ := curve.Generators()
	for _, sr := range []int{1, -1} {
		for _, sp := range []int{1, -1} {
			l := new(big.Int).Mul(big.NewInt(int64(sr)), sqrtR)
			l.Sub(l, big.NewInt(1)).Mul(l, new(big.Int).ModInverse(big.NewInt(2), fr.Modulus())).Mod(l, fr.Modulus())
			b := new(big.Int).Mul(big.NewInt(int64(sp)), sqrtP)
			b.Sub(b, big.NewInt(1)).Mul(b, new(big.Int).ModInverse(big.NewInt(2), fp.Modulus())).Mod(b, fp.Modulus())
			var lp curve.G1Affine
			lp.ScalarMultiplication(&g1, l)
			var bx fp.Element
			bx.SetBigInt(b)
			bx.Mul(&bx, &g1.X)
			if lp.X.Equal(&bx) && lp.Y.Equal(&g1.Y) {
				lambda.SetBigInt(l)
				beta.SetBigInt(b)
				return
			}
		}
	}
	panic("glv")
}

type Out struct {
	Gnark      string             `json:"gnark"`
	Circuit    string             `json:"circuit"`
	SRS        string             `json:"srs"`
	Size       uint64             `json:"domainSize"`
	NbPublic   uint64             `json:"nbPublic"`
	ProofBytes int                `json:"gnarkProofRawBytes"`
	Hex        map[string]string  `json:"hex"`
	Checks     map[string]bool    `json:"checks"`
	Tamper     map[string][2]bool `json:"tamperRejected"`
}

// ref verifies (proof, vk, pub) the CashVM way; lambdaW is plan B's witnessed Lambda (nil: honest MSM value).
// Returns accept and a map of intermediates (hex).
func ref(proof *plonkbn.Proof, vk *plonkbn.VerifyingKey, pub []fr.Element, lambdaW *curve.G1Affine) (bool, map[string]string) {
	H := map[string]string{}
	for _, p := range append(append([]curve.G1Affine{}, proof.LRO[:]...), proof.Z, proof.H[0], proof.H[1], proof.H[2], proof.BatchedProof.H, proof.ZShiftedOpening.H) {
		if !p.IsOnCurve() || p.IsInfinity() { // cofactor 1: on-curve == in G1; infinity rejected (honest probability negligible)
			return false, H
		}
	}
	vkpts := cat(raw(&vk.S[0]), raw(&vk.S[1]), raw(&vk.S[2]), raw(&vk.Ql), raw(&vk.Qr), raw(&vk.Qm), raw(&vk.Qo), raw(&vk.Qk))
	var pis []byte
	for i := range pub {
		pis = append(pis, frb(&pub[i])...)
	}
	sum := func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	gR := sum(cat([]byte("gamma"), vkpts, pis, raw(&proof.LRO[0]), raw(&proof.LRO[1]), raw(&proof.LRO[2])))
	bR := sum(cat([]byte("beta"), gR))
	aR := sum(cat([]byte("alpha"), bR, raw(&proof.Z)))
	zR := sum(cat([]byte("zeta"), aR, raw(&proof.H[0]), raw(&proof.H[1]), raw(&proof.H[2])))
	gamma, beta, alpha, zeta := chal(gR), chal(bR), chal(aR), chal(zR)
	H["gamma_raw"], H["beta_raw"], H["alpha_raw"], H["zeta_raw"] = hx(gR), hx(bR), hx(aR), hx(zR)

	one := fr.One()
	var zn, zh fr.Element
	zn.Exp(zeta, new(big.Int).SetUint64(vk.Size))
	zh.Sub(&zn, &one)
	// one witnessed inverse for prod_i (zeta - omega^i), i < nPI (i = 0 is also L1's denominator)
	dens := make([]fr.Element, len(pub))
	var w, prod fr.Element
	w.SetOne()
	prod.SetOne()
	for i := range pub {
		dens[i].Sub(&zeta, &w)
		prod.Mul(&prod, &dens[i])
		w.Mul(&w, &vk.Generator)
	}
	var inv fr.Element
	inv.Inverse(&prod) // on-chain: witness, check prod * inv == 1, inv < r
	H["batch_inverse_witness"] = hx(frb(&inv))
	invs := make([]fr.Element, len(pub)) // Montgomery back-substitution
	acc := inv
	for i := len(pub) - 1; i >= 0; i-- {
		var pre fr.Element
		pre.SetOne()
		for j := 0; j < i; j++ {
			pre.Mul(&pre, &dens[j])
		}
		invs[i].Mul(&acc, &pre)
		acc.Mul(&acc, &dens[i])
	}
	var l1, pi, t fr.Element
	l1.Mul(&zh, &invs[0]).Mul(&l1, &vk.SizeInv)
	w.SetOne()
	for i := range pub {
		t.Mul(&zh, &invs[i]).Mul(&t, &vk.SizeInv).Mul(&t, &w).Mul(&t, &pub[i])
		pi.Add(&pi, &t)
		w.Mul(&w, &vk.Generator)
	}
	cv := proof.BatchedProof.ClaimedValues
	l, r, o, s1, s2, zu := cv[1], cv[2], cv[3], cv[4], cv[5], proof.ZShiftedOpening.ClaimedValue
	var a2l1, constLin, tmp fr.Element
	a2l1.Mul(&l1, &alpha).Mul(&a2l1, &alpha)
	constLin.Mul(&beta, &s1).Add(&constLin, &gamma).Add(&constLin, &l)
	tmp.Mul(&s2, &beta).Add(&tmp, &gamma).Add(&tmp, &r)
	constLin.Mul(&constLin, &tmp)
	tmp.Add(&o, &gamma)
	constLin.Mul(&tmp, &constLin).Mul(&constLin, &alpha).Mul(&constLin, &zu)
	constLin.Sub(&constLin, &a2l1).Add(&constLin, &pi).Neg(&constLin)
	lin := constLin // ClaimedValues[0] is determined; the CashVM verifier recomputes it (gnark compares)
	if !lin.Equal(&cv[0]) {
		return false, H
	}
	var _s1, _s2, coeffZ, rl, zn2, zn2sq, zn2zh, zn2sqzh, mzh fr.Element
	_s1.Mul(&beta, &s1).Add(&_s1, &l).Add(&_s1, &gamma)
	tmp.Mul(&beta, &s2).Add(&tmp, &r).Add(&tmp, &gamma)
	_s1.Mul(&_s1, &tmp).Mul(&_s1, &beta).Mul(&_s1, &alpha).Mul(&_s1, &zu)
	_s2.Mul(&beta, &zeta).Add(&_s2, &gamma).Add(&_s2, &l)
	tmp.Mul(&beta, &vk.CosetShift).Mul(&tmp, &zeta).Add(&tmp, &gamma).Add(&tmp, &r)
	_s2.Mul(&_s2, &tmp)
	tmp.Mul(&beta, &vk.CosetShift).Mul(&tmp, &vk.CosetShift).Mul(&tmp, &zeta).Add(&tmp, &o).Add(&tmp, &gamma)
	_s2.Mul(&_s2, &tmp).Mul(&_s2, &alpha).Neg(&_s2)
	coeffZ.Add(&a2l1, &_s2)
	rl.Mul(&l, &r)
	zn2.Exp(zeta, new(big.Int).SetUint64(vk.Size+2))
	zn2sq.Mul(&zn2, &zn2)
	zn2zh.Mul(&zn2, &zh).Neg(&zn2zh)
	zn2sqzh.Mul(&zn2sq, &zh).Neg(&zn2sqzh)
	mzh.Neg(&zh)
	linPts := []curve.G1Affine{vk.Ql, vk.Qr, vk.Qm, vk.Qo, vk.Qk, vk.S[2], proof.Z, proof.H[0], proof.H[1], proof.H[2]}
	linSc := []fr.Element{l, r, rl, o, one, _s1, coeffZ, mzh, zn2zh, zn2sqzh}
	lambdaTrue := msm(linPts, linSc)
	lam := lambdaTrue
	if lambdaW != nil {
		lam = *lambdaW
		if !lam.IsOnCurve() || lam.IsInfinity() {
			return false, H
		}
	}
	H["Lambda"] = hx(raw(&lam))
	vR := sum(cat([]byte("gamma"), frb(&zeta), raw(&lam), raw(&proof.LRO[0]), raw(&proof.LRO[1]), raw(&proof.LRO[2]), raw(&vk.S[0]), raw(&vk.S[1]),
		frb(&lin), frb(&l), frb(&r), frb(&o), frb(&s1), frb(&s2), frb(&zu)))
	v := chal(vR)
	H["v_raw"] = hx(vR)
	// ours: u1, u2, t1, t2 = the four 64-bit big-endian words of SHA256("u" || v_raw || W_zeta || W_zeta_omega)
	uR := sum(cat([]byte("u"), vR, raw(&proof.BatchedProof.H), raw(&proof.ZShiftedOpening.H)))
	H["u_raw"] = hx(uR)
	lg, _ := glv()
	word := func(i int) fr.Element { var e fr.Element; e.SetBytes(uR[8*i : 8*i+8]); return e }
	u1, u2, t1, t2 := word(0), word(1), word(2), word(3)
	var u, tt fr.Element
	u.Mul(&u2, &lg).Add(&u, &u1)
	tt.Mul(&t2, &lg).Add(&tt, &t1)
	// P_left* = t*MSM_lin + (1 - t)*Lambda' + v L + v^2 R + v^3 O + v^4 S1 + v^5 S2 + u Z - (e + u zu) G1 + zeta Wz + u zeta omega Wzw
	vp := make([]fr.Element, 6)
	vp[0].SetOne()
	for i := 1; i < 6; i++ {
		vp[i].Mul(&vp[i-1], &v)
	}
	var e, ue, zw, uzw, omt fr.Element
	for i, c := range []fr.Element{lin, l, r, o, s1, s2} {
		tmp.Mul(&vp[i], &c)
		e.Add(&e, &tmp)
	}
	ue.Mul(&u, &zu).Add(&ue, &e).Neg(&ue)
	zw.Mul(&zeta, &vk.Generator)
	uzw.Mul(&u, &zw)
	omt.Sub(&one, &tt)
	_, _, g1, _ := curve.Generators()
	pts := []curve.G1Affine{lam, proof.LRO[0], proof.LRO[1], proof.LRO[2], vk.S[0], vk.S[1], proof.Z, g1, proof.BatchedProof.H, proof.ZShiftedOpening.H}
	sc := []fr.Element{omt, vp[1], vp[2], vp[3], vp[4], vp[5], u, ue, zeta, uzw}
	for i := range linPts {
		var s fr.Element
		s.Mul(&linSc[i], &tt)
		pts = append(pts, linPts[i])
		sc = append(sc, s)
	}
	pLeft := msm(pts, sc)
	var pRight curve.G1Affine
	pRight = msm([]curve.G1Affine{proof.BatchedProof.H, proof.ZShiftedOpening.H}, []fr.Element{one, u})
	pRight.Neg(&pRight)
	H["P_left"], H["P_right"] = hx(raw(&pLeft)), hx(raw(&pRight))
	ok, err := curve.PairingCheck([]curve.G1Affine{pLeft, pRight}, []curve.G2Affine{vk.Kzg.G2[0], vk.Kzg.G2[1]})
	must(err)
	H["zeta"], H["v"], H["u"], H["t"] = hx(frb(&zeta)), hx(frb(&v)), hx(frb(&u)), hx(frb(&tt))
	return ok, H
}

func main() {
	logger.Disable()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &Circuit{})
	must(err)
	srs, srsL, err := unsafekzg.NewSRS(ccs)
	must(err)
	pk, vkI, err := plonk.Setup(ccs, srs, srsL)
	must(err)
	// x = 3: Y = 27 + 3 + 5 = 35, Z = 105
	wit, err := frontend.NewWitness(&Circuit{X: 3, Y: 35, Z: 105}, ecc.BN254.ScalarField())
	must(err)
	pubW, err := wit.Public()
	must(err)
	proofI, err := plonk.Prove(ccs, pk, wit)
	must(err)
	must(plonk.Verify(proofI, vkI, pubW))
	proof := proofI.(*plonkbn.Proof)
	vk := vkI.(*plonkbn.VerifyingKey)
	pub := []fr.Element(pubW.Vector().(fr.Vector))

	out := Out{Gnark: "github.com/consensys/gnark v0.16.4, gnark-crypto v0.21.1-0.20260913224755-1409fe592052",
		Circuit: "x^3 + x + 5 == Y, x*Y == Z (Y, Z public); witness x = 3", SRS: "test/unsafekzg (toxic waste known: testing only)",
		Size: vk.Size, NbPublic: vk.NbPublicVariables, Checks: map[string]bool{}, Tamper: map[string][2]bool{}}
	var buf countWriter
	_, err = proof.WriteRawTo(&buf)
	must(err)
	out.ProofBytes = int(buf)
	ok, H := ref(proof, vk, pub, nil)
	out.Checks["gnark accepts honest proof"] = true
	out.Checks["reference accepts honest proof (u, t ours; Lambda = MSM)"] = ok
	lamTrue, _ := hex.DecodeString(H["Lambda"])
	var lw curve.G1Affine
	_, err = lw.SetBytes(lamTrue)
	must(err)
	okW, _ := ref(proof, vk, pub, &lw)
	out.Checks["reference accepts honest proof with witnessed Lambda (plan B)"] = okW
	_, _, g1, _ := curve.Generators()
	var bad curve.G1Affine
	bad.Add(&lw, &g1)
	okBad, _ := ref(proof, vk, pub, &bad)
	out.Checks["reference rejects a wrong witnessed Lambda (plan B)"] = !okBad
	H["vk_x2"] = hx(func() []byte { b := vk.Kzg.G2[1].RawBytes(); return b[:] }())
	out.Hex = H

	// plain rejection tests: both gnark and the reference must reject
	tamper := func(name string, f func(p *plonkbn.Proof, pub []fr.Element) []fr.Element) {
		var p plonkbn.Proof
		var b countBuf
		_, err := proof.WriteRawTo(&b)
		must(err)
		_, err = p.ReadFrom(&b)
		must(err)
		pb := append([]fr.Element{}, pub...)
		pb = f(&p, pb)
		gErr := plonk.Verify(&p, vk, mkWitness(pb))
		rOk, _ := ref(&p, vk, pb, nil)
		out.Tamper[name] = [2]bool{gErr != nil, !rOk}
	}
	one := fr.One()
	tamper("public input Y + 1", func(p *plonkbn.Proof, pb []fr.Element) []fr.Element { pb[0].Add(&pb[0], &one); return pb })
	tamper("claimed l(zeta) + 1", func(p *plonkbn.Proof, pb []fr.Element) []fr.Element {
		p.BatchedProof.ClaimedValues[1].Add(&p.BatchedProof.ClaimedValues[1], &one)
		return pb
	})
	tamper("z(omega zeta) + 1", func(p *plonkbn.Proof, pb []fr.Element) []fr.Element {
		p.ZShiftedOpening.ClaimedValue.Add(&p.ZShiftedOpening.ClaimedValue, &one)
		return pb
	})
	tamper("W_zeta doubled", func(p *plonkbn.Proof, pb []fr.Element) []fr.Element {
		p.BatchedProof.H.Double(&p.BatchedProof.H)
		return pb
	})
	tamper("H[1] + G", func(p *plonkbn.Proof, pb []fr.Element) []fr.Element { p.H[1].Add(&p.H[1], &g1); return pb })
	tamper("L and R swapped", func(p *plonkbn.Proof, pb []fr.Element) []fr.Element {
		p.LRO[0], p.LRO[1] = p.LRO[1], p.LRO[0]
		return pb
	})
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	must(enc.Encode(out))
	for k, v := range out.Checks {
		if !v {
			fmt.Fprintln(os.Stderr, "FAILED:", k)
			os.Exit(1)
		}
	}
	for k, v := range out.Tamper {
		if !v[0] || !v[1] {
			fmt.Fprintln(os.Stderr, "TAMPER NOT REJECTED:", k, v)
			os.Exit(1)
		}
	}
}
