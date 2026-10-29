package main

import (
	"bytes"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

type countWriter int64

func (c *countWriter) Write(p []byte) (int, error) { *c += countWriter(len(p)); return len(p), nil }

type countBuf = bytes.Buffer

// public witness (Y, Z) from field elements
func mkWitness(pb []fr.Element) witness.Witness {
	var y, z big.Int
	pb[0].BigInt(&y)
	pb[1].BigInt(&z)
	w, err := frontend.NewWitness(&Circuit{Y: &y, Z: &z}, ecc.BN254.ScalarField(), frontend.PublicOnly())
	must(err)
	return w
}
