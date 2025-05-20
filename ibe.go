package ibe

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"golang.org/x/crypto/hkdf"
)

// https://alinush.github.io/pairings

const NumBytes = 32

func xorBytes(a, b []byte) {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		a[i] ^= b[i]
	}
}

func RandomScalar() *bls.Scalar {
	z := new(bls.Scalar)
	z.Random(rand.Reader)
	return z
}

// H_1: {0,1}^* \leftarrow G_1^*
func H1(data []byte) *bls.G1 {
	h := new(bls.G1)
	h.Hash(data, nil)
	return h
}

// H_T: G_2 \leftarrow {0,1)^n
func HT(p *bls.Gt) []byte {
	bytes, err := p.MarshalBinary()
	if err != nil {
		mu.Panicf("Gt.MarshaBinary failed: %v", err)
	}

	kdf := hkdf.New(sha256.New, bytes, nil, nil)

	h := make([]byte, NumBytes)
	_, err = io.ReadFull(kdf, h)
	if err != nil {
		mu.Panicf("io.ReadFull failed: %v", err)
	}

	return h
}

type PublicParams struct {
	// master publick key
	MPK *bls.G2
	// number of bytes for plaintext and for HT() output
	N int
}

type PrivateKeyGenerator struct {
	PP *PublicParams
	// master secret key
	MSK *bls.Scalar
}

func NewPrivateKeyGenerator() (*PrivateKeyGenerator, *PublicParams) {
	pkg := new(PrivateKeyGenerator)
	pp := new(PublicParams)

	pkg.MSK = RandomScalar()

	pp.MPK = new(bls.G2)
	pp.MPK.ScalarMult(pkg.MSK, bls.G2Generator())
	pp.N = NumBytes

	return pkg, pp
}

func (pkg *PrivateKeyGenerator) Extract(id []byte) *bls.G1 {
	skId := new(bls.G1)
	skId.ScalarMult(pkg.MSK, H1(id))
	return skId
}

type Ciphertext struct {
	U *bls.G2
	V []byte
}

func Encrypt(pp *PublicParams, id []byte, msg []byte) (*Ciphertext, error) {
	if len(msg) != pp.N {
		return nil, fmt.Errorf("plaintext must be %d bytes, not %d", pp.N, len(msg))
	}

	r := RandomScalar()
	u := new(bls.G2)
	u.ScalarMult(r, bls.G2Generator())

	pkId := bls.Pair(H1(id), pp.MPK)
	tmp := new(bls.Gt)
	tmp.Exp(pkId, r)
	v := HT(tmp)
	xorBytes(v, msg)
	c := Ciphertext{
		U: u,
		V: v,
	}

	return &c, nil
}

func Decrypt(pp *PublicParams, c *Ciphertext, sk *bls.G1) []byte {
	msg := HT(bls.Pair(sk, c.U))
	xorBytes(msg, c.V)
	return msg
}
