package ibe_test

import (
	"bytes"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/ibe"
)

func TestDecrypt(t *testing.T) {
	// Setup
	pkg, pp := ibe.NewPrivateKeyGenerator()

	// Generate secret keys
	bobSk := pkg.Extract([]byte("bob"))

	// 32-byte message
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")

	// Alice encrypts the message to Bob
	c, err := ibe.Encrypt(pp, []byte("bob"), msg)
	if err != nil {
		t.Fatalf("ibe.Encrypt failed: %v", err)
	}

	// Bob decrypts the message
	got := ibe.Decrypt(pp, c, bobSk)

	if !bytes.Equal(msg, got) {
		t.Fatalf("expected decrypted message to be %x, but got %x", msg, got)
	}
}

var blackholeSk *bls.G1

func BenchmarkExtract(b *testing.B) {
	pkg, _ := ibe.NewPrivateKeyGenerator()
	id := []byte("test@example.com")
	for i := 0; i < b.N; i++ {
		idSk := pkg.Extract(id)
		// Ensure compiler preserves call to pkg.Extract
		blackholeSk = idSk
	}
}

var blackholeCiphertext *ibe.Ciphertext

func BenchmarkEncrypt(b *testing.B) {
	_, pp := ibe.NewPrivateKeyGenerator()
	id := []byte("test@example.com")
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	for i := 0; i < b.N; i++ {
		c, err := ibe.Encrypt(pp, id, msg)
		if err != nil {
			b.Fatalf("ibe.Encrypt failed: %v", err)
		}
		// Ensure compiler preserves call to pkg.Encrypt
		blackholeCiphertext = c
	}
}

func BenchmarkDecrypt(b *testing.B) {
	pkg, pp := ibe.NewPrivateKeyGenerator()
	id := []byte("test@example.com")
	idSk := pkg.Extract(id)
	msg := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	c, err := ibe.Encrypt(pp, id, msg)
	if err != nil {
		b.Fatalf("ibe.Encrypt failed: %v", err)
	}
	for i := 0; i < b.N; i++ {
		got := ibe.Decrypt(pp, c, idSk)
		if !bytes.Equal(msg, got) {
			b.Fatalf("expected decrypted message to be %x, but got %x", msg, got)
		}
	}
}
