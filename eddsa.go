package main

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
)

// ed25519Order is the group order L of Ed25519.
// L = 2^252 + 27742317777372353535851937790883648493
var ed25519Order, _ = new(big.Int).SetString(
	"7237005577332262213973186563042994240857116359379907606001950938285454250989", 10,
)

// scalarFromBytes converts a 32-byte MPC-exported scalar (big-endian hex decoded)
// to an edwards25519.Scalar (little-endian). MPC systems store scalars as big-endian
// integers while edwards25519 uses little-endian encoding. The scalar is also reduced
// mod L to handle non-canonical values.
func scalarFromBytes(raw [32]byte) (*edwards25519.Scalar, error) {
	// MPC export is big-endian; interpret as big.Int then reduce mod L
	v := new(big.Int).SetBytes(raw[:])
	v.Mod(v, ed25519Order)

	// Convert to 32-byte little-endian for edwards25519
	le := make([]byte, 32)
	for i, b := range v.Bytes() {
		le[len(v.Bytes())-1-i] = b
	}

	s, err := edwards25519.NewScalar().SetCanonicalBytes(le)
	if err != nil {
		return nil, fmt.Errorf("scalar reduction failed: %w", err)
	}
	return s, nil
}

// reverseBytes returns a new slice with bytes in reverse order.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

// PublicKeyFromScalar computes the Ed25519 public key (32 bytes) from a scalar a:
// PubKey = a × G
func PublicKeyFromScalar(scalarBytes [32]byte) ([32]byte, error) {
	s, err := scalarFromBytes(scalarBytes)
	if err != nil {
		return [32]byte{}, err
	}
	point := edwards25519.NewGeneratorPoint().ScalarBaseMult(s)
	var pub [32]byte
	copy(pub[:], point.Bytes())
	return pub, nil
}

// SignEd25519 performs Ed25519 signing using the raw scalar a (not a seed).
//
// Nonce generation uses SHA-512(a ‖ message) for determinism, replacing
// the standard SHA-512(nonce_key ‖ message) where nonce_key comes from
// SHA-512(seed). This is cryptographically equivalent; see RFC 8032 §5.1.6
// with a substituted prefix.
//
// Steps:
//  1. r = SHA-512(a ‖ message) mod L   (deterministic nonce)
//  2. R = r × G
//  3. h = SHA-512(R ‖ PubKey ‖ message) mod L
//  4. S = (r + h × a) mod L
//  5. Signature = R(32 bytes) ‖ S(32 bytes)
func SignEd25519(scalarBytes [32]byte, pubKey [32]byte, message []byte) ([64]byte, error) {
	a, err := scalarFromBytes(scalarBytes)
	if err != nil {
		return [64]byte{}, err
	}

	// Step 1: deterministic nonce r = SHA-512(a ‖ message) mod L
	nonceHash := sha512.New()
	nonceHash.Write(scalarBytes[:])
	nonceHash.Write(message)
	nonceDigest := nonceHash.Sum(nil) // 64 bytes

	r, err := edwards25519.NewScalar().SetUniformBytes(nonceDigest)
	if err != nil {
		return [64]byte{}, fmt.Errorf("nonce scalar: %w", err)
	}

	// Step 2: R = r × G
	R := edwards25519.NewGeneratorPoint().ScalarBaseMult(r)
	encodedR := R.Bytes() // 32 bytes

	// Step 3: h = SHA-512(R ‖ PubKey ‖ message) mod L
	hramHash := sha512.New()
	hramHash.Write(encodedR)
	hramHash.Write(pubKey[:])
	hramHash.Write(message)
	hramDigest := hramHash.Sum(nil)

	h, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		return [64]byte{}, fmt.Errorf("hram scalar: %w", err)
	}

	// Step 4: S = r + h × a  (mod L)
	ha := edwards25519.NewScalar().Multiply(h, a)
	S := edwards25519.NewScalar().Add(r, ha)

	// Step 5: signature = R ‖ S
	var sig [64]byte
	copy(sig[:32], encodedR)
	copy(sig[32:], S.Bytes())
	return sig, nil
}

// VerifyEd25519 verifies an Ed25519 signature against a public key.
// Used for local sanity checks before broadcasting.
func VerifyEd25519(pubKey [32]byte, message []byte, sig [64]byte) bool {
	A, err := edwards25519.NewIdentityPoint().SetBytes(pubKey[:])
	if err != nil {
		return false
	}

	var encodedR [32]byte
	copy(encodedR[:], sig[:32])
	R, err := edwards25519.NewIdentityPoint().SetBytes(encodedR[:])
	if err != nil {
		return false
	}

	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	// h = SHA-512(R ‖ PubKey ‖ message) mod L
	hramHash := sha512.New()
	hramHash.Write(encodedR[:])
	hramHash.Write(pubKey[:])
	hramHash.Write(message)
	hramDigest := hramHash.Sum(nil)
	h, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		return false
	}

	// Check: S × G == R + h × A
	negH := edwards25519.NewScalar().Negate(h)
	// S×G - h×A should equal R
	lhs := edwards25519.NewIdentityPoint().VarTimeDoubleScalarBaseMult(negH, A, S)
	return lhs.Equal(R) == 1
}

// lamportsFromSOL converts a SOL amount (float64) to lamports (uint64).
// 1 SOL = 1_000_000_000 lamports.
func lamportsFromSOL(sol float64) uint64 {
	return uint64(sol * 1_000_000_000)
}

// solFromLamports converts lamports to SOL for display.
func solFromLamports(lamports uint64) float64 {
	return float64(lamports) / 1_000_000_000
}

// le64 encodes a uint64 as 8 little-endian bytes.
func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}
