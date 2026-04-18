package main

import (
	"encoding/hex"
	"testing"
)

func TestPublicKeyFromScalar(t *testing.T) {
	// Known scalar from Cobo MPC export (sandbox)
	scalarHex := "08dab981ac72018565355597d3041812d148fcce905e3aa6e4ebce38bd6475f2"
	expectedAddr := "AaqKbYq7rRZWKFtDwgobJgnUDChv1UnqM7bVdxuRy8tM"

	scalarBytes, err := hex.DecodeString(scalarHex)
	if err != nil {
		t.Fatal(err)
	}
	var scalar [32]byte
	copy(scalar[:], scalarBytes)

	pub, err := PublicKeyFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}

	addr := Base58Encode(pub[:])
	if addr != expectedAddr {
		t.Errorf("address mismatch:\n  got:  %s\n  want: %s", addr, expectedAddr)
	}
}

func TestSignAndVerify(t *testing.T) {
	scalarHex := "08dab981ac72018565355597d3041812d148fcce905e3aa6e4ebce38bd6475f2"
	scalarBytes, _ := hex.DecodeString(scalarHex)
	var scalar [32]byte
	copy(scalar[:], scalarBytes)

	pub, err := PublicKeyFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message for Ed25519 scalar signing")
	sig, err := SignEd25519(scalar, pub, message)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyEd25519(pub, message, sig) {
		t.Fatal("signature verification failed")
	}

	// Verify that tampering with the message invalidates the signature
	tampered := []byte("tampered message")
	if VerifyEd25519(pub, tampered, sig) {
		t.Fatal("verification should fail on tampered message")
	}
}

func TestSignDeterministic(t *testing.T) {
	scalarHex := "08dab981ac72018565355597d3041812d148fcce905e3aa6e4ebce38bd6475f2"
	scalarBytes, _ := hex.DecodeString(scalarHex)
	var scalar [32]byte
	copy(scalar[:], scalarBytes)

	pub, _ := PublicKeyFromScalar(scalar)
	message := []byte("deterministic nonce test")

	sig1, _ := SignEd25519(scalar, pub, message)
	sig2, _ := SignEd25519(scalar, pub, message)

	if sig1 != sig2 {
		t.Fatal("signatures should be deterministic (same scalar + same message = same sig)")
	}
}

func TestBase58RoundTrip(t *testing.T) {
	original := "AaqKbYq7rRZWKFtDwgobJgnUDChv1UnqM7bVdxuRy8tM"
	decoded, err := Base58Decode(original)
	if err != nil {
		t.Fatal(err)
	}
	encoded := Base58Encode(decoded)
	if encoded != original {
		t.Errorf("base58 round-trip failed: %s != %s", encoded, original)
	}
}

func TestBuildTransferTransaction(t *testing.T) {
	var from, to, blockhash [32]byte
	from[0] = 1
	to[0] = 2
	blockhash[0] = 3

	msg := BuildTransferTransaction(from, to, 1000000, blockhash)

	// Header checks
	if msg[0] != 1 {
		t.Errorf("num_required_signatures: got %d, want 1", msg[0])
	}
	if msg[1] != 0 {
		t.Errorf("num_readonly_signed: got %d, want 0", msg[1])
	}
	if msg[2] != 1 {
		t.Errorf("num_readonly_unsigned: got %d, want 1", msg[2])
	}
	// 3 accounts
	if msg[3] != 3 {
		t.Errorf("num_accounts: got %d, want 3", msg[3])
	}

	// Message should be deterministic
	msg2 := BuildTransferTransaction(from, to, 1000000, blockhash)
	if len(msg) != len(msg2) {
		t.Fatal("transaction messages should be identical for same inputs")
	}
	for i := range msg {
		if msg[i] != msg2[i] {
			t.Fatalf("mismatch at byte %d", i)
		}
	}
}

func TestEncodeCompact(t *testing.T) {
	tests := []struct {
		input    int
		expected []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{127, []byte{127}},
		{128, []byte{0x80, 0x01}},
		{255, []byte{0xff, 0x01}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x80, 0x80, 0x01}},
	}
	for _, tt := range tests {
		got := encodeCompact(tt.input)
		if len(got) != len(tt.expected) {
			t.Errorf("encodeCompact(%d): len %d, want %d", tt.input, len(got), len(tt.expected))
			continue
		}
		for i := range got {
			if got[i] != tt.expected[i] {
				t.Errorf("encodeCompact(%d): byte %d = %02x, want %02x", tt.input, i, got[i], tt.expected[i])
			}
		}
	}
}
