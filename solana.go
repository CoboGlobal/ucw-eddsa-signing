package main

import (
	"encoding/binary"
	"fmt"
)

// Solana SystemProgram.Transfer instruction index
const transferInstructionIndex uint32 = 2

// systemProgramID is the all-zero 32-byte Solana System Program address.
var systemProgramID [32]byte

// BuildTransferTransaction builds a Solana transaction message (v0 legacy format)
// containing a single SystemProgram.Transfer instruction.
//
// Solana transaction wire format (legacy, single-signer):
//
//	[1] num_required_signatures
//	[1] num_readonly_signed_accounts
//	[1] num_readonly_unsigned_accounts
//	[compact] num_accounts
//	[32 * n] account pubkeys
//	[32] recent_blockhash
//	[compact] num_instructions
//	  per instruction:
//	    [compact] program_id_index
//	    [compact] num_account_indices
//	    [compact * n] account_indices
//	    [compact] data_length
//	    [n] data
func BuildTransferTransaction(
	from [32]byte,
	to [32]byte,
	lamports uint64,
	recentBlockhash [32]byte,
) []byte {
	fromIsTo := from == to

	var msg []byte

	// Header
	msg = append(msg, 1) // num_required_signatures (only `from`)
	msg = append(msg, 0) // num_readonly_signed_accounts
	if fromIsTo {
		msg = append(msg, 1) // num_readonly_unsigned_accounts (system program only)
	} else {
		msg = append(msg, 1) // num_readonly_unsigned_accounts (system program)
	}

	// Account keys
	if fromIsTo {
		// 2 accounts: from/to (same), system_program
		msg = append(msg, encodeCompact(2)...)
		msg = append(msg, from[:]...)
		msg = append(msg, systemProgramID[:]...)
	} else {
		// 3 accounts: from, to, system_program
		msg = append(msg, encodeCompact(3)...)
		msg = append(msg, from[:]...)
		msg = append(msg, to[:]...)
		msg = append(msg, systemProgramID[:]...)
	}

	// Recent blockhash
	msg = append(msg, recentBlockhash[:]...)

	// Instructions (1 instruction)
	msg = append(msg, encodeCompact(1)...)

	// Instruction: SystemProgram.Transfer
	if fromIsTo {
		programIndex := byte(1)
		msg = append(msg, encodeCompact(int(programIndex))...)
		msg = append(msg, encodeCompact(2)...)
		msg = append(msg, 0, 0) // both from and to reference account index 0
	} else {
		programIndex := byte(2)
		msg = append(msg, encodeCompact(int(programIndex))...)
		msg = append(msg, encodeCompact(2)...)
		msg = append(msg, 0, 1) // account indices: from=0, to=1
	}

	// Instruction data: [4-byte LE instruction index] [8-byte LE lamports]
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], transferInstructionIndex)
	binary.LittleEndian.PutUint64(data[4:12], lamports)

	msg = append(msg, encodeCompact(len(data))...)
	msg = append(msg, data...)

	return msg
}

// WrapSignedTransaction wraps a signed message into a full Solana transaction
// wire format (legacy) with the signature prepended.
//
// Wire format:
//
//	[compact] num_signatures
//	[64 * n] signatures
//	[...] message
func WrapSignedTransaction(signature [64]byte, message []byte) []byte {
	var tx []byte
	tx = append(tx, encodeCompact(1)...) // 1 signature
	tx = append(tx, signature[:]...)
	tx = append(tx, message...)
	return tx
}

// encodeCompact encodes an integer as a Solana compact-u16.
// Values 0-127 → 1 byte; 128-16383 → 2 bytes; 16384-65535 → 3 bytes.
func encodeCompact(v int) []byte {
	if v < 0 {
		panic("encodeCompact: negative value")
	}
	if v < 0x80 {
		return []byte{byte(v)}
	}
	if v < 0x4000 {
		return []byte{byte(v&0x7f) | 0x80, byte(v >> 7)}
	}
	return []byte{byte(v&0x7f) | 0x80, byte((v>>7)&0x7f) | 0x80, byte(v >> 14)}
}

// Base58Decode decodes a base58-encoded string to bytes.
func Base58Decode(s string) ([]byte, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	var table [256]int
	for i := range table {
		table[i] = -1
	}
	for i, c := range alphabet {
		table[c] = i
	}

	result := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		carry := table[c]
		if carry < 0 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		for i := range result {
			carry += int(result[i]) * 58
			result[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			result = append(result, byte(carry&0xff))
			carry >>= 8
		}
	}

	// Leading '1's → leading zero bytes
	for _, c := range []byte(s) {
		if c != '1' {
			break
		}
		result = append(result, 0)
	}

	// Reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result, nil
}

// Base58Encode encodes bytes to base58.
func Base58Encode(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	result := make([]byte, 0, len(data)*138/100+1)
	for _, b := range data {
		carry := int(b)
		for i := range result {
			carry += int(result[i]) << 8
			result[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			result = append(result, byte(carry%58))
			carry /= 58
		}
	}

	// Leading zeros → '1'
	var encoded []byte
	for _, b := range data {
		if b != 0 {
			break
		}
		encoded = append(encoded, '1')
	}

	// Reverse and map to alphabet
	for i := len(result) - 1; i >= 0; i-- {
		encoded = append(encoded, alphabet[result[i]])
	}

	return string(encoded)
}

// ParseSolanaAddress decodes a base58 Solana address into [32]byte.
func ParseSolanaAddress(addr string) ([32]byte, error) {
	decoded, err := Base58Decode(addr)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid base58 address: %w", err)
	}
	if len(decoded) != 32 {
		return [32]byte{}, fmt.Errorf("address must be 32 bytes, got %d", len(decoded))
	}
	var result [32]byte
	copy(result[:], decoded)
	return result, nil
}
