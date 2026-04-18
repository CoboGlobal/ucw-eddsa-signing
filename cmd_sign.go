package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	var (
		scalarHex  string
		messageHex string
		filePath   string
		jsonOutput bool
	)
	fs.StringVar(&scalarHex, "key", "", "Ed25519 scalar (hex, 64 chars)")
	fs.StringVar(&messageHex, "message", "", "Message to sign (hex encoded)")
	fs.StringVar(&filePath, "file", "", "File containing raw bytes to sign")
	fs.BoolVar(&jsonOutput, "json", false, "Output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Sign an arbitrary message using an Ed25519 private scalar.

The signature is standard Ed25519 and can be verified by any Ed25519 verifier.
Users can construct transactions for any Ed25519 chain (Solana SPL tokens,
Aptos, Sui, etc.), sign them with this command, and broadcast independently.

Usage:
  ucw-eddsa-signing sign --key <scalar_hex> --message <message_hex>
  ucw-eddsa-signing sign --key <scalar_hex> --file <path>
  cat tx.bin | ucw-eddsa-signing sign --key <scalar_hex>

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Input:
  --message   Hex-encoded bytes to sign
  --file      Path to a file containing raw bytes to sign
  stdin       If neither --message nor --file is given, reads from stdin

Output:
  By default prints human-readable text.
  Use --json for machine-readable JSON output.

Examples:
  # Sign a hex-encoded Solana transaction message
  ucw-eddsa-signing sign --key 08dab9...75f2 --message 0100...abcd

  # Sign a binary file
  ucw-eddsa-signing sign --key 08dab9...75f2 --file unsigned_tx.bin

  # Pipe from another tool
  solana-build-tx | ucw-eddsa-signing sign --key 08dab9...75f2

  # JSON output for scripting
  ucw-eddsa-signing sign --key 08dab9...75f2 --message abcd --json
`)
	}
	_ = fs.Parse(args)

	if scalarHex == "" {
		fs.Usage()
		os.Exit(1)
	}

	scalar := parseScalar(scalarHex)
	pub, err := PublicKeyFromScalar(scalar)
	if err != nil {
		fatalf("Derive public key: %v", err)
	}

	message := readMessageInput(messageHex, filePath)

	sig, err := SignEd25519(scalar, pub, message)
	if err != nil {
		fatalf("Signing failed: %v", err)
	}

	verified := VerifyEd25519(pub, message, sig)

	address := Base58Encode(pub[:])
	pubHex := hex.EncodeToString(pub[:])
	sigHex := hex.EncodeToString(sig[:])
	msgHex := hex.EncodeToString(message)

	if jsonOutput {
		emitJSON(map[string]interface{}{
			"public_key": pubHex,
			"address":    address,
			"message":    msgHex,
			"signature":  sigHex,
			"verified":   verified,
		})
	} else {
		fmt.Printf("Public key:   %s\n", pubHex)
		fmt.Printf("Address:      %s\n", address)
		fmt.Printf("Message:      %s (%d bytes)\n", msgHex, len(message))
		fmt.Printf("Signature:    %s\n", sigHex)
		if verified {
			fmt.Printf("Verified:     ok\n")
		} else {
			fmt.Printf("Verified:     FAILED\n")
			os.Exit(1)
		}
	}
}
