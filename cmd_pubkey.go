package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func runPubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	var scalarHex string
	var jsonOutput bool
	fs.StringVar(&scalarHex, "key", "", "Ed25519 scalar (hex, 64 chars)")
	fs.BoolVar(&jsonOutput, "json", false, "Output as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Derive public key and address from an Ed25519 scalar.

Usage:
  ucw-eddsa-signing pubkey --key <scalar_hex>

Flags:
`)
		fs.PrintDefaults()
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

	address := Base58Encode(pub[:])
	pubHex := hex.EncodeToString(pub[:])

	if jsonOutput {
		emitJSON(map[string]string{
			"public_key": pubHex,
			"address":    address,
		})
	} else {
		fmt.Printf("Public key (hex):  %s\n", pubHex)
		fmt.Printf("Address (base58):  %s\n", address)
	}
}
