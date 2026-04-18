package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printMainUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "transfer":
		runTransfer(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	case "pubkey":
		runPubkey(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("ucw-eddsa-signing v%s\n", version)
	case "help", "--help", "-h":
		printMainUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printMainUsage()
		os.Exit(1)
	}
}

func printMainUsage() {
	fmt.Fprintf(os.Stderr, `ucw-eddsa-signing v%s

Sign Ed25519 messages and transfer SOL using Cobo MPC-exported private scalars.

Usage:
  ucw-eddsa-signing <command> [flags]

Commands:
  transfer    Transfer SOL from an MPC-exported address to a standard wallet
  sign        Sign an arbitrary message with the Ed25519 scalar
  pubkey      Derive and display the public key / address from a scalar

Flags:
  --version   Show version
  --help      Show this help

Examples:
  ucw-eddsa-signing transfer --key <hex> --to <address> --amount 1.5
  ucw-eddsa-signing sign --key <hex> --message <hex>
  ucw-eddsa-signing sign --key <hex> --file tx.bin
  ucw-eddsa-signing pubkey --key <hex>

Run 'ucw-eddsa-signing <command> --help' for details on a specific command.
`, version)
}

// parseScalar parses and validates a hex-encoded Ed25519 scalar.
func parseScalar(rawHex string) [32]byte {
	cleaned := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(rawHex), "0x"), "0X")
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		fatalf("Invalid scalar hex: %v", err)
	}
	if len(b) != 32 {
		fatalf("Scalar must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	var scalar [32]byte
	copy(scalar[:], b)
	return scalar
}

// emitJSON writes a JSON object to stdout (for scripting / piping).
func emitJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// readMessageInput reads the message to sign from --message hex, --file path, or stdin.
func readMessageInput(messageHex, filePath string) []byte {
	sources := 0
	if messageHex != "" {
		sources++
	}
	if filePath != "" {
		sources++
	}
	if sources > 1 {
		fatalf("Specify only one of --message or --file")
	}

	if messageHex != "" {
		cleaned := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(messageHex), "0x"), "0X")
		b, err := hex.DecodeString(cleaned)
		if err != nil {
			fatalf("Invalid message hex: %v", err)
		}
		return b
	}

	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			fatalf("Read file %s: %v", filePath, err)
		}
		return b
	}

	// Try stdin if it's piped
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatalf("Read stdin: %v", err)
		}
		if len(b) > 0 {
			return b
		}
	}

	fatalf("No message provided. Use --message <hex>, --file <path>, or pipe to stdin")
	return nil
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
