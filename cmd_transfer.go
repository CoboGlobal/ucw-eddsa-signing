package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func runTransfer(args []string) {
	fs := flag.NewFlagSet("transfer", flag.ExitOnError)
	var (
		scalarHex   string
		toAddr      string
		amountSOL   float64
		rpcURL      string
		skipConfirm bool
		transferAll bool
	)
	fs.StringVar(&scalarHex, "key", "", "Ed25519 scalar (hex, 64 chars)")
	fs.StringVar(&toAddr, "to", "", "Destination Solana address (base58)")
	fs.Float64Var(&amountSOL, "amount", 0, "Amount to transfer in SOL")
	fs.StringVar(&rpcURL, "rpc", defaultRPCURL, "Solana RPC endpoint URL")
	fs.BoolVar(&skipConfirm, "yes", false, "Skip confirmation prompt")
	fs.BoolVar(&transferAll, "all", false, "Transfer entire balance (minus tx fee)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Transfer SOL from an MPC-exported Ed25519 scalar address to a standard wallet.

Usage:
  ucw-eddsa-signing transfer --key <scalar_hex> --to <address> --amount <SOL>
  ucw-eddsa-signing transfer --key <scalar_hex> --to <address> --all

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Transfer 1.5 SOL
  ucw-eddsa-signing transfer --key 08dab9...75f2 --to 9aE8...Fp3 --amount 1.5

  # Transfer entire balance
  ucw-eddsa-signing transfer --key 08dab9...75f2 --to 9aE8...Fp3 --all

  # Use devnet
  ucw-eddsa-signing transfer --key 08dab9...75f2 --to 9aE8...Fp3 --amount 0.1 --rpc %s
`, defaultTestnetURL)
	}
	_ = fs.Parse(args)

	if scalarHex == "" || toAddr == "" {
		fs.Usage()
		os.Exit(1)
	}
	if amountSOL <= 0 && !transferAll {
		fatalf("--amount must be positive, or use --all to transfer entire balance")
	}

	scalar := parseScalar(scalarHex)

	pubKey, err := PublicKeyFromScalar(scalar)
	if err != nil {
		fatalf("Failed to derive public key: %v", err)
	}
	fromAddr := Base58Encode(pubKey[:])

	toPubkey, err := ParseSolanaAddress(toAddr)
	if err != nil {
		fatalf("Invalid destination address: %v", err)
	}

	rpc := NewSolanaRPC(rpcURL)

	fmt.Println("=== Cobo UCW EdDSA Transfer ===")
	fmt.Println()
	fmt.Printf("  Source address:  %s\n", fromAddr)
	fmt.Printf("  Dest address:   %s\n", toAddr)
	fmt.Printf("  RPC endpoint:   %s\n", rpcURL)
	fmt.Println()

	fmt.Print("Querying balance... ")
	balance, err := rpc.GetBalance(fromAddr)
	if err != nil {
		fatalf("Failed to get balance: %v", err)
	}
	fmt.Printf("%.9f SOL (%d lamports)\n", solFromLamports(balance), balance)

	if balance == 0 {
		fatalf("Source address has zero balance")
	}

	const estimatedFee uint64 = 5000

	var transferLamports uint64
	if transferAll {
		if balance <= estimatedFee {
			fatalf("Balance (%d lamports) is not enough to cover the transaction fee (%d lamports)",
				balance, estimatedFee)
		}
		transferLamports = balance - estimatedFee
		fmt.Printf("  Transfer all:   %.9f SOL (%d lamports, fee ~%d)\n",
			solFromLamports(transferLamports), transferLamports, estimatedFee)
	} else {
		transferLamports = lamportsFromSOL(amountSOL)
		if transferLamports+estimatedFee > balance {
			fatalf("Insufficient balance: need %d lamports (amount + fee), have %d",
				transferLamports+estimatedFee, balance)
		}
		fmt.Printf("  Transfer:       %.9f SOL (%d lamports)\n",
			solFromLamports(transferLamports), transferLamports)
		fmt.Printf("  Est. fee:       %d lamports\n", estimatedFee)
		fmt.Printf("  Remaining:      %.9f SOL\n",
			solFromLamports(balance-transferLamports-estimatedFee))
	}
	fmt.Println()

	if !skipConfirm {
		fmt.Print("Proceed with transfer? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return
		}
		fmt.Println()
	}

	fmt.Print("Fetching latest blockhash... ")
	blockhash, _, err := rpc.GetLatestBlockhash()
	if err != nil {
		fatalf("Failed to get blockhash: %v", err)
	}
	fmt.Printf("%s\n", Base58Encode(blockhash[:]))

	fmt.Print("Building transaction... ")
	txMsg := BuildTransferTransaction(pubKey, toPubkey, transferLamports, blockhash)
	fmt.Println("ok")

	fmt.Print("Signing with Ed25519 scalar... ")
	signature, err := SignEd25519(scalar, pubKey, txMsg)
	if err != nil {
		fatalf("Signing failed: %v", err)
	}
	fmt.Println("ok")

	fmt.Print("Verifying signature locally... ")
	if !VerifyEd25519(pubKey, txMsg, signature) {
		fatalf("Local signature verification FAILED — aborting to prevent fund loss")
	}
	fmt.Println("ok")

	fmt.Print("Sending transaction... ")
	signedTx := WrapSignedTransaction(signature, txMsg)
	txSig, err := rpc.SendTransaction(signedTx)
	if err != nil {
		fatalf("Send failed: %v", err)
	}
	fmt.Printf("submitted\n")
	fmt.Println()
	fmt.Printf("  Transaction: %s\n", txSig)
	fmt.Printf("  Explorer:    %s\n", solscanTxURL(rpcURL, txSig))
	fmt.Println()

	fmt.Print("Waiting for confirmation... ")
	status, err := rpc.ConfirmTransaction(txSig, 60*time.Second)
	if err != nil {
		fmt.Printf("warning: %v\n", err)
		fmt.Println("The transaction may still succeed. Check the explorer link above.")
	} else {
		fmt.Printf("%s\n", status)
		fmt.Println()
		fmt.Println("Transfer complete!")
	}
}

// solscanTxURL returns the Solscan explorer URL for a transaction signature,
// picking the cluster query param based on the RPC endpoint.
func solscanTxURL(rpcURL, txSig string) string {
	lower := strings.ToLower(rpcURL)
	switch {
	case strings.Contains(lower, "devnet"):
		return fmt.Sprintf("https://solscan.io/tx/%s?cluster=devnet", txSig)
	case strings.Contains(lower, "testnet"):
		return fmt.Sprintf("https://solscan.io/tx/%s?cluster=testnet", txSig)
	default:
		return fmt.Sprintf("https://solscan.io/tx/%s", txSig)
	}
}
