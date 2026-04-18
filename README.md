# ucw-eddsa-signing

Sign Ed25519 messages and transfer SOL using Cobo MPC-exported private scalars.

## Background

Cobo's MPC-TSS system exports Ed25519 private keys as the raw **scalar `a`** (32 bytes), not the standard **seed** that wallets expect. Due to the one-way nature of SHA-512 (`seed → SHA-512 → scalar`), it is impossible to convert the scalar back into a seed. This means the exported key **cannot be imported into any standard Solana wallet** (Phantom, OKX, Backpack, etc.).

This tool provides:
- **`sign`** — Sign arbitrary messages with the scalar (works for any Ed25519 chain)
- **`transfer`** — Full SOL transfer flow (build tx → sign → broadcast)
- **`pubkey`** — Derive public key / address from the scalar

See [How It Works](#how-it-works) below for a brief technical summary.

## Build

```bash
git clone https://github.com/CoboGlobal/ucw-eddsa-signing.git
cd ucw-eddsa-signing
go build -o ucw-eddsa-signing .
```

Cross-compile for Linux:

```bash
GOOS=linux GOARCH=amd64 go build -o ucw-eddsa-signing-linux-amd64 .
```

## Commands

### `sign` — Sign arbitrary messages

Sign any hex-encoded message and get an Ed25519 signature. Users can construct transactions for any Ed25519 chain (Solana SPL tokens, Aptos, Sui, etc.), sign them with this command, and broadcast independently.

```bash
# Sign a hex-encoded message
./ucw-eddsa-signing sign --key <scalar_hex> --message <message_hex>

# Sign a binary file (e.g. unsigned Solana transaction)
./ucw-eddsa-signing sign --key <scalar_hex> --file unsigned_tx.bin

# Pipe from another tool
solana-build-tx | ./ucw-eddsa-signing sign --key <scalar_hex>

# JSON output for scripting
./ucw-eddsa-signing sign --key <scalar_hex> --message abcd --json
```

Output:

```json
{
  "public_key": "8e63fc3e...",
  "address": "AaqKbYq7...",
  "message": "abcd",
  "signature": "d444a816...",
  "verified": true
}
```

### `transfer` — Transfer native SOL

Complete end-to-end flow: query balance → build transaction → sign → broadcast → confirm.

```bash
# Transfer a specific amount
./ucw-eddsa-signing transfer --key <scalar_hex> --to <address> --amount 1.5

# Transfer entire balance (minus fee)
./ucw-eddsa-signing transfer --key <scalar_hex> --to <address> --all

# Use devnet
./ucw-eddsa-signing transfer --key <scalar_hex> --to <address> --amount 0.1 \
  --rpc https://api.devnet.solana.com

# Skip confirmation prompt
./ucw-eddsa-signing transfer --key <scalar_hex> --to <address> --all --yes
```

### `pubkey` — Derive public key

```bash
./ucw-eddsa-signing pubkey --key <scalar_hex>
# Public key (hex):  8e63fc3e...
# Address (base58):  AaqKbYq7...

./ucw-eddsa-signing pubkey --key <scalar_hex> --json
```

## Use Case: SPL Token Transfer

For SPL tokens or other complex Solana transactions, use `sign` with an external transaction builder:

```bash
# 1. Build the transaction message externally (e.g. with @solana/web3.js)
#    Save the serialized message as hex or binary

# 2. Sign with ucw-eddsa-signing
./ucw-eddsa-signing sign --key <scalar_hex> --file unsigned_tx.bin --json > sig.json

# 3. Attach the signature to the transaction and broadcast externally
```

## How It Works

1. **Derive public key** from scalar: `PubKey = a × G`
2. **Sign** using custom Ed25519 with deterministic nonce: `r = SHA-512(a ‖ message)`
3. **Verify** signature locally before returning / broadcasting

### Signing Difference from Standard Ed25519

Standard Ed25519 uses `nonce_key` (from `SHA-512(seed)`) for deterministic nonce generation. Since we don't have the seed, we use the scalar itself:

```
Standard:  r = SHA-512(nonce_key ‖ message)
This tool: r = SHA-512(a ‖ message)
```

The rest of the signing algorithm is identical. The resulting signature is valid and verifiable by any Ed25519 verifier.

## Dependencies

- `filippo.io/edwards25519` — Ed25519 curve operations (Go standard ecosystem)
- No other external dependencies

## License

MIT
