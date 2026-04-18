package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultRPCURL     = "https://api.mainnet-beta.solana.com"
	defaultTestnetURL = "https://api.devnet.solana.com"
	rpcTimeout        = 30 * time.Second
)

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type SolanaRPC struct {
	url    string
	client *http.Client
}

func NewSolanaRPC(url string) *SolanaRPC {
	return &SolanaRPC{
		url: url,
		client: &http.Client{
			Timeout: rpcTimeout,
		},
	}
}

func (s *SolanaRPC) call(method string, params []interface{}) (json.RawMessage, error) {
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", s.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w (body: %s)", err, string(respBody))
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// GetBalance returns the balance in lamports for a given address.
func (s *SolanaRPC) GetBalance(address string) (uint64, error) {
	result, err := s.call("getBalance", []interface{}{address})
	if err != nil {
		return 0, err
	}

	var parsed struct {
		Value uint64 `json:"value"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return 0, fmt.Errorf("parse balance: %w", err)
	}
	return parsed.Value, nil
}

// GetLatestBlockhash returns the latest blockhash as a [32]byte.
func (s *SolanaRPC) GetLatestBlockhash() ([32]byte, uint64, error) {
	params := []interface{}{
		map[string]string{"commitment": "finalized"},
	}
	result, err := s.call("getLatestBlockhash", params)
	if err != nil {
		return [32]byte{}, 0, err
	}

	var parsed struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return [32]byte{}, 0, fmt.Errorf("parse blockhash: %w", err)
	}

	bhBytes, err := Base58Decode(parsed.Value.Blockhash)
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("decode blockhash: %w", err)
	}
	if len(bhBytes) != 32 {
		return [32]byte{}, 0, fmt.Errorf("blockhash is %d bytes, expected 32", len(bhBytes))
	}

	var blockhash [32]byte
	copy(blockhash[:], bhBytes)
	return blockhash, parsed.Value.LastValidBlockHeight, nil
}

// SendTransaction submits a signed transaction (base64 encoded) and returns the signature.
func (s *SolanaRPC) SendTransaction(signedTx []byte) (string, error) {
	encoded := base64.StdEncoding.EncodeToString(signedTx)

	params := []interface{}{
		encoded,
		map[string]interface{}{
			"encoding":            "base64",
			"skipPreflight":       false,
			"preflightCommitment": "confirmed",
			"maxRetries":          5,
		},
	}

	result, err := s.call("sendTransaction", params)
	if err != nil {
		return "", err
	}

	var txSig string
	if err := json.Unmarshal(result, &txSig); err != nil {
		return "", fmt.Errorf("parse tx signature: %w", err)
	}
	return txSig, nil
}

// ConfirmTransaction polls getSignatureStatuses until the transaction is confirmed or times out.
func (s *SolanaRPC) ConfirmTransaction(signature string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	for time.Now().Before(deadline) {
		params := []interface{}{
			[]string{signature},
			map[string]interface{}{"searchTransactionHistory": false},
		}
		result, err := s.call("getSignatureStatuses", params)
		if err != nil {
			time.Sleep(interval)
			continue
		}

		var parsed struct {
			Value []json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(result, &parsed); err != nil || len(parsed.Value) == 0 {
			time.Sleep(interval)
			continue
		}

		if string(parsed.Value[0]) == "null" {
			time.Sleep(interval)
			continue
		}

		var status struct {
			Err                interface{} `json:"err"`
			ConfirmationStatus string      `json:"confirmationStatus"`
		}
		if err := json.Unmarshal(parsed.Value[0], &status); err != nil {
			time.Sleep(interval)
			continue
		}

		if status.Err != nil {
			return "", fmt.Errorf("transaction failed: %v", status.Err)
		}

		if status.ConfirmationStatus == "confirmed" || status.ConfirmationStatus == "finalized" {
			return status.ConfirmationStatus, nil
		}

		time.Sleep(interval)
	}

	return "", fmt.Errorf("transaction not confirmed within %s", timeout)
}

// GetMinimumBalanceForRentExemption returns the minimum lamports needed for rent exemption
// for an account of the given data size.
func (s *SolanaRPC) GetMinimumBalanceForRentExemption(dataSize uint64) (uint64, error) {
	result, err := s.call("getMinimumBalanceForRentExemption", []interface{}{dataSize})
	if err != nil {
		return 0, err
	}

	var lamports uint64
	if err := json.Unmarshal(result, &lamports); err != nil {
		return 0, fmt.Errorf("parse rent exemption: %w", err)
	}
	return lamports, nil
}
