package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/itzngga/fakeuseragent"
)

var (
	CAPTCHA_API_KEY      = "0819e870cb1567524090e29e1f14b4eb"
	HCAPTCHA_SITE_KEY    = "1230eb62-f50c-4da4-a736-da5c3c342e8e"
	FAUCET_ENDPOINT      = "https://992dkn4ph6.execute-api.us-west-1.amazonaws.com/"
	MAX_RETRY            = 2
	REQUEST_DELAY        = 10
	NEWTON_CHAIN_ID      = int64(16600)
	TARGET_ADDRESS       = "0x6980437B8E74FC08856983F28AC637D5487ff173"
	GAS_LIMIT            = uint64(21000)
	GAS_PRICE            = big.NewInt(1000000000) // 1 gwei
	TRANSFER_DELAY       = 10                     // seconds to wait after faucet before transfer
	NEWTON_RPC_ENDPOINTS = []string{
		"https://0g.mhclabs.com",
		"https://0g-json-rpc-public.originstake.com",
		"https://evmrpc-testnet.0g.ai",
		"https://evm-rpc.0g.testnet.node75.org",
	}
)

type CaptchaResponse struct {
	Status  int    `json:"status"`
	Request string `json:"request"`
}

type FaucetResponse struct {
	Message string `json:"message"`
}

type Wallet struct {
	PrivateKey string
	Address    string
}

func readLines(filepath string) []string {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return []string{}
	}
	lines := strings.Split(string(data), "\n")
	var result []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func createClient(proxyStr string) (*http.Client, error) {
	if proxyStr == "" {
		return http.DefaultClient, nil
	}

	if !strings.HasPrefix(proxyStr, "http://") && !strings.HasPrefix(proxyStr, "https://") {
		proxyStr = "http://" + proxyStr
	}

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

func genWallet() (Wallet, error) {
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return Wallet{}, err
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return Wallet{}, fmt.Errorf("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return Wallet{
		PrivateKey: privateKeyHex,
		Address:    address,
	}, nil
}

func solveCaptcha(client *http.Client) *string {
	captchaRequest := map[string]interface{}{
		"key":     CAPTCHA_API_KEY,
		"method":  "hcaptcha",
		"sitekey": HCAPTCHA_SITE_KEY,
		"pageurl": FAUCET_ENDPOINT,
		"json":    1,
	}
	captchaReqBytes, _ := json.Marshal(captchaRequest)
	resp, err := client.Post("http://2captcha.com/in.php", "application/json", bytes.NewBuffer(captchaReqBytes))
	if err != nil {
		fmt.Println("[-] Network error solving captcha:", err)
		return nil
	}
	defer resp.Body.Close()

	var initialResp CaptchaResponse
	json.NewDecoder(resp.Body).Decode(&initialResp)

	if initialResp.Status != 1 {
		fmt.Println("[-] Captcha request error:", initialResp.Request)
		return nil
	}

	captchaID := initialResp.Request
	fmt.Println("[+] Captcha ID obtained:", captchaID)

	solutionRequest := map[string]interface{}{
		"key":    CAPTCHA_API_KEY,
		"action": "get",
		"id":     captchaID,
		"json":   1,
	}
	time.Sleep(10 * time.Second)

	for {
		req, _ := http.NewRequest("GET", "http://2captcha.com/res.php", nil)
		q := req.URL.Query()
		for k, v := range solutionRequest {
			q.Add(k, fmt.Sprintf("%v", v))
		}
		req.URL.RawQuery = q.Encode()

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("[-] Network error solving captcha:", err)
			return nil
		}
		defer resp.Body.Close()

		var solutionResp CaptchaResponse
		json.NewDecoder(resp.Body).Decode(&solutionResp)

		if solutionResp.Status == 1 {
			fmt.Println("[+] Captcha solved successfully.")
			return &solutionResp.Request
		} else if solutionResp.Request == "CAPCHA_NOT_READY" {
			fmt.Println("[*] Captcha still pending, waiting 30 sec ....")
			time.Sleep(30 * time.Second)
		} else {
			fmt.Println("[-] Captcha error:", solutionResp.Request)
			return nil
		}
	}
}

func claimFaucet(client *http.Client, wallet, captchaToken string) (string, bool) {
	randomUA := fakeuseragent.DesktopUserAgent()

	headers := map[string]string{
		"Accept":       "application/json, text/plain, */*",
		"Content-Type": "application/json",
		"Origin":       "https://hub.0g.ai",
		"Referer":      "https://hub.0g.ai/",
		"User-Agent":   randomUA,
	}

	payload := map[string]string{
		"address":       wallet,
		"hcaptchaToken": captchaToken,
		"token":         "A0GI",
	}
	payloadBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", FAUCET_ENDPOINT, bytes.NewBuffer(payloadBytes))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	fmt.Println("[*] Submitting faucet claim for wallet", wallet)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Network error during faucet claim:", err)
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var result FaucetResponse
		json.NewDecoder(resp.Body).Decode(&result)
		txHash := result.Message
		if txHash != "" {
			explorerURL := "https://chainscan-newton.0g.ai/tx/" + txHash
			fmt.Println("[+] Successfully claimed faucet! Transaction link:", explorerURL)
			return explorerURL, true
		} else {
			fmt.Println("[-] Transaction hash missing in response.")
		}
	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("[-] Failed to claim faucet: HTTP", resp.StatusCode, "-", string(body))
	}
	return "", false
}

func getWorkingRPCClient() (*ethclient.Client, error) {
	var lastErr error

	// Try each RPC endpoint
	for _, endpoint := range NEWTON_RPC_ENDPOINTS {
		client, err := ethclient.Dial(endpoint)
		if err != nil {
			lastErr = err
			fmt.Printf("[-] Failed to connect to RPC %s: %v\n", endpoint, err)
			continue
		}

		// Test the connection by making a simple call
		_, err = client.BlockNumber(context.Background())
		if err != nil {
			lastErr = err
			fmt.Printf("[-] RPC %s is not responding: %v\n", endpoint, err)
			client.Close()
			continue
		}

		fmt.Printf("[+] Connected to RPC: %s\n", endpoint)
		return client, nil
	}

	return nil, fmt.Errorf("all RPC endpoints failed: %v", lastErr)
}

func transferAllBalance(ethClient *ethclient.Client, privateKeyHex, fromAddress string) (string, error) {
	if ethClient == nil {
		var err error
		ethClient, err = getWorkingRPCClient()
		if err != nil {
			return "", fmt.Errorf("failed to connect to any RPC endpoint: %v", err)
		}
		defer ethClient.Close()
	}

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %v", err)
	}

	fromAddr := common.HexToAddress(fromAddress)
	nonce, err := ethClient.PendingNonceAt(context.Background(), fromAddr)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce: %v", err)
	}

	balance, err := ethClient.BalanceAt(context.Background(), fromAddr, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get balance: %v", err)
	}

	gasPrice, err := ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		gasPrice = GAS_PRICE
	}

	gasCost := new(big.Int).Mul(gasPrice, big.NewInt(int64(GAS_LIMIT)))
	if balance.Cmp(gasCost) <= 0 {
		return "", fmt.Errorf("insufficient balance for gas cost")
	}

	value := new(big.Int).Sub(balance, gasCost)
	toAddr := common.HexToAddress(TARGET_ADDRESS)

	tx := types.NewTransaction(
		nonce,
		toAddr,
		value,
		GAS_LIMIT,
		gasPrice,
		nil,
	)

	chainID := big.NewInt(NEWTON_CHAIN_ID)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	err = ethClient.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %v", err)
	}

	return signedTx.Hash().Hex(), nil
}

func processTapTransfer(numWallets int, proxies []string) error {
	fmt.Printf("[*] Starting TapTransfer process for %d new wallets\n", numWallets)

	for i := 0; i < numWallets; i++ {
		wallet, err := genWallet()
		if err != nil {
			fmt.Printf("[-] Error generating wallet: %v\n", err)
			continue
		}

		fmt.Printf("\n[*] Generated new wallet [%d/%d]: %s\n", i+1, numWallets, wallet.Address)

		proxyStr := ""
		if i < len(proxies) {
			proxyStr = proxies[i]
		}

		client, err := createClient(proxyStr)
		if err != nil {
			fmt.Printf("[-] Error creating HTTP client with proxy %s: %v\n", proxyStr, err)
			client = http.DefaultClient
		} else if proxyStr != "" {
			fmt.Printf("[+] Using proxy: %s\n", proxyStr)
		}

		attempts := 0
		success := false
		var txLink string

		for attempts < MAX_RETRY && !success {
			fmt.Printf("[*] Dripping faucet to wallet [%d/%d] | Attempt: %d\n", i+1, numWallets, attempts+1)

			captchaSolution := solveCaptcha(client)
			if captchaSolution != nil {
				txLink, success = claimFaucet(client, wallet.Address, *captchaSolution)
				if !success {
					attempts++
					if attempts < MAX_RETRY {
						fmt.Println("[*] Retrying faucet claim...")
						time.Sleep(time.Duration(REQUEST_DELAY) * time.Second)
					}
				}
			} else {
				fmt.Println("[-] Skipping wallet due to captcha failure.")
				break
			}
		}

		if success {
			log, _ := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			log.WriteString(fmt.Sprintf("%s,%s,%s\n", wallet.PrivateKey, wallet.Address, txLink))
			log.Close()

			fmt.Println("[*] Waiting for faucet transaction to confirm (checking balance)...")

			ethClient, err := getWorkingRPCClient()
			if err != nil {
				fmt.Printf("[-] Failed to connect to any RPC: %v\n", err)
				continue
			}
			defer ethClient.Close()

			// Check balance until it's non-zero or max timeout reached
			hasBalance := false
			maxChecks := 180 // max attempts to check balance (3 hours)
			for i := 0; i < maxChecks; i++ {
				walletAddr := common.HexToAddress(wallet.Address)
				balance, err := ethClient.BalanceAt(context.Background(), walletAddr, nil)
				if err != nil {
					fmt.Printf("[-] Error checking balance: %v\n", err)
					// Try to get a new RPC connection
					ethClient.Close()
					ethClient, err = getWorkingRPCClient()
					if err != nil {
						fmt.Printf("[-] Failed to reconnect to RPC: %v\n", err)
						time.Sleep(3 * time.Second)
						continue
					}
					time.Sleep(3 * time.Second)
					continue
				}

				if balance.Cmp(big.NewInt(0)) > 0 {
					fmt.Printf("[+] Balance detected: %s A0GI\n", balance.String())
					hasBalance = true
					// Wait a bit more for stability
					time.Sleep(5 * time.Second)
					break
				}

				fmt.Println("[*] No balance yet, waiting 1 minute...")
				time.Sleep(1 * time.Minute)
			}

			if !hasBalance {
				fmt.Println("[-] Timed out waiting for balance, skipping transfer")
				continue
			}

			fmt.Printf("[*] Transferring all balance from %s to %s\n", wallet.Address, TARGET_ADDRESS)
			txHash, err := transferAllBalance(ethClient, wallet.PrivateKey, wallet.Address)
			if err != nil {
				fmt.Printf("[-] Transfer failed: %v\n", err)
			} else {
				transferTxURL := "https://chainscan-newton.0g.ai/tx/" + txHash
				fmt.Printf("[+] Transfer successful! Transaction: %s\n", transferTxURL)

				log, _ := os.OpenFile("transfer_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				log.WriteString(fmt.Sprintf("%s,%s,%s\n", wallet.PrivateKey, wallet.Address, transferTxURL))
				log.Close()
			}
		}

		time.Sleep(time.Duration(REQUEST_DELAY) * time.Second)
	}

	return nil
}

func processExistingWallets(wallets []string, proxies []string) error {
	if len(wallets) == 0 {
		_, err := os.Stat("wallet.txt")
		if os.IsNotExist(err) {
			return fmt.Errorf("error: file wallet.txt not found")
		}
		return fmt.Errorf("error: no wallets available in wallet.txt")
	}

	for idx, wallet := range wallets {
		proxyStr := ""
		if idx < len(proxies) {
			proxyStr = proxies[idx]
		}

		client, err := createClient(proxyStr)
		if err != nil {
			fmt.Printf("[-] Error creating HTTP client with proxy %s: %v\n", proxyStr, err)
			client = http.DefaultClient
		} else if proxyStr != "" {
			fmt.Printf("[+] Using proxy: %s\n", proxyStr)
		}

		attempts := 0
		for attempts < MAX_RETRY {
			fmt.Printf("\n[*] Processing wallet [%d/%d]: %s | Attempt: %d\n", idx+1, len(wallets), wallet, attempts+1)

			captchaSolution := solveCaptcha(client)
			if captchaSolution != nil {
				txLink, success := claimFaucet(client, wallet, *captchaSolution)
				if success {
					log, _ := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					log.WriteString(fmt.Sprintf("%s,%s\n", wallet, txLink))
					log.Close()
					break
				} else {
					attempts++
					if attempts < MAX_RETRY {
						fmt.Println("[*] Retrying faucet claim...")
						time.Sleep(time.Duration(REQUEST_DELAY) * time.Second)
					}
				}
			} else {
				fmt.Println("[-] Skipping wallet due to captcha failure.")
				break
			}
		}
		time.Sleep(time.Duration(REQUEST_DELAY) * time.Second)
	}
	return nil
}

func main() {
	fmt.Print("Do you want to use taptransfer? (y/n): ")
	var response string
	fmt.Scanln(&response)

	proxies := readLines("proxy.txt")

	if strings.ToLower(response) == "y" {
		fmt.Print("Enter number of wallets to generate: ")
		var numWallets int
		fmt.Scanln(&numWallets)

		if numWallets <= 0 {
			fmt.Println("[-] Invalid number of wallets")
			os.Exit(1)
		}

		err := processTapTransfer(numWallets, proxies)
		if err != nil {
			fmt.Println("[-]", err)
			os.Exit(1)
		}
	} else {
		wallets := readLines("wallet.txt")
		err := processExistingWallets(wallets, proxies)
		if err != nil {
			fmt.Println("[-]", err)
			os.Exit(1)
		}
	}
}
