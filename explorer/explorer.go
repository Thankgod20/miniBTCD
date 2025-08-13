package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/rpc"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Thankgod20/miniBTCD/blockchain"
)

const (
	BLOCKSTREAM_API_URL = "https://blockstream.info/api"
)

// Global RPC client and templates
var (
	rpcClient *rpc.Client
	//templates  *template.Template
	templates  map[string]*template.Template
	httpClient = &http.Client{Timeout: 10 * time.Second} // HTTP client for external APIs
)

// funcMap holds custom functions for use in templates.
var funcMap = template.FuncMap{
	"add":       func(a, b int) int { return a + b },
	"subtract":  func(a, b int) int { return a - b },
	"satsToBTC": func(sats int) float64 { return float64(sats) / 100_000_000 },
	"timeSince": func(ts int64) string {
		t := time.Unix(ts, 0)
		d := time.Since(t)
		if d.Minutes() < 60 {
			return fmt.Sprintf("%.0f minutes ago", d.Minutes())
		}
		if d.Hours() < 24 {
			return fmt.Sprintf("%.0f hours ago", d.Hours())
		}
		return fmt.Sprintf("%.0f days ago", d.Hours()/24)
	},
	"formatFloat": func(f float64) string { return fmt.Sprintf("%.2f", f) },
}

// --- NEW: Simplified Mainnet Home View ---
// This struct now holds only the latest blocks fetched from Blockstream.
type MainnetHomeView struct {
	LatestBlocks []BitcoinBlock
}
type MainnetAddressView struct {
	BitcoinAddress             // Embed the existing address stats struct
	Transactions   []BitcoinTx // Add a slice to hold the transaction history
}

// --- Data Structures for Templates ---
// Structs for Bitcoin Mainnet (from Blockstream API)
type BitcoinBlock struct {
	ID                string `json:"id"`
	Height            int    `json:"height"`
	Version           int    `json:"version"`
	Timestamp         int64  `json:"timestamp"`
	TxCount           int    `json:"tx_count"`
	Size              int    `json:"size"`
	Weight            int    `json:"weight"`
	MerkleRoot        string `json:"merkle_root"`
	PreviousBlockHash string `json:"previousblockhash"`
}

type BitcoinTx struct {
	Txid     string `json:"txid"`
	Version  int    `json:"version"`
	Locktime int    `json:"locktime"`
	Size     int    `json:"size"`
	Weight   int    `json:"weight"`
	Fee      int    `json:"fee"`
	Vin      []struct {
		Txid       string       `json:"txid"`
		Vout       int          `json:"vout"`
		Prevout    BitcoinTxOut `json:"prevout"`
		IsCoinbase bool         `json:"is_coinbase"`
	} `json:"vin"`
	Vout   []BitcoinTxOut `json:"vout"`
	Status struct {
		Confirmed   bool   `json:"confirmed"`
		BlockHeight int    `json:"block_height"`
		BlockHash   string `json:"block_hash"`
	} `json:"status"`
}

type BitcoinTxOut struct {
	ScriptPubKeyAddress string `json:"scriptpubkey_address"`
	Value               int    `json:"value"`
}

type BitcoinAddress struct {
	Address    string `json:"address"`
	ChainStats struct {
		FundedTxoCount int `json:"funded_txo_count"`
		FundedTxoSum   int `json:"funded_txo_sum"`
		SpentTxoCount  int `json:"spent_txo_count"`
		SpentTxoSum    int `json:"spent_txo_sum"`
		TxCount        int `json:"tx_count"`
	} `json:"chain_stats"`
	MempoolStats struct {
		TxCount int `json:"tx_count"`
	} `json:"mempool_stats"`
}
type BlockView struct {
	Hash          string    `json:"Hash"`
	PrevBlockHash string    `json:"PrevBlockHash"`
	Height        int       `json:"Height"`
	Timestamp     int64     `json:"Timestamp"`
	Nonce         int       `json:"Nonce"`
	Transactions  []*TXView `json:"Transactions"`
}

// TXView is the top-level structure for the transaction details.
// Tags have been corrected to match the lowercase JSON keys.
type TXView struct {
	ID        string         `json:"txid"`
	Version   int32          `json:"version"`
	Locktime  int32          `json:"locktime"`
	Vin       []TXInputView  `json:"vin"`
	Vout      []TXOutputView `json:"vout"`
	Hex       string         `json:"hex"`
	Size      int            `json:"size"`
	Blockhash string         `json:"blockhash"`
	Time      int64          `json:"time"`
}

// TXInputView correctly models the "vin" array elements.
type TXInputView struct {
	Txid      string        `json:"txid"`
	Vout      int           `json:"vout"`
	ScriptSig ScriptSigView `json:"scriptSig"`
	Witness   []string      `json:"witness,omitempty"`  // ADDED: Handles the witness data
	Sequence  uint32        `json:"sequence,omitempty"` // ADDED: For completeness
}

// ScriptSigView models the nested "scriptSig" object.
type ScriptSigView struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

func (s *ScriptSigView) UnmarshalJSON(data []byte) error {
	// Check if the data is a JSON object (starts with '{').
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		// To avoid an infinite loop of calling this same UnmarshalJSON method,
		// we create an 'alias' type and unmarshal the data into that.
		type alias ScriptSigView
		var temp alias

		if err := json.Unmarshal(data, &temp); err != nil {
			return err // If parsing the object fails, return the error.
		}
		// If successful, copy the data from the temporary alias to our struct.
		*s = ScriptSigView(temp)
		return nil
	}

	// If the data is not a JSON object, we assume it's the empty string `""` from
	// a SegWit transaction. In this case, we do nothing. The `ScriptSigView` struct
	// will correctly be left with its default zero-values (empty Asm and Hex strings).
	return nil
}

// TXOutputView correctly models the "vout" array elements.
type TXOutputView struct {
	Value        float64          `json:"value"` // Corrected to float64 to handle decimals
	N            int              `json:"n"`
	ScriptPubKey ScriptPubKeyView `json:"scriptPubKey"` // Corrected to be a struct
}

// ScriptPubKeyView models the complex nested "scriptPubKey" object.
type ScriptPubKeyView struct {
	Asm       string   `json:"asm"`
	Hex       string   `json:"hex"`
	Addresses []string `json:"addresses"`
	Type      string   `json:"type"`
}

type AddressView struct {
	Address               string
	Balance               int
	TransactionHex        []string
	TransactionHexMempool []string
}

type HomeView struct {
	CurrentHeight int
	LatestBlocks  []BlockView
}

// --- Main Function ---

func main() {
	var err error
	// Attempt to connect to the local miniBTCD RPC server
	rpcClient, err = rpc.Dial("tcp", "localhost:18885")
	if err != nil {
		log.Printf("Warning: Could not connect to local miniBTCD RPC server: %v", err)
		log.Println("Explorer will run in Bitcoin Mainnet-only mode for local features.")
	} else {
		log.Println("Successfully connected to miniBTCD RPC server.")
	}

	// Initialize templates
	//templates = template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*.html"))
	// --- NEW: Robust Template Loading ---
	templates = make(map[string]*template.Template)

	// Find all our layout files
	layouts, err := filepath.Glob("templates/_layout.html")
	if err != nil {
		log.Fatal(err)
	}

	// Find all our content pages
	pages, err := filepath.Glob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}

	// For each page, create its own template set that includes the layout
	for _, page := range pages {
		if strings.Contains(page, "_layout.html") {
			continue // Skip the layout file itself
		}

		// Each page gets the layout file + its own file.
		files := append(layouts, page)

		// The template is named after the file, e.g., "home.html"
		fileName := filepath.Base(page)
		templates[fileName] = template.Must(template.New(fileName).Funcs(funcMap).ParseFiles(files...))
	}
	// --- END of new template loading logic ---
	// Setup static file server
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// --- CORRECTED & SIMPLIFIED ROUTING ---
	// Homepage ("/") is the mainnet dashboard.
	http.HandleFunc("/", mainnetHomeHandler)

	// Search handler for both local and mainnet
	http.HandleFunc("/search", searchHandler)

	// Local miniBTCD routes are prefixed with "/lnd/"
	http.HandleFunc("/lnd/block/", localBlockHandler)
	http.HandleFunc("/lnd/tx/", localTxHandler)
	http.HandleFunc("/lnd/address/", localAddressHandler)

	// Bitcoin Mainnet routes for search results
	http.HandleFunc("/mainnet/block/", mainnetBlockHandler)
	http.HandleFunc("/mainnet/tx/", mainnetTxHandler)
	http.HandleFunc("/mainnet/address/", mainnetAddressHandler)
	// --- END OF ROUTING SECTION ---

	log.Println("Starting Hybrid CryptoNetX explorer on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

type ProfessionalHomeView struct {
	LatestBlocks []BitcoinBlock
	Stats        struct {
		LatestBlockHeight int
		AvgBlockTime      float64 // In minutes
		AvgTxsPerBlock    float64
		TotalTxsInView    int
	}
}

/*
// --- Mainnet Homepage Handler (No Mempool.space) ---
func mainnetHomeHandler(w http.ResponseWriter, r *http.Request) {
	var latestBlocks []BitcoinBlock
	// Fetch the 10 most recent blocks from Blockstream
	err := getJSON(fmt.Sprintf("%s/blocks/tip", BLOCKSTREAM_API_URL), &latestBlocks)
	if err != nil {
		renderError(w, "Could not fetch latest mainnet blocks", err)
		return
	}

	// Ensure we only show a maximum of 10 blocks
	if len(latestBlocks) > 10 {
		latestBlocks = latestBlocks[:10]
	}

	data := MainnetHomeView{
		LatestBlocks: latestBlocks,
	}

	err = templates.ExecuteTemplate(w, "home.html", data)
	if err != nil {
		renderError(w, "Failed to render homepage", err)
	}
}
*/
// --- Mainnet Homepage Handler (Updated for Professional Dashboard) ---
func mainnetHomeHandler(w http.ResponseWriter, r *http.Request) {
	var latestBlocks []BitcoinBlock
	// Fetch up to 12 recent blocks from Blockstream
	err := getJSON(fmt.Sprintf("%s/blocks/tip", BLOCKSTREAM_API_URL), &latestBlocks)
	if err != nil {
		renderError(w, "Could not fetch latest mainnet blocks", err)
		return
	}

	// Limit to 12 blocks for a clean grid layout
	if len(latestBlocks) > 12 {
		latestBlocks = latestBlocks[:12]
	}

	data := ProfessionalHomeView{
		LatestBlocks: latestBlocks,
	}

	// --- NEW: Calculate stats for the dashboard ---
	if len(latestBlocks) > 1 {
		data.Stats.LatestBlockHeight = latestBlocks[0].Height

		var totalTimeDiff int64
		var totalTxs int

		// Use max 11 intervals (12 blocks) for stats
		numIntervals := len(latestBlocks) - 1

		for i := 0; i < numIntervals; i++ {
			timeDiff := latestBlocks[i].Timestamp - latestBlocks[i+1].Timestamp
			totalTimeDiff += timeDiff
			totalTxs += latestBlocks[i].TxCount
		}
		totalTxs += latestBlocks[numIntervals].TxCount // Add the last block's TXs

		if numIntervals > 0 {
			data.Stats.AvgBlockTime = float64(totalTimeDiff) / float64(numIntervals) / 60.0 // in minutes
			data.Stats.AvgTxsPerBlock = float64(totalTxs) / float64(len(latestBlocks))
			data.Stats.TotalTxsInView = totalTxs
		}
	}

	// Render the template with the new data structure
	// OLD: err = templates.ExecuteTemplate(w, "home.html", data)
	err = templates["home.html"].ExecuteTemplate(w, "_layout.html", data) // NEW
	if err != nil {
		renderError(w, "Failed to render homepage", err)
	}
}

// --- HYBRID SEARCH HANDLER ---
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.FormValue("query"))
	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// --- 1. SEARCH LOCAL miniBTCD BLOCKCHAIN FIRST ---
	if rpcClient != nil {
		// Try as block height
		if height, err := strconv.Atoi(query); err == nil {
			if _, err := getBlockByHeight(height); err == nil {
				http.Redirect(w, r, "/lnd/block/"+query, http.StatusSeeOther)
				return
			}
		}
		// Try as block hash or transaction hash (64 chars)
		if len(query) == 64 {
			if _, err := getBlockByHash(query); err == nil {
				http.Redirect(w, r, "/lnd/block/"+query, http.StatusSeeOther)
				return
			}
			if _, err := getFullTx(query); err == nil {
				http.Redirect(w, r, "/lnd/tx/"+query, http.StatusSeeOther)
				return
			}
		}
		// Try as address
		if _, err := getAddressBalance(query); err == nil {
			http.Redirect(w, r, "/lnd/address/"+query, http.StatusSeeOther)
			return
		}
	}

	// --- 2. IF NOT FOUND LOCALLY, SEARCH BITCOIN MAINNET ---
	log.Printf("Query '%s' not found on local chain. Searching Bitcoin Mainnet...", query)
	// Try as block height on mainnet
	if _, err := strconv.Atoi(query); err == nil {
		hash, err := getBitcoinBlockHashFromHeight(query)
		if err == nil {
			http.Redirect(w, r, "/mainnet/block/"+hash, http.StatusSeeOther)
			return
		}
	}
	// Try as block hash or tx hash on mainnet
	if len(query) == 64 {
		// Check if it's a block
		if _, err := getBitcoinBlock(query); err == nil {
			http.Redirect(w, r, "/mainnet/block/"+query, http.StatusSeeOther)
			return
		}
		// Check if it's a transaction
		if _, err := getBitcoinTx(query); err == nil {
			http.Redirect(w, r, "/mainnet/tx/"+query, http.StatusSeeOther)
			return
		}
	}
	// Try as address on mainnet
	if _, err := getBitcoinAddress(query); err == nil {
		http.Redirect(w, r, "/mainnet/address/"+query, http.StatusSeeOther)
		return
	}

	renderError(w, "Search Not Found", fmt.Errorf("the query '%s' was not found on your local miniBTCD or the Bitcoin Mainnet", query))
}

func stringToInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// --- Bitcoin Mainnet Handlers ---
func mainnetBlockHandler(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimPrefix(r.URL.Path, "/mainnet/block/")
	block, err := getBitcoinBlock(hash)
	if err != nil {
		renderError(w, "Bitcoin Mainnet Block Not Found", err)
		return
	}
	// OLD: templates.ExecuteTemplate(w, "mainnet_block.html", block)
	templates["mainnet_block.html"].ExecuteTemplate(w, "_layout.html", block) // NEW
}

func mainnetTxHandler(w http.ResponseWriter, r *http.Request) {
	txid := strings.TrimPrefix(r.URL.Path, "/mainnet/tx/")
	tx, err := getBitcoinTx(txid)
	if err != nil {
		renderError(w, "Bitcoin Mainnet Transaction Not Found", err)
		return
	}
	// OLD: templates.ExecuteTemplate(w, "mainnet_transaction.html", tx)
	templates["mainnet_transaction.html"].ExecuteTemplate(w, "_layout.html", tx) // NEW
}

// getBitcoinAddressTxs fetches the list of transactions for a given mainnet address.
func getBitcoinAddressTxs(address string) ([]BitcoinTx, error) {
	var txs []BitcoinTx
	// The mempool.space API returns the most recent 25 transactions by default.
	url := fmt.Sprintf("%s/address/%s/txs", BLOCKSTREAM_API_URL, address)
	err := getJSON(url, &txs)
	return txs, err
}
func mainnetAddressHandler(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimPrefix(r.URL.Path, "/mainnet/address/")

	// 1. Fetch the address statistics (as before)
	addrInfo, err := getBitcoinAddress(address)
	if err != nil {
		renderError(w, "Bitcoin Mainnet Address Not Found", err)
		return
	}

	// 2. Fetch the transaction history for the address
	txs, err := getBitcoinAddressTxs(address)
	if err != nil {
		// If this fails, we can still show the page with a warning, or just fail completely.
		// For a better user experience, we'll log the error and show the page without the tx list.
		log.Printf("Warning: Could not fetch transaction history for %s: %v", address, err)
		txs = []BitcoinTx{} // Ensure txs is an empty slice, not nil
	}

	// 3. Combine both results into our new view model
	data := MainnetAddressView{
		BitcoinAddress: addrInfo,
		Transactions:   txs,
	}

	// 4. Render the template with the combined data
	err = templates["mainnet_address.html"].ExecuteTemplate(w, "_layout.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

/*
func mainnetAddressHandler(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimPrefix(r.URL.Path, "/mainnet/address/")
	addrInfo, err := getBitcoinAddress(address)
	if err != nil {
		renderError(w, "Bitcoin Mainnet Address Not Found", err)
		return
	}
	// OLD: templates.ExecuteTemplate(w, "mainnet_address.html", addrInfo)
	templates["mainnet_address.html"].ExecuteTemplate(w, "_layout.html", addrInfo) // NEW
}*/

// --- Local miniBTCD Handlers ---
func localBlockHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/lnd/block/")
	var block BlockView
	var err error

	if height, convErr := strconv.Atoi(id); convErr == nil {
		block, err = getBlockByHeight(height)
	} else {
		block, err = getBlockByHash(id)
	}

	if err != nil {
		renderError(w, fmt.Sprintf("Local Block not found: %s", id), err)
		return
	}

	// OLD: err = templates.ExecuteTemplate(w, "block.html", block)
	err = templates["block.html"].ExecuteTemplate(w, "_layout.html", block) // NEW
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func localTxHandler(w http.ResponseWriter, r *http.Request) {
	txid := strings.TrimPrefix(r.URL.Path, "/lnd/tx/")
	if len(txid) != 64 {
		renderError(w, "Invalid Local Transaction ID", fmt.Errorf("TXID must be 64 characters long"))
		return
	}

	tx, err := getFullTx(txid)
	if err != nil {
		renderError(w, "Local Transaction not found", err)
		return
	}

	// OLD: err = templates.ExecuteTemplate(w, "transaction.html", tx)
	err = templates["transaction.html"].ExecuteTemplate(w, "_layout.html", tx) // NEW
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func localAddressHandler(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimPrefix(r.URL.Path, "/lnd/address/")

	balance, err := getAddressBalance(address)
	if err != nil {
		renderError(w, "Could not fetch local address balance", err)
		return
	}

	history, err := getAddressHistory(address)
	if err != nil {
		renderError(w, "Could not fetch local address history", err)
		return
	}

	data := AddressView{
		Address:               address,
		Balance:               balance,
		TransactionHex:        history.TransactionHex,
		TransactionHexMempool: history.TransactionHexMempool,
	}

	// OLD: err = templates.ExecuteTemplate(w, "address.html", data)
	err = templates["address.html"].ExecuteTemplate(w, "_layout.html", data) // NEW
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// --- API Helper Functions ---
func getBitcoinBlock(hash string) (BitcoinBlock, error) {
	var block BitcoinBlock
	err := getJSON(fmt.Sprintf("%s/block/%s", BLOCKSTREAM_API_URL, hash), &block)
	return block, err
}

func getBitcoinTx(txid string) (BitcoinTx, error) {
	var tx BitcoinTx
	err := getJSON(fmt.Sprintf("%s/tx/%s", BLOCKSTREAM_API_URL, txid), &tx)
	return tx, err
}

func getBitcoinAddress(address string) (BitcoinAddress, error) {
	var addr BitcoinAddress
	err := getJSON(fmt.Sprintf("%s/address/%s", BLOCKSTREAM_API_URL, address), &addr)
	return addr, err
}

func getBitcoinBlockHashFromHeight(height string) (string, error) {
	url := fmt.Sprintf("%s/block-height/%s", BLOCKSTREAM_API_URL, height)
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %s: %s", resp.Status, string(body))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Generic helper to fetch and unmarshal JSON from an API
func getJSON(url string, target interface{}) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API request to %s failed with status %s: %s", url, resp.Status, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// --- RPC Helper Functions for miniBTCD ---
func getCurrentHeight() (int, error) {
	if rpcClient == nil {
		return -1, fmt.Errorf("not connected to miniBTCD RPC server")
	}
	args := blockchain.GetLatestBlockArgs{}
	var reply blockchain.GetLatestBlockReply
	err := rpcClient.Call("Blockchain.GetCurrentHeight", &args, &reply)
	if err != nil {
		return -1, err
	}
	var height int
	err = json.Unmarshal(reply.JSONBlock, &height)
	return height, err
}

func getBlockByHash(hash string) (BlockView, error) {
	if rpcClient == nil {
		return BlockView{}, fmt.Errorf("not connected to miniBTCD RPC server")
	}
	args := blockchain.GetBlockArgs{TransactionID: hash}
	var reply blockchain.GetBlockReply
	var block BlockView

	err := rpcClient.Call("Blockchain.GetBlockRPC", &args, &reply)
	if err != nil || reply.Block == "" {
		return block, fmt.Errorf("block with hash %s not found: %w", hash, err)
	}
	err = json.Unmarshal([]byte(reply.Block), &block)
	return block, err
}

func getBlockByHeight(height int) (BlockView, error) {
	var block BlockView

	// Step 1: Get latest block
	var latestReply blockchain.GetLatestBlockReply
	err := rpcClient.Call("Blockchain.GetLatestBlock", &blockchain.GetLatestBlockArgs{}, &latestReply)
	if err != nil {
		return block, fmt.Errorf("failed to get latest block: %w", err)
	}
	err = json.Unmarshal(latestReply.JSONBlock, &block)
	if err != nil {
		return block, fmt.Errorf("failed to parse latest block: %w", err)
	}

	// Step 2: Walk backwards until we hit the target height
	for block.Height > height {
		if len(block.Transactions) == 0 {
			return block, fmt.Errorf("no transactions in block at height %d", block.Height)
		}

		// Use the first transaction's ID to fetch the previous block
		prevTxID := block.Transactions[0].ID

		var prevReply blockchain.GetBlockReply
		err := rpcClient.Call("Blockchain.GetBlockRPC",
			&blockchain.GetBlockArgs{TransactionID: prevTxID},
			&prevReply)
		if err != nil {
			return block, fmt.Errorf("failed to get block for tx %s: %w", prevTxID, err)
		}

		if prevReply.Block == "" {
			return block, fmt.Errorf("block not found for tx %s", prevTxID)
		}

		err = json.Unmarshal([]byte(prevReply.Block), &block)
		if err != nil {
			return block, fmt.Errorf("failed to parse block JSON: %w", err)
		}
	}

	if block.Height != height {
		return block, fmt.Errorf("block at height %d not found", height)
	}

	return block, nil
}

func getFullTx(txid string) (TXView, error) {
	if rpcClient == nil {
		return TXView{}, fmt.Errorf("not connected to miniBTCD RPC server")
	}
	log.Printf("Fetching full transaction for ID: %s", txid)
	args := blockchain.GetVerifyTransactionArgs{TransactionID: txid}
	var reply blockchain.GetLatestBlockReply
	var tx TXView // This will now be the new, corrected TXView struct

	err := rpcClient.Call("Blockchain.GetFulTXElect", &args, &reply)
	if err != nil {
		return tx, err
	}
	if reply.JSONString == "" || reply.JSONString == "null" {
		return tx, fmt.Errorf("transaction %s not found", txid)
	}

	// This is great for debugging! It shows you the raw data.
	log.Printf("Trans: %+v\n", reply.JSONString)

	// With the corrected structs, this unmarshal will now succeed.
	err = json.Unmarshal([]byte(reply.JSONString), &tx)
	return tx, err
}

func getAddressBalance(address string) (int, error) {
	if rpcClient == nil {
		return 0, fmt.Errorf("not connected to miniBTCD RPC server")
	}
	args := blockchain.GetBalanceArgs{Address: address}
	var reply blockchain.GetLatestBlockReply
	err := rpcClient.Call("Blockchain.GetBalance", &args, &reply)
	if err != nil {
		return 0, err
	}
	var balance int
	err = json.Unmarshal(reply.JSONBlock, &balance)
	return balance, err
}

func getAddressHistory(address string) (blockchain.GetAddressHistoryReply, error) {
	if rpcClient == nil {
		return blockchain.GetAddressHistoryReply{}, fmt.Errorf("not connected to miniBTCD RPC server")
	}
	args := blockchain.GetAddressHistoryArgs{Address: address}
	var reply blockchain.GetAddressHistoryReply
	err := rpcClient.Call("Blockchain.GetTransactionHistory", &args, &reply)
	return reply, err
}

func renderError(w http.ResponseWriter, message string, err error) {
	log.Printf("ERROR: %s - %v", message, err)
	w.WriteHeader(http.StatusNotFound)
	data := struct {
		Title   string
		Message string
	}{
		Title:   message,
		Message: err.Error(),
	}
	// OLD: templates.ExecuteTemplate(w, "error.html", data)
	templates["error.html"].ExecuteTemplate(w, "_layout.html", data) // NEW
}
