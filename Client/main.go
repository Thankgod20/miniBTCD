package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"strings"

	"github.com/Thankgod20/miniBTCD/blockchain"
	"github.com/Thankgod20/miniBTCD/elliptical"
	"github.com/Thankgod20/miniBTCD/mempool"
	"github.com/Thankgod20/miniBTCD/trx"
	"github.com/Thankgod20/miniBTCD/wallet"
)

// PassPharse
func main() {
	client, err := rpc.Dial("tcp", "localhost:18885")
	if err != nil {
		log.Fatalf("Failed to connect to RPC server: %v", err)
	}
	getlatestblock := flag.Bool("latestblock", false, "Get Latest Block")
	getCurrentHeight := flag.Bool("blockheight", false, "Get Current Block Height")
	newWallet := flag.String("newWallet", "", "Create New Wallet")
	myWallet := flag.Bool("wallet", false, "Create New Wallet")
	balance := flag.String("balance", "", "Create New Wallet")
	address := flag.String("address", "", "Wallet Address")
	trnx := flag.String("createtx", "", "Enter PassPhrase")
	toAddress := flag.String("to", "", "Enter Recivers Address")
	value := flag.Int("amount", -1, "Enter amount")
	fee := flag.Float64("fees", -1, "Enter Fee")
	decodetx := flag.String("decodetx", "", "Enter Transaction Hex")
	bech32 := flag.Bool("bech32", false, "Bech32 Address format")
	p2PKH := flag.Bool("p2pkh", false, "p2PKH Address format")
	p2SH := flag.Bool("p2sh", false, "p2SH Address format")
	full := flag.Bool("full", false, "p2SH Address format")
	walletTye := flag.String("wallettype", "", "Wallet Type")
	scripthash := flag.String("scripthash", "", "Wallet Type")
	broadcast := flag.String("broadcast", "", "Wallet Type")
	verifyHash := flag.String("verifytxID", "", "verify  txID")
	getTrx := flag.String("getTrx", "", "Get  txID")
	getblock := flag.String("getblock", "", "Get  txID")
	getaddrhistry := flag.String("trnxs", "", "Get  txID")
	computTxID := flag.String("computTxID", "", "Get  txID")
	//getlatestBlock(client)
	flag.Parse()
	switch {
	case *getlatestblock:
		log.Println("Get Latest Block")
		getlatestBlock(client)
	case *computTxID != "":
		log.Println("Get Latest Block")
		computTxIDs(client, *computTxID)
	case *getaddrhistry != "":
		log.Println("Get Address History")
		getTrnxHistory(client, *getaddrhistry)
	case *scripthash != "":
		log.Println("Get ScriptHash ")
		getScriptHast(*scripthash)
	case *getblock != "":
		log.Println("Get Latest Block")
		getBlock(client, *getblock)
	case *getTrx != "":

		if *full {
			getFulTrXs(client, *getTrx)
		} else {
			log.Println("Get Transaction")
			getTrXs(client, *getTrx)
		}
	case *verifyHash != "":
		log.Println("Verify Transaction")
		verifyTXID(client, *verifyHash)
	case *getCurrentHeight:
		log.Println("Get Current Block Height")
		getcurrentHeight(client)
	case *newWallet != "":
		log.Println("Create New Wallet")
		switch {
		case *bech32:
			createWallet(*newWallet)
		case *p2PKH:
			createP2PKHWallet(*newWallet)
		case *p2SH:
			createP2SHWallet(*newWallet)
		default:
			log.Println("Must Specify type --bech32, --p2pkh,--p2sh")
		}

	case *decodetx != "":
		decodeTx(*decodetx)
	case *broadcast != "":
		broadcasttx(client, *broadcast)
	case *myWallet:

		// Check specific flags within wallet functionality
		switch {
		case *balance != "":
			fmt.Println("Fetching wallet balance...")
			// Perform get balance actio
			getBalance(client, *balance)
		case *address != "":
			log.Println("My Wallet")
			//createWallet(*address)
			switch {
			case *bech32:
				createWallet(*newWallet)
			case *p2PKH:
				createP2PKHWallet(*newWallet)
			case *p2SH:
				createP2SHWallet(*newWallet)
			default:
				log.Println("Must Specify type --bech32, --p2pkh,--p2sh")
			}
		case *trnx != "":
			var recvAddress string
			var amount int
			var fees float64
			if *toAddress != "" && *value != -1 && *walletTye != "" && *fee != -1 {
				recvAddress = *toAddress
				amount = *value
				fees = *fee
			} else {
				log.Println("Transaction must have to address and amount <app> --wallet --createtx=\"My name is Lartry\" --to=\"bc1qmfyzqsnp3zfxzd73xthv99hmq2pjda8tvc60pg\" --amount=10 --wallettype=\"p2pkh\"")
			}
			log.Println("Transfer To:", recvAddress)
			log.Println("Amount:", amount)
			createTx(client, recvAddress, amount, fees, *trnx, *walletTye)
		default:

		}
	default:
		log.Println("Usage <client.go> --<options>. Please use --latestblock.")
	}

}
func computTxIDs(client *rpc.Client, trxx string) {
	txBytes, err := hex.DecodeString(trxx)
	if err != nil {
		log.Println("Error Seting ID", err)
	}
	isSegWit := isSegWitTransaction(txBytes)
	if isSegWit {
		txID := trx.SegTxID(txBytes)
		log.Printf("Transaction ID : %x", txID)
	} else {
		txID := elliptical.ComputeTransactionID(txBytes)
		log.Printf("Transaction ID : %x", txID)
	}
}
func getScriptHast(address string) {
	if strings.HasPrefix(address, "1") {
		// P2PKH address
		pubkey := mempool.GetP2PKHScript(address)
		//pubkeyHex = hex.EncodeToString(pubkey)
		log.Printf("Address PubKeyScript:%x", pubkey)
		log.Printf("Address ScriptHash:%x", mempool.SingleSha256(pubkey))
		log.Printf("Address ScriptHash Electrun:%x", trx.ReverseBytes(mempool.SingleSha256(pubkey)))
	} else if strings.HasPrefix(address, "3") {
		// P2SH address
		pubkey := mempool.GetP2SHScript(address)
		//pubkeyHex = hex.EncodeToString(pubkey)
		log.Printf("Address PubKeyScript:%x", pubkey)
		log.Printf("Address ScriptHash:%x", mempool.SingleSha256(pubkey))
		log.Printf("Address ScriptHash Electrun:%x", trx.ReverseBytes(mempool.SingleSha256(pubkey)))
	} else if strings.HasPrefix(address, "bc1") {
		pubkey := mempool.GetP2PWKHScript(address)
		//	pubkeyHex = hex.EncodeToString(pubkey)
		log.Printf("Address PubKeyScript:%x", pubkey)
		log.Printf("Address ScriptHash:%x", mempool.SingleSha256(pubkey))
		log.Printf("Address ScriptHash Electrun:%x", trx.ReverseBytes(mempool.SingleSha256(pubkey)))
	}
}
func getTrnxHistory(client *rpc.Client, address string) {
	args := blockchain.GetAddressHistoryArgs{Address: address}
	var reply blockchain.GetAddressHistoryReply

	err := client.Call("Blockchain.GetTransactionHistory", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	/*var block blockchain.Block
	err = json.Unmarshal(reply.JSONBlock, &block)
	if err != nil {
		log.Fatalf("Failed to unmarshal block JSON: %v", err)
	}*/

	fmt.Println("Trannsactions:", reply.TransactionHex, "Mempool", reply.TransactionHexMempool) //block)
}
func getlatestBlock(client *rpc.Client) {
	args := blockchain.GetLatestBlockArgs{}
	var reply blockchain.GetLatestBlockReply

	err := client.Call("Blockchain.GetLatestBlock", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	/*var block blockchain.Block
	err = json.Unmarshal(reply.JSONBlock, &block)
	if err != nil {
		log.Fatalf("Failed to unmarshal block JSON: %v", err)
	}*/

	fmt.Printf("Latest Block: %s\n", reply.JSONString) //block)
}
func getBlock(client *rpc.Client, blck string) {
	args := blockchain.GetBlockArgs{}
	var reply blockchain.GetBlockReply

	err := client.Call("Blockchain.GetBlockRPC", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	fmt.Printf(" Block: %s\n", reply.Block)
}
func verifyTXID(client *rpc.Client, txID string) {
	args := blockchain.GetVerifyTransactionArgs{TransactionID: txID}
	var reply blockchain.GetLatestBlockReply

	err := client.Call("Blockchain.VerifyTX", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	fmt.Printf("Trans: %+v\n", reply.JSONString)
}
func getTrXs(client *rpc.Client, txID string) {
	args := blockchain.GetVerifyTransactionArgs{TransactionID: txID}
	var reply blockchain.GetLatestBlockReply

	err := client.Call("Blockchain.GetTX", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	fmt.Printf("Trans: %+v\n", reply.JSONString)
}
func getFulTrXs(client *rpc.Client, txID string) {
	args := blockchain.GetVerifyTransactionArgs{TransactionID: txID}
	var reply blockchain.GetLatestBlockReply

	err := client.Call("Blockchain.GetFulTXElect", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	fmt.Printf("Trans: %+v\n", reply.JSONString)
}
func getcurrentHeight(client *rpc.Client) {
	args := blockchain.GetLatestBlockArgs{}
	var reply blockchain.GetLatestBlockReply

	err := client.Call("Blockchain.GetCurrentHeight", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	var height int
	err = json.Unmarshal(reply.JSONBlock, &height)
	if err != nil {
		log.Fatalf("Failed to unmarshal block JSON: %v", err)
	}

	fmt.Printf("Current Block Height: %+v\n", height)
}
func createWallet(seed string) {
	log.Println("Your Seed Phrase:", seed)
	myWallet, _ := wallet.NewWalletFromSeed(seed)
	log.Println("myWallet:", myWallet.Address)

}
func createP2PKHWallet(seed string) {
	log.Println("Your Seed Phrase:", seed)
	myWallet, _ := wallet.NewP2PKHWalletFromSeed(seed)
	log.Println("myWallet:", myWallet.Address)

}
func createP2SHWallet(seed string) {
	log.Println("Your Seed Phrase:", seed)
	myWallet, _ := wallet.NewP2SHWalletFromSeed(seed)
	log.Println("myWallet:", myWallet.Address)

}
func getBalance(client *rpc.Client, address string) {
	args := blockchain.GetBalanceArgs{Address: address}
	var reply blockchain.GetLatestBlockReply
	err := client.Call("Blockchain.GetBalance", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	var balance int
	err = json.Unmarshal(reply.JSONBlock, &balance)
	if err != nil {
		log.Fatalf("Failed to unmarshal block JSON: %v", err)
	}

	fmt.Printf("Current Address Balance: %+v\n", balance)
}
func createTx(client *rpc.Client, address string, amount int, fee float64, passphrase string, walletType string) {
	var myWallet *wallet.Wallet
	switch walletType {
	case "p2pkh":
		myWallet, _ = wallet.NewP2PKHWalletFromSeed(passphrase)
	case "p2sh":
		myWallet, _ = wallet.NewP2SHWalletFromSeed(passphrase)
	case "bech32":
		myWallet, _ = wallet.NewWalletFromSeed(passphrase)
	}

	log.Println("From:", myWallet.Address)

	//Create utxos Initializer
	args := blockchain.GetBalanceArgs{Address: myWallet.Address, Amount: amount} //blockchain.GetLatestBlockArgs{}
	var reply blockchain.GetLatestBlockReply
	err := client.Call("Blockchain.GetAddressUTXOs", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}

	var collected map[string]*trx.TXOutput //var utxos *mempool.UTXOSet
	err = json.Unmarshal(reply.JSONBlock, &collected)
	if err != nil {
		log.Fatalf("Failed to unmarshal block JSON: %v", err)
	}
	// Create and sign a transaction
	//log.Println("All UTXOS", collected)
	tx, err := myWallet.CreateTransaction(address, amount, fee, collected) //bc.UTXOSet)
	if err != nil {
		log.Fatal(err)
	}

	//trxString := tx.ToString()
	log.Println("Transaction:\n", tx)
	//trxHex, _ := tx.ToHex()
	//log.Println("Raw Trnx:\n", trxHex)
}
func decodeTx(txhex string) {
	rawTx, err := hex.DecodeString(txhex)
	if err != nil {
		log.Fatalf("Failed to decode raw transaction: %v", err)
	}

	// Check if the transaction is SegWit
	isSegWit := isSegWitTransaction(rawTx)

	if isSegWit {
		log.Println("Transaction Type: SegWit transaction detected.")
		// Process using SegWit decoder
		txn, err := trx.FromSegWitHex(txhex)
		if err != nil {
			log.Println("Error Decoding HexTX:", err)
		}
		readTx := txn.ToString()
		log.Printf("Transaction ID:%x\n", txn.ID)
		log.Println("Transaction:\n", readTx)
	} else {
		log.Println("Transaction Type: Non-SegWit transaction detected.")
		// Process using non-SegWit decoder
		txn, err := trx.FromHex(txhex)
		if err != nil {
			log.Println("Error Decoding HexTX:", err)
		}
		readTx := txn.ToString()
		log.Printf("Transaction ID:%x\n", txn.ID)
		log.Println("Transaction:\n", readTx)
	}

	/*
		txn, err := trx.FromHex(txhex)
		if err != nil {
			log.Println("Error Decoding HexTX:", err)
		}
		readTx := txn.ToString()
		log.Println("Transaction:\n", readTx)*/
}
func isSegWitTransaction(rawTx []byte) bool {
	// Minimum transaction length check
	if len(rawTx) < 10 {
		return false
	}

	// Version field (4 bytes)
	//version := rawTx[0:4]

	// Check for SegWit marker (varint for number of inputs)
	inputsStart := 4
	if rawTx[inputsStart] == 0 && rawTx[inputsStart+1] != 0 {
		// SegWit marker found (0x00 followed by non-zero byte)
		return true
	}

	// No SegWit marker found
	return false
}
func broadcasttx(client *rpc.Client, txhex string) {

	//Create utxos Initializer
	args := blockchain.GetTransactionsArgs{TransactionHex: txhex}
	var reply blockchain.GetLatestBlockReply
	err := client.Call("Blockchain.AddToMempool", &args, &reply)
	if err != nil {
		log.Fatalf("Failed to get latest block: %v", err)
	}
	if reply.JSONString == "" {
		trnxID := hex.EncodeToString(reply.JSONBlock)
		fmt.Println("Transaction ID", trnxID)
	} else {
		fmt.Println("Error", reply.JSONString)
	}
	//}

}
