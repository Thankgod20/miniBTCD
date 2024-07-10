// blockchainrpc
package blockchain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/Thankgod20/miniBTCD/mempool"
	"github.com/Thankgod20/miniBTCD/trx"
)

type GetVerifyTransactionArgs struct{ TransactionID string }
type GetBlockArgs struct{ TransactionID string }
type GetLatestBlockArgs struct{}
type GetAddressHistoryArgs struct {
	Address string
}
type GetAddressHistoryReply struct {
	TransactionHexMempool []string
	TransactionHex        []string
}
type GetTransactionsArgs struct {
	//Transactions *trx.Transaction
	//SegWit       *trx.SegWit
	TransactionHex string
}
type GetTransactionReply struct {
	TransactionID string
}
type GetBlockReply struct {
	Block string
}
type GetLatestBlockReply struct {
	JSONBlock  []byte
	JSONString string
}
type GetBalanceArgs struct {
	Address string
	Amount  int
}

func (b *Blockchain) GetLatestBlock(args *GetLatestBlockArgs, reply *GetLatestBlockReply) error {
	jsonBlock, err := b.GetLatestBlockJSON()
	if err != nil {
		return err
	}

	reply.JSONString = jsonBlock
	return nil
}
func (bc *Blockchain) GetLatestBlockJSON() (string, error) {
	if len(bc.Blocks) == 0 {
		return "", errors.New("blockchain is empty")
	}

	latestBlock := bc.Blocks[len(bc.Blocks)-1]
	/*jsonBlock, err := json.Marshal(latestBlock)
	if err != nil {
		return nil, errors.New("failed to marshal block")
	}*/
	jsonBlock := ToBlockString(*latestBlock)
	log.Println("Getting Latest Block:", len(bc.Blocks)-1)
	return jsonBlock, nil
}

func (bc *Blockchain) GetCurrentHeight(args *GetLatestBlockArgs, reply *GetLatestBlockReply) error {
	currentHeight := len(bc.Blocks) - 1
	jsonBlock, err := json.Marshal(currentHeight)
	if err != nil {
		return errors.New("failed to marshal block")
	}
	reply.JSONBlock = jsonBlock
	return nil
}
func (bc *Blockchain) GetUTXOSScripttHash(args *GetBalanceArgs, reply *GetAddressHistoryReply) error {

	//var scriptpubKey string = args.Address
	scriptHash, _ := hex.DecodeString(args.Address)
	scriptpubKey := trx.ReverseBytes(scriptHash)
	log.Printf("Get UTXO By Hash Reversed: %x", scriptpubKey)

	collected, ids := bc.UTXOSet.GetUTXOsOfScriptHash(hex.EncodeToString(scriptpubKey))
	var allutxos []string
	for i, id := range ids {
		sliptId := strings.Split(id, ":")
		tx_hash := sliptId[0]
		tx_pos := sliptId[1]
		value := collected[i][id].Value
		height := getBlockDetailOfTx(tx_hash, *bc, "Height")
		utxos := fmt.Sprintf("{ \"tx_pos\":%s , \"value\": %d, \"tx_hash\": \"%s\",\"height\": %d }", tx_pos, value, tx_hash, height)
		allutxos = append(allutxos, utxos)
	}
	reply.TransactionHex = allutxos
	return nil
}

func getBlockDetailOfTx(txID string, bc Blockchain, getType string) any {
	for _, block := range bc.Blocks {

		for _, txDetail := range block.Transactions {
			if IsSegWitTransaction(txDetail) {
				txS := hex.EncodeToString(txDetail)
				segTx, err := trx.FromSegWitHex(txS)
				if err != nil {
					log.Println("Decode Genesis Hex Error:", err)
				}
				if hex.EncodeToString(segTx.ID) == txID {
					switch getType {
					case "Height":
						return block.Height

					}
				}
			} else {
				txS := hex.EncodeToString(txDetail)
				trnx, err := trx.FromHex(txS)
				if err != nil {
					log.Println("Decode Genesis Hex Error:", err)
				}
				if hex.EncodeToString(trnx.ID) == txID {
					switch getType {
					case "Height":
						return block.Height

					}
				}
			}
		}
	}
	return nil
}
func (bc *Blockchain) GetBalanceWitScripttHash(args *GetBalanceArgs, reply *GetLatestBlockReply) error {
	var scriptpubKey string = args.Address
	var publickeyhash string = ""
	var coinbase string = ""
	_, total := bc.UTXOSet.UTXOAddressBalance(scriptpubKey, coinbase+publickeyhash)

	jsonBlock, err := json.Marshal(total)
	if err != nil {
		return errors.New("failed to marshal block")
	}
	reply.JSONBlock = jsonBlock
	return nil
}
func (bc *Blockchain) GetBalanceByHash(args *GetBalanceArgs, reply *GetLatestBlockReply) error {
	//var scriptpubKey string = args.Address
	var publickeyhash string = ""
	var coinbase string = ""
	scriptHash, _ := hex.DecodeString(args.Address)
	scriptpubKey := trx.ReverseBytes(scriptHash)
	log.Printf("Get Balance By Hash Reversed: %x", scriptpubKey)
	_, total := bc.UTXOSet.UTXOAddressBalance(hex.EncodeToString(scriptpubKey), coinbase+publickeyhash)

	jsonBlock, err := json.Marshal(total)
	if err != nil {
		return errors.New("failed to marshal block")
	}
	reply.JSONBlock = jsonBlock
	return nil
}
func (bc *Blockchain) GetBalance(args *GetBalanceArgs, reply *GetLatestBlockReply) error {
	var scriptpubKey string
	var publickeyhash string
	var coinbase string
	if strings.HasPrefix(args.Address, "1") {
		// P2PKH Get Public Key Hash from address
		r_pubKey, _ := trx.Base58Decode(args.Address)
		publickeyhash = hex.EncodeToString(r_pubKey)[2:42]
		// P2PKH Get length of the byte of the public key hash
		pubKeyByte, err := hex.DecodeString(publickeyhash)
		if err != nil {
			log.Println("error decoding Pubkey Byte for balance:", err)
		}
		pubkeylen := byte(len(pubKeyByte))

		//Script of the P2PKH
		pubKeyHashStr := "OP_DUP OP_HASH160 OP_PUSHBYTES_20 /" + publickeyhash + "/ OP_EQUALVERIFY OP_CHECKSIG"

		//Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		//Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)

		// Find enough UTXOs to cover the amount

		coinbase = hex.EncodeToString([]byte{0xc0, byte(len(pubKeyByte))})
	} else if strings.HasPrefix(args.Address, "3") {
		// P2SH Get Public Key Hash from address
		r_pubKey, _ := trx.Base58Decode(args.Address)
		publickeyhash = hex.EncodeToString(r_pubKey)[2:42]

		// P2SH Get length of the byte of the public key hash
		pubKeyByte, err := hex.DecodeString(publickeyhash)
		if err != nil {
			log.Println("error decoding Pubkey Byte for balance:", err)
		}
		pubkeylen := byte(len(pubKeyByte))

		//Script of the P2SH
		pubKeyHashStr := "OP_HASH160 OP_PUSHBYTES_20 /" + publickeyhash + "/ OP_EQUAL"
		//Script byte of the P2SH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		//Script hex of the P2Sh
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)

		// Find enough UTXOs to cover the amount

		coinbase = hex.EncodeToString([]byte{0xc0, 0x07, byte(len(pubKeyByte))})
	} else if strings.HasPrefix(args.Address, "bc1") {
		// Bech32 address (P2WPKH or P2WSH)
		_, r_pubKey, _ := trx.DecodeBech32(args.Address)
		decodedData, err := trx.ConvertBits(r_pubKey[1:], 5, 8, false)
		if err != nil {
			fmt.Println("Error Converting:", err)
			return err
		}
		publickeyhash = hex.EncodeToString(decodedData)
		pubKeyByte, err := hex.DecodeString(hex.EncodeToString(decodedData))
		if err != nil {
			log.Println("error decoding Pubkey Byte for balance:", err)
		}
		pubkeylen := byte(len(pubKeyByte))
		//pubkeylen := byte(len(hex.EncodeToString(decodedData)))
		pubKeyHashStr := "OP_0 OP_PUSHBYTES_20 /" + hex.EncodeToString(decodedData) + "/"
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)
		// Find enough UTXOs to cover the amount

		coinbase = hex.EncodeToString([]byte{0xc0, 0x10, byte(len(pubKeyByte))})
	} else {
		return errors.New("invalid address type")
	}

	log.Println("Script PubKey", scriptpubKey, "CoinBase Script", coinbase+publickeyhash)
	_, total := bc.UTXOSet.UTXOAddressBalance(scriptpubKey, coinbase+publickeyhash)

	jsonBlock, err := json.Marshal(total)
	if err != nil {
		return errors.New("failed to marshal block")
	}
	reply.JSONBlock = jsonBlock
	return nil
}
func (bc *Blockchain) GetAddressUTXOs(args *GetBalanceArgs, reply *GetLatestBlockReply) error {
	var scriptpubKey string
	var publickeyhash string
	var coinbase string
	if strings.HasPrefix(args.Address, "1") {
		// P2PKH Get Public Key Hash from address
		r_pubKey, _ := trx.Base58Decode(args.Address)
		publickeyhash = hex.EncodeToString(r_pubKey)[2:42]
		// P2PKH Get length of the byte of the public key hash
		pubKeyByte, err := hex.DecodeString(publickeyhash)
		if err != nil {
			log.Println("error decoding Pubkey Byte for balance:", err)
		}
		pubkeylen := byte(len(pubKeyByte))

		//Script of the P2PKH
		pubKeyHashStr := "OP_DUP OP_HASH160 OP_PUSHBYTES_20 /" + publickeyhash + "/ OP_EQUALVERIFY OP_CHECKSIG"

		//Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		//Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)

		// Find enough UTXOs to cover the amount

		coinbase = hex.EncodeToString([]byte{0xc0, byte(len(pubKeyByte))})
	} else if strings.HasPrefix(args.Address, "3") {
		// P2SH Get Public Key Hash from address
		r_pubKey, _ := trx.Base58Decode(args.Address)
		publickeyhash = hex.EncodeToString(r_pubKey)[2:42]

		// P2SH Get length of the byte of the public key hash
		pubKeyByte, err := hex.DecodeString(publickeyhash)
		if err != nil {
			log.Println("error decoding Pubkey Byte for balance:", err)
		}
		pubkeylen := byte(len(pubKeyByte))

		//Script of the P2SH
		pubKeyHashStr := "OP_HASH160 OP_PUSHBYTES_20 /" + publickeyhash + "/ OP_EQUAL"
		//Script byte of the P2SH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		//Script hex of the P2Sh
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)

		// Find enough UTXOs to cover the amount

		coinbase = hex.EncodeToString([]byte{0xc0, 0x07, byte(len(pubKeyByte))})
	} else if strings.HasPrefix(args.Address, "bc1") {
		// Bech32 address (P2WPKH or P2WSH)
		_, r_pubKey, _ := trx.DecodeBech32(args.Address)
		decodedData, err := trx.ConvertBits(r_pubKey[1:], 5, 8, false)
		if err != nil {
			fmt.Println("Error Converting:", err)
			return err
		}
		publickeyhash = hex.EncodeToString(decodedData)
		pubKeyByte, err := hex.DecodeString(hex.EncodeToString(decodedData))
		if err != nil {
			log.Println("error decoding Pubkey Byte for balance:", err)
		}
		pubkeylen := byte(len(pubKeyByte))
		//pubkeylen := byte(len(hex.EncodeToString(decodedData)))
		pubKeyHashStr := "OP_0 OP_PUSHBYTES_20 /" + hex.EncodeToString(decodedData) + "/"
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)
		// Find enough UTXOs to cover the amount

		coinbase = hex.EncodeToString([]byte{0xc0, 0x10, byte(len(pubKeyByte))})
	} else {
		return errors.New("invalid address type")
	}
	const SatoshiPerBitcoin = 100000000
	log.Println("Script PubKey", scriptpubKey, "CoinBase Script", coinbase+publickeyhash)
	collected, _ := bc.UTXOSet.UTXOAddress(scriptpubKey, coinbase+publickeyhash, (args.Amount * SatoshiPerBitcoin))

	jsonBlock, err := json.Marshal(collected)
	if err != nil {
		return errors.New("failed to marshal block")
	}
	reply.JSONBlock = jsonBlock
	return nil
}
func (bc *Blockchain) GetUTXOs(args *GetLatestBlockArgs, reply *GetLatestBlockReply) error {
	utxos := bc.UTXOSet

	jsonBlock, err := json.Marshal(utxos)
	if err != nil {
		return errors.New("failed to marshal block")
	}
	reply.JSONBlock = jsonBlock
	return nil
}

func (bc *Blockchain) VerifyTX(args *GetTransactionReply, reply *GetLatestBlockReply) error {
	//var isExist bool
	for _, block := range bc.Blocks {
		trxID, err := hex.DecodeString(args.TransactionID)
		if err != nil {
			log.Println("Error Decode Verify Tx", err)
		}
		if block.VerifyTransaction(trxID) {
			//isExist := true
			reply.JSONString = ("True")
			log.Println("Transaction exists in the blockchain.")
			break
		}
	}
	return nil
}
func (bc *Blockchain) GetFulTXElect(args *GetTransactionReply, reply *GetLatestBlockReply) error {
	//var isExist bool

	for _, block := range bc.Blocks {

		for _, txDetail := range block.Transactions {
			if IsSegWitTransaction(txDetail) {
				txS := hex.EncodeToString(txDetail)
				segTx, err := trx.FromSegWitHex(txS)
				if err != nil {
					log.Println("Decode Genesis Hex Error:", err)
				}
				if hex.EncodeToString(segTx.ID) == args.TransactionID {
					var lines []string
					lines = append(lines, "{")
					lines = append(lines, fmt.Sprintf("	\"blockhash\": \"%x\",", block.Hash))
					lines = append(lines, fmt.Sprintf("	\"blocktime\": %d,", block.Timestamp))
					lines = append(lines, fmt.Sprintf("	\"confirmations\": %d,", ((bc.Blocks[len(bc.Blocks)-1].Height-block.Height)+1)))
					lines = append(lines, fmt.Sprintf(" \"hash\": \"%x\",", segTx.ID))
					lines = append(lines, fmt.Sprintf(" \"hex\": \"%x\",", block.SerializeHeader()))
					//lines = append(lines, fmt.Sprintf("	\"locktime\": %d,", 0))
					lines = append(lines, fmt.Sprintf(" \"size\": %x,", byte(len(block.SerializeHeader()))))
					lines = append(lines, fmt.Sprintf("	\"time\": %d,", block.Timestamp))
					lines = append(lines, fmt.Sprintf(" \"txid\": \"%x\",", segTx.ID))
					lines = append(lines, fmt.Sprintf(" \"height\": %d,", block.Height))
					lines = append(lines, segTx.ToString())
					trxhex, _ := segTx.ToHex(false)
					lines = append(lines, fmt.Sprintf(" \"transactionHex\": \"%s\"", trxhex))
					lines = append(lines, "}")
					reply.JSONString = strings.Join(lines, "\n")
					segTx.ToHex(true) //("True")
					log.Println("Transaction exists in the blockchain.")
					break
				}
			} else {
				txS := hex.EncodeToString(txDetail)
				trnx, err := trx.FromHex(txS)
				if err != nil {
					log.Println("Decode Genesis Hex Error:", err)
				}
				if hex.EncodeToString(trnx.ID) == args.TransactionID {
					var lines []string
					lines = append(lines, "{")
					lines = append(lines, fmt.Sprintf("	\"blockhash\": \"%x\",", block.Hash))
					lines = append(lines, fmt.Sprintf("	\"blocktime\": %d,", block.Timestamp))
					lines = append(lines, fmt.Sprintf("	\"confirmations\": %d,", ((bc.Blocks[len(bc.Blocks)-1].Height-block.Height)+1)))
					lines = append(lines, fmt.Sprintf(" \"hash\": \"%x\",", trnx.ID))
					lines = append(lines, fmt.Sprintf(" \"hex\": \"%x\",", block.SerializeHeader()))
					//lines = append(lines, fmt.Sprintf("	\"locktime\": %d,", 0))
					lines = append(lines, fmt.Sprintf(" \"size\": %x,", byte(len(block.SerializeHeader()))))
					lines = append(lines, fmt.Sprintf("	\"time\": %d,", block.Timestamp))
					lines = append(lines, fmt.Sprintf(" \"txid\": \"%x\",", trnx.ID))
					lines = append(lines, fmt.Sprintf(" \"height\": %d,", block.Height))
					lines = append(lines, trnx.ToString())
					trxhex, _ := trnx.ToHex(false)
					lines = append(lines, fmt.Sprintf(" \"transactionHex\": \"%s\"", trxhex))
					lines = append(lines, "}")
					reply.JSONString = strings.Join(lines, "\n")
					trnx.ToHex(true)
					//reply.JSONString = trnx.ToString() //("True")
					log.Println("Transaction exists in the blockchain.")
					break
				}

			}
		}

	}
	return nil
}
func (bc *Blockchain) GetFulTX(args *GetTransactionReply, reply *GetLatestBlockReply) error {
	//var isExist bool

	for _, block := range bc.Blocks {

		for _, txDetail := range block.Transactions {
			if IsSegWitTransaction(txDetail) {
				txS := hex.EncodeToString(txDetail)
				segTx, err := trx.FromSegWitHex(txS)
				if err != nil {
					log.Println("Decode Genesis Hex Error:", err)
				}
				if hex.EncodeToString(segTx.ID) == args.TransactionID {
					var lines []string
					lines = append(lines, fmt.Sprintf("BlockHash: %x", block.Hash))
					lines = append(lines, fmt.Sprintf("Height: %d", block.Height))
					lines = append(lines, fmt.Sprintf("Hex: %x", block.SerializeHeader()))
					lines = append(lines, fmt.Sprintf("Confirmations: %d", ((bc.Blocks[len(bc.Blocks)-1].Height-block.Height)+1)))
					lines = append(lines, fmt.Sprintf("Size: %x", byte(len(block.SerializeHeader()))))
					lines = append(lines, fmt.Sprintf("Hash: %x", segTx.ID))
					lines = append(lines, fmt.Sprintf("Time: %d", block.Timestamp))
					lines = append(lines, segTx.ToString())
					trxhex, _ := segTx.ToHex(false)
					lines = append(lines, fmt.Sprintf("TransactionHex: %s", trxhex))
					reply.JSONString = strings.Join(lines, "\n")
					segTx.ToHex(true) //("True")
					log.Println("Transaction exists in the blockchain.")
					break
				}
			} else {
				txS := hex.EncodeToString(txDetail)
				trnx, err := trx.FromHex(txS)
				if err != nil {
					log.Println("Decode Genesis Hex Error:", err)
				}
				if hex.EncodeToString(trnx.ID) == args.TransactionID {
					var lines []string
					lines = append(lines, fmt.Sprintf("BlockHash: %x", block.Hash))
					lines = append(lines, fmt.Sprintf("Height: %d", block.Height))
					lines = append(lines, fmt.Sprintf("Hex: %x", block.SerializeHeader()))
					lines = append(lines, fmt.Sprintf("Size: %x", byte(len(block.SerializeHeader()))))
					lines = append(lines, fmt.Sprintf("Confirmations: %d", ((bc.Blocks[len(bc.Blocks)-1].Height-block.Height)+1)))
					lines = append(lines, fmt.Sprintf("Hash: %x", trnx.ID))
					lines = append(lines, fmt.Sprintf("Time: %d", block.Timestamp))
					lines = append(lines, trnx.ToString())
					trxhex, _ := trnx.ToHex(false)
					lines = append(lines, fmt.Sprintf("TransactionHex: %s", trxhex))
					reply.JSONString = strings.Join(lines, "\n")
					trnx.ToHex(true)
					//reply.JSONString = trnx.ToString() //("True")
					log.Println("Transaction exists in the blockchain.")
					break
				}

			}
		}

	}
	return nil
}
func (bc *Blockchain) GetTX(args *GetTransactionReply, reply *GetLatestBlockReply) error {
	//var isExist bool
	if txs, exists := bc.IndexTrx.TransactionByID[args.TransactionID]; exists {
		//return txIDs
		reply.JSONString = txs
	}

	return nil
}
func (bc *Blockchain) GetBlockRPC(args *GetBlockArgs, reply *GetBlockReply) error {
	log.Printf("[*][*] Getting Block: %s ....", args.TransactionID)
	block := bc.GetBlock(args.TransactionID)
	if block != "" {
		reply.Block = block
	}
	return nil
}
func (bc *Blockchain) GetTransactionHistory(args *GetAddressHistoryArgs, reply *GetAddressHistoryReply) error {
	//bc.IndexTrx[args.Address]
	var pubkeyHex string
	if strings.HasPrefix(args.Address, "1") && len(args.Address) == len("3Ag5RYpyspx4j8q9HFY1aJA3nLcK25AFHy") {
		// P2PKH address
		pubkey := mempool.GetP2PKHScript(args.Address)
		pubkeyHex = hex.EncodeToString(pubkey)
		log.Printf("Address PubKeyScript:%x", pubkey)
	} else if strings.HasPrefix(args.Address, "3") && len(args.Address) == len("3Ag5RYpyspx4j8q9HFY1aJA3nLcK25AFHy") {
		// P2SH address
		pubkey := mempool.GetP2SHScript(args.Address)
		pubkeyHex = hex.EncodeToString(pubkey)
		log.Printf("Address PubKeyScript:%x", pubkey)
	} else if strings.HasPrefix(args.Address, "bc1") {
		pubkey := mempool.GetP2PWKHScript(args.Address)
		pubkeyHex = hex.EncodeToString(pubkey)
		log.Printf("Address PubKeyScript:%x", pubkey)
	} else {
		scriptHash, _ := hex.DecodeString(args.Address)
		reversed := trx.ReverseBytes(scriptHash)
		if txIDs, exists := bc.IndexTrx.ScriptHashTransactionIndex[hex.EncodeToString(reversed)]; exists {
			//return txIDs
			reply.TransactionHex = txIDs
		}
		if memtxIDs, exists := bc.IndexTrx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(reversed)]; exists {
			//return txIDs
			reply.TransactionHexMempool = memtxIDs
		}
		return nil
	}
	if txIDs, exists := bc.IndexTrx.ScriptTransactionIndex[pubkeyHex]; exists {
		//return txIDs
		reply.TransactionHex = txIDs
	}
	if memtxIDs, exists := bc.IndexTrx.ScriptMempoolTransactionIndex[pubkeyHex]; exists {
		//return txIDs
		reply.TransactionHexMempool = memtxIDs
	}
	return nil
}
func (bc *Blockchain) GetTransactionHistoryScriptHash(args *GetAddressHistoryArgs, reply *GetAddressHistoryReply) error {
	//bc.IndexTrx[args.Address]

	scriptHash, _ := hex.DecodeString(args.Address)
	reversed := trx.ReverseBytes(scriptHash)
	//log.Printf("Getting Transaction History for reversed %x of %s ", reversed, args.Address)
	if txIDs, exists := bc.IndexTrx.ScriptHashTransactionIndex[hex.EncodeToString(reversed)]; exists {
		//return txIDs
		log.Println("Transaction Found for:", args.Address)
		reply.TransactionHex = txIDs
	}
	if memtxIDs, exists := bc.IndexTrx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(reversed)]; exists {
		//return txIDs
		log.Println("Transaction Mempool Found for:", args.Address)
		reply.TransactionHexMempool = memtxIDs
	}
	return nil

}
func (bc *Blockchain) AddToMempool(args *GetTransactionsArgs, reply *GetLatestBlockReply) error {
	log.Println("[*][*] Reciving Request to Add Trnx to Mempool ....")
	txhex := args.TransactionHex

	rawTx, err := hex.DecodeString(txhex)
	if err != nil {
		log.Fatalf("Failed to decode raw transaction: %v", err)
	}

	// Check if the transaction is SegWit
	isSegWit := IsSegWitTransaction(rawTx)

	if isSegWit {
		log.Println("Transaction Type: SegWit transaction detected.")
		// Process using SegWit decoder
		txn, err := trx.FromSegWitHex(txhex)
		if err != nil {
			log.Println("Error Decoding HexTX:", err)
		}
		untxn, err := trx.FromSegWitHex(txhex)
		if err != nil {
			log.Println("Error Decoding HexTX:", err)
		}
		trnkeep := untxn
		//fmt.Println("Decode Transaction To String", txhex, "---", hex.EncodeToString(txn.Inputs[0].ID))
		report := bc.Mempool.SubmitSegWitTransaction(txn, untxn, bc.UTXOSet)
		txn.ToHex(true)
		if report == "Successful" {
			bc.IndexTrx.IndexMempoolSegTransaction(untxn, false)
			for _, in := range trnkeep.Inputs {
				//fmt.Println("Removing from Mempool:", (hex.EncodeToString(in.ID)))
				if len(hex.EncodeToString(in.ID)) > 0 {
					bc.UTXOSet.RemoveUTXO(hex.EncodeToString(trx.ReverseBytes(in.ID)), in.Out)
				}
			}
			reply.JSONBlock = txn.ID
		} else {
			log.Println("report", report)

			reply.JSONString = (report)
		}
	} else {
		log.Println("Transaction Type: Non-SegWit transaction detected.")
		// Process using non-SegWit decoder
		txn, err := trx.FromHex(txhex)
		if err != nil {
			log.Println("Error Decoding HexTX:", err)
		}
		untxn, err := trx.FromHex(txhex)
		if err != nil {
			log.Println("Error Decoding HexTX:", err)
		}
		trnkeep := untxn
		//fmt.Println("Decode Transaction To String", txhex, "---", hex.EncodeToString(txn.Inputs[0].ID))
		report := bc.Mempool.SubmitTransaction(txn, untxn, bc.UTXOSet)
		txn.ToHex(true)
		if report == "Successful" {
			bc.IndexTrx.IndexMempoolTransaction(untxn, false)
			for _, in := range trnkeep.Inputs {
				//fmt.Println("Removing from Mempool:", (hex.EncodeToString(in.ID)))
				if len(hex.EncodeToString(in.ID)) > 0 {
					bc.UTXOSet.RemoveUTXO(hex.EncodeToString(trx.ReverseBytes(in.ID)), in.Out)
				}
			}
			reply.JSONBlock = txn.ID
		} else {
			log.Println("report", report)

			reply.JSONString = (report)
		}
	}
	//bc.Mempool.AddTransaction(args.Transactions)

	//reply.JSONBlock = args.Transactions.ID
	return nil
}
func IsSegWitTransaction(rawTx []byte) bool {
	// Minimum transaction length check
	if len(rawTx) < 10 {
		return false
	}

	inputsStart := 4
	if rawTx[inputsStart] == 0 && rawTx[inputsStart+1] != 0 {
		// SegWit marker found (0x00 followed by non-zero byte)
		return true
	}

	// No SegWit marker found
	return false
}
func (bc *Blockchain) MinersAddress(address string) {
	bc.Mempool.Miner = address
}
