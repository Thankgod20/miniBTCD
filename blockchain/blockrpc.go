// blockchainrpc
package blockchain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"minibtcd/trx"
	"strings"
)

type GetVerifyTransactionArgs struct{ TransactionID string }
type GetBlockArgs struct{ TransactionID string }
type GetLatestBlockArgs struct{}
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
func (bc *Blockchain) GetTX(args *GetTransactionReply, reply *GetLatestBlockReply) error {
	//var isExist bool
	for _, block := range bc.Blocks {
		/*trxID, err := hex.DecodeString(args.TransactionID)
		if err != nil {
			log.Println("Error Decode Verify Tx", err)
		}*/
		//if block.VerifyTransaction(trxID) {
		//isExist := true
		//log.Println("iii", i)
		for _, txDetail := range block.Transactions {
			if IsSegWitTransaction(txDetail) {
				txS := hex.EncodeToString(txDetail)
				segTx, err := trx.FromSegWitHex(txS)
				if err != nil {
					log.Println("Decode Genesis Hex Error:", err)
				}
				if hex.EncodeToString(segTx.ID) == args.TransactionID {
					reply.JSONString = segTx.ToString() //("True")
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
					reply.JSONString = trnx.ToString() //("True")
					log.Println("Transaction exists in the blockchain.")
					break
				}

			}
		}
		//break
		//}
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
