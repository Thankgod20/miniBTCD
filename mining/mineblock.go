// miningblock.go
package mining

import (
	"encoding/hex"
	"log"

	"github.com/Thankgod20/miniBTCD/blockchain"
	"github.com/Thankgod20/miniBTCD/trx"
)

func CheckInputAddress(transactions [][]byte, bc *blockchain.Blockchain, allowedAddress string) bool {
	for _, tx := range transactions {
		if blockchain.IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			segTx, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			for _, input := range segTx.Witness {
				address := bc.IndexTrx.GetSegAddress(input)
				if address == allowedAddress {
					return true
				}
			}

		} else {
			txS := hex.EncodeToString(tx)
			txn, err := trx.FromHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}

			for _, input := range txn.Inputs {
				address := bc.IndexTrx.GetAddressFromSig(input)
				if address == allowedAddress {
					return true
				}
			}

		}
	}
	return false
}
func AddBlock(transactions [][]byte /*[]*trx.Transaction*/, bc *blockchain.Blockchain) { //miner string) {
	// Remove transactions from the mempool
	for i, tx := range transactions {
		if blockchain.IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			segTx, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			bc.Mempool.RemoveTransaction(hex.EncodeToString(segTx.ID))
			bc.IndexTrx.IndexMempoolSegTransaction(segTx, true)
			// Check if transaction exists in any block
			for _, block := range bc.Blocks {
				if block.VerifyTransaction(segTx.ID) {
					log.Println("Transaction exists in the blockchain.")
					for j, txx := range transactions {
						if j != i {
							transactions = append(transactions, txx)
						}
					}
					//block.RemoveTransaction(segTx.ID)
					log.Println("Transaction Removed From the Block.")
					//return
				}
			}
		} else {
			txS := hex.EncodeToString(tx)
			txn, err := trx.FromHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}

			bc.Mempool.RemoveTransaction(hex.EncodeToString(txn.ID))
			bc.IndexTrx.IndexMempoolTransaction(txn, true)
			log.Println("Removing from Mempool:", (hex.EncodeToString(txn.ID)))
			// Check if transaction exists in any block
			for ix, block := range bc.Blocks {
				if block.VerifyTransaction(txn.ID) {
					log.Println("Transaction exists in the blockchain.")
					for j, txx := range transactions {
						if j != ix {
							transactions = append(transactions, txx)
						}
					}
					log.Println("Transaction Removed From the Block.")
					//return
				}
			}
		}
	}
	//tx_coinbase := trx.CreateGenesisCoinbase("coinbase", miner, 1000)
	//transactions = append(transactions, tx_coinbase)
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := blockchain.NewBlock(prevBlock.Height+1, transactions, prevBlock.Hash)

	pow := NewProofOfWork(newBlock)
	nonce, bit, hash := pow.Run()
	// Set the new block's hash and nonce

	newBlock.Hash = hash[:]
	newBlock.Nonce = nonce
	newBlock.Bits = bit
	newBlock.Version = []byte{0x00, 0x00, 0x00, 0x20}
	log.Println("Nonce:", nonce, "New Hash:", hex.EncodeToString(hash), "Bit", hex.EncodeToString(bit))
	bc.Blocks = append(bc.Blocks, newBlock)
	bc.SaveBlock(newBlock)
	bc.UpdateUTXOSet(newBlock)
}
