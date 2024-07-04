// miningblock.go
package mining

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/Thankgod20/miniBTCD/blockchain"
	"github.com/Thankgod20/miniBTCD/trx"
)

func AddBlock(transactions [][]byte /*[]*trx.Transaction*/, bc *blockchain.Blockchain) { //miner string) {
	// Remove transactions from the mempool
	for _, tx := range transactions {
		if blockchain.IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			segTx, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			bc.Mempool.RemoveTransaction(hex.EncodeToString(segTx.ID))
			// Check if transaction exists in any block
			for _, block := range bc.Blocks {
				if block.VerifyTransaction(segTx.ID) {
					log.Println("Transaction exists in the blockchain.")
					block.RemoveTransaction(segTx.ID)
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
			log.Println("Removing from Mempool:", (hex.EncodeToString(txn.ID)))
			// Check if transaction exists in any block
			for _, block := range bc.Blocks {
				if block.VerifyTransaction(txn.ID) {
					log.Println("Transaction exists in the blockchain.")
					block.RemoveTransaction(txn.ID)
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
	nonce, hash := pow.Run()
	// Set the new block's hash and nonce
	newBlock.Hash = hash[:]
	newBlock.Nonce = nonce
	fmt.Println("Nonce:", nonce, "New Hash:", hex.EncodeToString(hash))
	bc.Blocks = append(bc.Blocks, newBlock)
	bc.SaveBlock(newBlock)
	bc.UpdateUTXOSet(newBlock)
}
