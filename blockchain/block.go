// block.go
package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"log"
	"time"

	"github.com/Thankgod20/miniBTCD/trx"
)

type Block struct {
	Version       []byte
	Height        int
	Timestamp     uint32
	Bits          []byte
	Transactions  [][]byte //[]*trx.Transaction
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int
	MerkleRoot    []byte // Add this field
}

func (b *Block) CalculateMerkleRoot() []byte {

	var transactions [][]byte
	for _, tx := range b.Transactions {
		log.Println("Calculating Merkel Trees")
		if IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			txs, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			transactions = append(transactions, txs.ID)
		} else {
			txS := hex.EncodeToString(tx)

			txn, err := trx.FromHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex 1Error:", err)
			}
			transactions = append(transactions, txn.ID)
		}
	}
	log.Println("Done Calculating Merkel Trees")
	return NewMerkleTree(transactions).RootNode.Data
}

func (b *Block) SetHash() {
	var headers bytes.Buffer
	gob.NewEncoder(&headers).Encode(b.Timestamp)
	gob.NewEncoder(&headers).Encode(b.Transactions)
	gob.NewEncoder(&headers).Encode(b.PrevBlockHash)
	gob.NewEncoder(&headers).Encode(b.Nonce)
	hash := sha256.Sum256(headers.Bytes())
	b.Hash = hash[:]
}

func NewBlock(height int, transactions [][]byte, prevBlockHash []byte) *Block {
	block := &Block{
		Height:        height,
		Timestamp:     uint32(time.Now().Unix()),
		Transactions:  transactions,
		PrevBlockHash: prevBlockHash,
		Hash:          []byte{},
		Nonce:         0,
	}
	block.MerkleRoot = block.CalculateMerkleRoot()
	block.SetHash()
	//fmt.Println("Hash Obtained")
	return block
}

func GenesisBlock() *Block {
	tx := trx.CreateGenesisCoinbase("Genesis", "19z4W1LYKvdgdy8iA9sR9fo7dpKbTsZsQG", 1000)

	//trxString := tx.ToString()
	txx, _ := tx.ToHex(false) //TransactionToHex(tx, false)
	txbyte, err := hex.DecodeString(txx)
	if err != nil {
		log.Println("Decode Genesis Hex Error:", err)
	}
	//fmt.Println("Genesis Transaction:\n", trxString, "HexDecimal:\n", txx)
	var transactions [][]byte
	transactions = append(transactions, txbyte)
	return NewBlock(0, transactions, []byte{})
}
func (b *Block) HashTransactions() []byte {
	var txHashes [][]byte
	var txHash [32]byte

	for _, tx := range b.Transactions {
		if IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			segTx, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			txHashes = append(txHashes, segTx.ID)
		} else {
			txS := hex.EncodeToString(tx)
			tx, err := trx.FromHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			txHashes = append(txHashes, tx.ID)
		}
		//txHashes = append(txHashes, tx.ID)
	}
	txHash = sha256.Sum256(bytes.Join(txHashes, []byte{}))

	return txHash[:]
}
func (b *Block) RemoveTransaction(txID []byte) bool {
	var updatedTransactions [][]byte
	transactionFound := false

	for _, tx := range b.Transactions {
		if IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			txs, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			if !bytes.Equal(txs.ID, txID) {
				updatedTransactions = append(updatedTransactions, tx)
			} else {
				transactionFound = true
			}
		} else {
			txS := hex.EncodeToString(tx)
			txn, err := trx.FromHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			if !bytes.Equal(txn.ID, txID) {
				updatedTransactions = append(updatedTransactions, tx)
			} else {
				transactionFound = true
			}
		}
	}

	if !transactionFound {
		return false
	}

	b.Transactions = updatedTransactions
	b.MerkleRoot = b.CalculateMerkleRoot()
	b.SetHash()

	return true
}

// Converts the block's header fields to a byte slice in the correct order
func (b *Block) SerializeHeader() []byte {
	var result bytes.Buffer

	// Version (4 bytes, little-endian)
	if _, err := result.Write(b.Version); err != nil {
		log.Panic(err)
	}

	// Previous Block Hash (32 bytes, big-endian)
	if _, err := result.Write(b.PrevBlockHash); err != nil {
		log.Panic(err)
	}

	// Merkle Root (32 bytes, big-endian)
	if _, err := result.Write(b.MerkleRoot); err != nil {
		log.Panic(err)
	}

	// Timestamp (4 bytes, little-endian)
	timebytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timebytes, uint32(b.Timestamp))
	if _, err := result.Write(timebytes); err != nil {
		log.Panic(err)
	}
	// Bits (4 bytes, little-endian)
	if _, err := result.Write(b.Bits); err != nil {
		log.Panic(err)
	}

	// Nonce (4 bytes, little-endian)
	if err := binary.Write(&result, binary.LittleEndian, int32(b.Nonce)); err != nil {
		log.Panic(err)
	}

	return result.Bytes()
}
