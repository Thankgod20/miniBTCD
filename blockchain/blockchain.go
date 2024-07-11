// blockchain.go
package blockchain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/Thankgod20/miniBTCD/mempool"
	"github.com/Thankgod20/miniBTCD/trx"

	"github.com/go-redis/redis/v8"
)

type Blockchain struct {
	Blocks   []*Block
	rdb      *redis.Client
	Mempool  *mempool.Mempool
	UTXOSet  *mempool.UTXOSet
	IndexTrx *mempool.IndexTrx
}

func (bc *Blockchain) UpdateUTXOSet(block *Block) {
	for _, tx := range block.Transactions {
		if IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			segTx, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			for index, out := range segTx.Outputs {
				bc.UTXOSet.AddUTXO(hex.EncodeToString(segTx.ID), index, &out)
			}

			for _, in := range segTx.Inputs {
				fmt.Println(len(hex.EncodeToString(in.ID)))
				if len(hex.EncodeToString(in.ID)) > 0 {
					bc.UTXOSet.RemoveUTXO(hex.EncodeToString(in.ID), in.Out)
				}
			}
			bc.IndexTrx.IndexSegTransaction(segTx)
		} else {
			log.Println("Transacion Type Legacy")
			txS := hex.EncodeToString(tx)
			txn, err := trx.FromHex(txS)
			//fmt.Println("Tdff", txn.ToString())
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			for index, out := range txn.Outputs {
				bc.UTXOSet.AddUTXO(hex.EncodeToString(txn.ID), index, &out)
			}

			for _, in := range txn.Inputs {
				fmt.Println(len(hex.EncodeToString(in.ID)))
				if len(hex.EncodeToString(in.ID)) > 0 {
					bc.UTXOSet.RemoveUTXO(hex.EncodeToString(in.ID), in.Out)
				}
			}
			//Index Transactions
			bc.IndexTrx.IndexTransaction(txn)
		}
	}
}

func (bc *Blockchain) SaveBlock(block *Block) {

	blockData, err := json.Marshal(block)
	if err != nil {
		log.Fatal(err)
	}
	heightInt := len(bc.Blocks) - 1
	height := strconv.Itoa(heightInt)
	err = bc.rdb.Set(context.Background(), height+"_"+hex.EncodeToString(block.Hash), blockData, 0).Err()
	if err != nil {
		log.Fatal(err)
	}
}

func (bc *Blockchain) LoadBlocks() {
	keys, err := bc.rdb.Keys(context.Background(), "*").Result()
	if err != nil {
		log.Fatal(err)
	}

	// Extract numerical part from each key and store in a map
	keyMap := make(map[int]string)
	for _, key := range keys {
		// Assuming keys are in the format "x_xxxxxx"
		parts := strings.Split(key, "_")
		if len(parts) < 2 {
			continue
		}

		num, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Fatal(err)
		}

		keyMap[num] = key
	}

	// Extract and sort the numerical keys
	numKeys := make([]int, 0, len(keyMap))
	for num := range keyMap {
		numKeys = append(numKeys, num)
	}
	sort.Ints(numKeys)

	// Load blocks based on sorted numerical keys
	for _, num := range numKeys {
		key := keyMap[num]
		blockData, err := bc.rdb.Get(context.Background(), key).Bytes()
		if err != nil {
			log.Fatal(err)
		}

		var block Block
		err = json.Unmarshal(blockData, &block)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Loading Block from db:", key)
		bc.Blocks = append(bc.Blocks, &block)
		bc.UpdateUTXOSet(&block)
	}
}
func (bc *Blockchain) GetBlock(hash string) string {
	hashByte, err := hex.DecodeString(hash)
	if err != nil {
		log.Println(err)
	}
	var block string
	for _, blck := range bc.Blocks {
		if bytes.Equal(blck.Hash, hashByte) {
			block = ToBlockString(*blck)
			break
		}
	}
	return block
}
func ToBlockString(bc Block) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Version: %x", bc.Version))
	lines = append(lines, fmt.Sprintf("Height: %d", bc.Height))
	lines = append(lines, fmt.Sprintf("Time Stampe: %d", bc.Timestamp))
	for i, tx := range bc.Transactions {
		lines = append(lines, fmt.Sprintf("  Transactions %d:", i))
		lines = append(lines, fmt.Sprintf("          %x,", tx))

	}

	lines = append(lines, fmt.Sprintf("Prev Block Hash: %x", bc.PrevBlockHash))
	lines = append(lines, fmt.Sprintf("Block Hash: %x", bc.Hash))
	lines = append(lines, fmt.Sprintf("Bits : %x", bc.Bits))
	lines = append(lines, fmt.Sprintf("Nonce: %d", bc.Nonce))
	lines = append(lines, fmt.Sprintf("MerkleRoot: %x", bc.MerkleRoot))
	lines = append(lines, fmt.Sprintf("Hex: %x", bc.SerializeHeader()))
	return strings.Join(lines, "\n")
}

func NewBlockchain(rdb *redis.Client, address string) *Blockchain {

	bc := &Blockchain{
		Blocks:   []*Block{}, //[]*Block{genesisBlock},
		rdb:      rdb,
		Mempool:  mempool.NewMempool(),
		UTXOSet:  mempool.NewUTXOSet(),
		IndexTrx: mempool.NewMIndexTrx(),
	}
	bc.LoadBlocks()

	if len(bc.Blocks) == 0 {
		genesisBlock := GenesisBlock(address)

		bc.Blocks = append(bc.Blocks, genesisBlock)
		bc.SaveBlock(genesisBlock)
		bc.UpdateUTXOSet(genesisBlock)
	} else {
		log.Println("Loaded blockchain from Redis.")
	}
	return bc
}
