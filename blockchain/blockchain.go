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

	"minibtcd/mempool"
	"minibtcd/trx"

	"github.com/go-redis/redis/v8"
)

type Blockchain struct {
	Blocks  []*Block
	rdb     *redis.Client
	Mempool *mempool.Mempool
	UTXOSet *mempool.UTXOSet
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
		} else {
			log.Println("Transacion Type Legacy")
			txS := hex.EncodeToString(tx)
			//log.Printf("\n--------------------------\n %s \n---------------------------------------\n", txS)
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
	// Sort keys in reverse lexicographical order
	sort.Strings(keys) //sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, key := range keys {
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
	lines = append(lines, fmt.Sprintf("Height: %d", bc.Height))
	lines = append(lines, fmt.Sprintf("Time Stampe: %d", bc.Timestamp))
	for i, tx := range bc.Transactions {
		lines = append(lines, fmt.Sprintf("  Transactions %d:", i))
		lines = append(lines, fmt.Sprintf("          %x,", tx))

	}

	lines = append(lines, fmt.Sprintf("Prev Block Hash: %x", bc.PrevBlockHash))
	lines = append(lines, fmt.Sprintf("Block Hash: %x", bc.Hash))
	lines = append(lines, fmt.Sprintf("Nonce: %d", bc.Nonce))
	lines = append(lines, fmt.Sprintf("MerkleRoot: %x", bc.MerkleRoot))
	return strings.Join(lines, "\n")
}

func NewBlockchain(rdb *redis.Client) *Blockchain {

	bc := &Blockchain{
		Blocks:  []*Block{}, //[]*Block{genesisBlock},
		rdb:     rdb,
		Mempool: mempool.NewMempool(),
		UTXOSet: mempool.NewUTXOSet(),
	}
	bc.LoadBlocks()

	if len(bc.Blocks) == 0 {
		genesisBlock := GenesisBlock()

		bc.Blocks = append(bc.Blocks, genesisBlock)
		bc.SaveBlock(genesisBlock)
		bc.UpdateUTXOSet(genesisBlock)
	} else {
		log.Println("Loaded blockchain from Redis.")
	}
	return bc
}

//02000000017aadab720dffecbafcbac19251b004099e10990857a7e829dbc8136889c6b081010000006c473046022100a67049d150051798c837d7ff135b944913d75ddf778a0a57a018a33aab2d242b02210081c73e2a56ef4338ed1139e43f5d72afc83112f731836559acba699f314ef4c301210298d002f19b185122928f1598a1867ea06f2616dd3f0ad5037f93cb378a46478d00000000020008af2f00000000160014628ba348bd752bfe879f1b31c203d6e551f3855e40ce671e160000001976a914628ba348bd752bfe879f1b31c203d6e551f3855e88ac00000000

//0200000001052db84fef6419bdceb2ee0e0efdc741a2a5605ff4a853d1cbb712b512986b1e010000006b473045022030be15467c35f2fc60b63c6aff74580c575fd72c15526f0db5c5ad47d8adc9390221008846b3eef8dbe69b82b7f5f72c21155a9a749ae98767b61c1a9500d4e22e359501210298d002f19b185122928f1598a1867ea06f2616dd3f0ad5037f93cb378a46478d00000000020008af2f00000000160014628ba348bd752bfe879f1b31c203d6e551f3855ec095de110000000017a914628ba348bd752bfe879f1b31c203d6e551f3855e8700000000
//02000000000103d954c41d9aff6b8f3b346b1afcab6ff37236a92695d006b8fd75552b0bac4c6f0000000000ffffffff7aadab720dffecbafcbac19251b004099e10990857a7e829dbc8136889c6b0810000000000ffffffffe5935f18c381ba2e7143f148fc269104158d2334a03279d5bdae919bb9eca4600100000000ffffffff0200f153650000000017a914628ba348bd752bfe879f1b31c203d6e551f3855e87204df10500000000160014628ba348bd752bfe879f1b31c203d6e551f3855e02493046022100ae7576e297adbb4585c3de9839a06dbef8a68776207936595d00f98c30105630022100b82748ed0db348465969a42bd6323ba4da5171317a83c9f20a49f7dc5be21f2601210298d002f19b185122928f1598a1867ea06f2616dd3f0ad5037f93cb378a46478d0248304502203d91b94dc36920afd321f0db80d3afd2ae82ee3fb93e7d9c6e0080b2344b595e022100fa1de3d5839b2cae84b50dcc89359b1f21b7601a620e152a52f7f8e2e07e34c501210298d002f19b185122928f1598a1867ea06f2616dd3f0ad5037f93cb378a46478d02493046022100fb29828e622b54e4a4c8ee0e086dffaba98c45b1e8940d690ae6b5c8f0832909022100cb9f7faf1c989c65916ba7a6f0d2ec22e3ba93bdd9458f747f13e54a41cc7e7501210298d002f19b185122928f1598a1867ea06f2616dd3f0ad5037f93cb378a46478d00000000
