// utxoset.go
package mempool

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Thankgod20/miniBTCD/trx"
)

type UTXOSet struct {
	UTXOs map[string]*trx.TXOutput
	//AddressBalance map[string][]string
	mutex sync.Mutex
}

func NewUTXOSet() *UTXOSet {
	fmt.Println("New UTXOS")
	return &UTXOSet{UTXOs: make(map[string]*trx.TXOutput)}
}

func (u *UTXOSet) AddUTXO(txID string, index int, output *trx.TXOutput) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	u.UTXOs[fmt.Sprintf("%s:%d", txID, index)] = output

	log.Printf("[*] Updated UTXOs: %s", txID) //, (u.UTXOs))
}

func (u *UTXOSet) RemoveUTXO(txID string, index int) {

	u.mutex.Lock()
	defer u.mutex.Unlock()

	delete(u.UTXOs, fmt.Sprintf("%s:%d", txID, index))

	log.Printf("Removed from UTXO:%s", txID)
}

func (u *UTXOSet) FindUTXO(to string, amount int) (map[string]*trx.TXOutput, int) { //(scriptpubKey, pubKeyHash string, amount int) (map[string]*trx.TXOutput, int) {
	fmt.Println("Searching UTXOS")
	u.mutex.Lock()
	defer u.mutex.Unlock()
	collected := make(map[string]*trx.TXOutput)
	var scriptpubKey string
	var coinbaseTx string
	if strings.HasPrefix(to, "1") {
		// P2PKH address
		pubKeyh, _ := trx.Base58Decode(to)

		pubKeyHash := hex.EncodeToString(pubKeyh)[2:42]
		r_pubkey, err := hex.DecodeString(pubKeyHash)
		pubkeylen := byte(len(r_pubkey))
		// Script of the P2PKH
		pubKeyHashStr := "OP_DUP OP_HASH160 OP_PUSHBYTES_20 /" + pubKeyHash + "/ OP_EQUALVERIFY OP_CHECKSIG"

		// Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		// Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)

		//Coinbase TX

		coinbase := hex.EncodeToString([]byte{0xc0, pubkeylen})
		coinbaseTx = coinbase + pubKeyHash

	} else if strings.HasPrefix(to, "3") {
		// P2SH address
		pubKeyh, _ := trx.Base58Decode(to)

		pubKeyHash := hex.EncodeToString(pubKeyh)[2:42]
		r_pubkey, err := hex.DecodeString(pubKeyHash)
		pubkeylen := byte(len(r_pubkey))
		// Script of the P2PKH
		pubKeyHashStr := "OP_HASH160 OP_PUSHBYTES_20 /" + pubKeyHash + "/ OP_EQUAL"

		// Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		// Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)
		//Coinbase TX

		coinbase := hex.EncodeToString([]byte{0xc0, 0x07, pubkeylen})
		coinbaseTx = coinbase + pubKeyHash
	} else if strings.HasPrefix(to, "bc1") {
		// Bech32 address (P2WPKH or P2WSH)
		_, r_pubKey, _ := trx.DecodeBech32(to)
		decodedData, err := trx.ConvertBits(r_pubKey[1:], 5, 8, false)
		if err != nil {
			log.Println("Error Converting:", err)
			//return nil, nil, "", "", err
		}
		pubKeyHash := hex.EncodeToString(decodedData)
		r_pubkey, err := hex.DecodeString(pubKeyHash)
		pubkeylen := byte(len(r_pubkey))
		// Script of the P2PKH
		pubKeyHashStr := "OP_0 OP_PUSHBYTES_20 /" + pubKeyHash + "/"

		// Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStr, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		// Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)

		//Coinbase TX

		coinbase := hex.EncodeToString([]byte{0xc0, 0x10, pubkeylen})
		coinbaseTx = coinbase + pubKeyHash
	} else {
		log.Println("invalid address type")
	}
	total := 0
	for id, out := range u.UTXOs {
		log.Println("Get Transactions", coinbaseTx, "2-", scriptpubKey, "3-", out.PubKeyHash)
		if out.PubKeyHash == coinbaseTx {
			collected[id] = out
			total += out.Value
			if total >= amount {
				break
			}
		} else if out.PubKeyHash == scriptpubKey {
			collected[id] = out
			total += out.Value
			if total >= amount {
				break
			}
		}
	}
	return collected, total
}
func (u *UTXOSet) UTXOAddress(pubKeyHash string, pubkey string, amount int) (map[string]*trx.TXOutput, int) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	collected := make(map[string]*trx.TXOutput)

	total := 0
	for id, out := range u.UTXOs {
		scriptbyte, err := hex.DecodeString(out.PubKeyHash)
		if err != nil {
			log.Println("Error ", err)
		}
		scripthash := SingleSha256(scriptbyte)
		if out.PubKeyHash == pubKeyHash {
			collected[id] = out
			//fmt.Println("Public Hash", ownerPubkeyHahs, "Script:", scriptPubkey)

			total += out.Value
			log.Println("Amount", amount, total)
			if total > amount {
				log.Println("break", amount, total)
				break
			}
		} else if hex.EncodeToString(scripthash) == pubKeyHash {
			collected[id] = out
			//fmt.Println("Public Hash", ownerPubkeyHahs, "Script:", scriptPubkey)

			total += out.Value
			log.Println("Amount", amount, total)
			if total > amount {
				log.Println("break", amount, total)
				break
			}
		} else if out.PubKeyHash == pubkey {
			collected[id] = out

			//fmt.Println("Public Hash Coin", out.PubKeyHash , "Script:", scriptPubkey)
			total += out.Value
			log.Println("Amount PubKey", amount, total)
			if total > amount {
				break
			}
		}
	}
	return collected, total
}
func (u *UTXOSet) UTXOAddressBalance(pubKeyHash string, pubkey string) (map[string]*trx.TXOutput, int) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	collected := make(map[string]*trx.TXOutput)

	total := 0
	for id, out := range u.UTXOs {
		scriptbyte, err := hex.DecodeString(out.PubKeyHash)
		if err != nil {
			log.Println("Error ", err)
		}
		scripthash := SingleSha256(scriptbyte)
		if out.PubKeyHash == pubKeyHash {
			collected[id] = out
			//fmt.Println("Public Hash", ownerPubkeyHahs, "Script:", scriptPubkey)
			total += out.Value

		} else if hex.EncodeToString(scripthash) == pubKeyHash {
			collected[id] = out
			//fmt.Println("Public Hash", ownerPubkeyHahs, "Script:", scriptPubkey)
			total += out.Value

		} else if out.PubKeyHash == pubkey {
			collected[id] = out
			//fmt.Println("Public Hash Coin", out.PubKeyHash , "Script:", scriptPubkey)
			total += out.Value

		}
	}
	return collected, total
}
func (u *UTXOSet) GetUTXOs(pubKeyHash string) []map[string]*trx.TXOutput {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	collected := make(map[string]*trx.TXOutput)
	var allutxos []map[string]*trx.TXOutput
	for id, out := range u.UTXOs {

		//if out.PubKeyHash == pubKeyHash {
		collected[id] = out
		//total += out.Value
		allutxos = append(allutxos, collected)
		//}
	}
	return allutxos
}
