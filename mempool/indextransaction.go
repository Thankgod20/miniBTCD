package mempool

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Thankgod20/miniBTCD/elliptical"
	"github.com/Thankgod20/miniBTCD/trx"
	"github.com/Thankgod20/miniBTCD/wallet"
)

type IndexTrx struct {
	ScriptTransactionIndex            map[string][]string
	ScriptHashTransactionIndex        map[string][]string
	ScriptMempoolTransactionIndex     map[string][]string
	ScriptHashMempoolTransactionIndex map[string][]string
	TransactionByID                   map[string]string
	mutex                             sync.Mutex
}

func NewMIndexTrx() *IndexTrx {
	return &IndexTrx{ScriptTransactionIndex: make(map[string][]string), ScriptHashTransactionIndex: make(map[string][]string), ScriptMempoolTransactionIndex: make(map[string][]string), ScriptHashMempoolTransactionIndex: make(map[string][]string), TransactionByID: make(map[string]string)}
}
func (ntx *IndexTrx) IndexTransaction(tx *trx.Transaction) {
	ntx.mutex.Lock()
	defer ntx.mutex.Unlock()
	for _, input := range tx.Inputs {

		address := getAddressFromSig(input)
		var pubkeyHex []byte
		//var pubKeyByte
		//log.Println("Input Address", address)
		if strings.HasPrefix(address, "1") {
			// P2PKH address
			pubkey := GetP2PKHScript(address)
			log.Printf("Address PubKeyScript:%x", pubkey)
			pubkeyHex = pubkey
		} else if strings.HasPrefix(address, "3") {
			// P2SH address
			pubkey := GetP2SHScript(address)
			log.Printf("Address PubKeyScript:%x", pubkey)
			pubkeyHex = pubkey
		}
		scripthash := SingleSha256(pubkeyHex)

		ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

		ntx.ScriptTransactionIndex[hex.EncodeToString(pubkeyHex)] = append(ntx.ScriptTransactionIndex[hex.EncodeToString(pubkeyHex)], hex.EncodeToString(tx.ID))
	}

	for _, out := range tx.Outputs {

		address := out.PubKeyHash
		pubKeyByte, err := hex.DecodeString(address)
		if err != nil {
			fmt.Println("Error Converting:", err)

		}
		scripthash := SingleSha256(pubKeyByte)

		ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

		ntx.ScriptTransactionIndex[address] = append(ntx.ScriptTransactionIndex[address], hex.EncodeToString(tx.ID))
	}
	ntx.TransactionByID[hex.EncodeToString(tx.ID)] = tx.ToString()
	log.Println("Legacy Transactions Indexed!!!")
}
func (ntx *IndexTrx) IndexSegTransaction(tx *trx.SegWit) {
	ntx.mutex.Lock()
	defer ntx.mutex.Unlock()
	for _, input := range tx.Witness {

		address := getSegAddress(input)
		pubKeyHasg := GetP2PWKHScript(address)
		pubkeyHex := hex.EncodeToString(pubKeyHasg)

		scripthash := SingleSha256(pubKeyHasg)

		ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

		ntx.ScriptTransactionIndex[pubkeyHex] = append(ntx.ScriptTransactionIndex[pubkeyHex], hex.EncodeToString(tx.ID))
		log.Printf("Address PubKeyScript:%x", pubKeyHasg)
	}

	for _, out := range tx.Outputs {

		address := out.PubKeyHash
		pubKeyByte, err := hex.DecodeString(address)
		if err != nil {
			fmt.Println("Error Converting:", err)

		}
		scripthash := SingleSha256(pubKeyByte)

		ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

		ntx.ScriptTransactionIndex[address] = append(ntx.ScriptTransactionIndex[address], hex.EncodeToString(tx.ID))
	}

	ntx.TransactionByID[hex.EncodeToString(tx.ID)] = tx.ToString()
	log.Println("SegWit Transactions Indexed!!!")
}
func (ntx *IndexTrx) IndexMempoolTransaction(tx *trx.Transaction, isDelete bool) {
	ntx.mutex.Lock()
	defer ntx.mutex.Unlock()
	for _, input := range tx.Inputs {

		address := getAddressFromSig(input)
		var pubkeyHex []byte
		//var pubKeyByte
		//log.Println("Input Address", address)
		if strings.HasPrefix(address, "1") {
			// P2PKH address
			pubkey := GetP2PKHScript(address)
			log.Printf("Address PubKeyScript:%x", pubkey)
			pubkeyHex = pubkey
		} else if strings.HasPrefix(address, "3") {
			// P2SH address
			pubkey := GetP2SHScript(address)
			log.Printf("Address PubKeyScript:%x", pubkey)
			pubkeyHex = pubkey
		}
		scripthash := SingleSha256(pubkeyHex)
		if isDelete {
			delete(ntx.ScriptHashMempoolTransactionIndex, hex.EncodeToString(scripthash))
			delete(ntx.ScriptMempoolTransactionIndex, hex.EncodeToString(pubkeyHex))
		} else {
			log.Println("hex.EncodeToString(scripthash)", hex.EncodeToString(scripthash), "TxID", hex.EncodeToString(tx.ID))

			ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

			ntx.ScriptMempoolTransactionIndex[hex.EncodeToString(pubkeyHex)] = append(ntx.ScriptMempoolTransactionIndex[hex.EncodeToString(pubkeyHex)], hex.EncodeToString(tx.ID))
		}
	}

	for _, out := range tx.Outputs {

		address := out.PubKeyHash
		pubKeyByte, err := hex.DecodeString(address)
		if err != nil {
			fmt.Println("Error Converting:", err)

		}
		scripthash := SingleSha256(pubKeyByte)
		if isDelete {
			delete(ntx.ScriptHashMempoolTransactionIndex, hex.EncodeToString(scripthash))
			delete(ntx.ScriptMempoolTransactionIndex, address)
		} else {
			ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

			ntx.ScriptMempoolTransactionIndex[address] = append(ntx.ScriptMempoolTransactionIndex[address], hex.EncodeToString(tx.ID))
		}
	}
	//ntx.TransactionByID[hex.EncodeToString(tx.ID)] = tx.ToString()
	log.Println("Legacy Transactions Indexed!!!")
}
func (ntx *IndexTrx) IndexMempoolSegTransaction(tx *trx.SegWit, isDelete bool) {
	ntx.mutex.Lock()
	defer ntx.mutex.Unlock()
	for _, input := range tx.Witness {

		address := getSegAddress(input)
		pubKeyHasg := GetP2PWKHScript(address)
		pubkeyHex := hex.EncodeToString(pubKeyHasg)

		scripthash := SingleSha256(pubKeyHasg)
		if isDelete {
			delete(ntx.ScriptHashMempoolTransactionIndex, hex.EncodeToString(scripthash))
			delete(ntx.ScriptMempoolTransactionIndex, pubkeyHex)
		} else {
			ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

			ntx.ScriptMempoolTransactionIndex[pubkeyHex] = append(ntx.ScriptMempoolTransactionIndex[pubkeyHex], hex.EncodeToString(tx.ID))
			log.Printf("Address PubKeyScript:%x", pubKeyHasg)
		}
	}

	for _, out := range tx.Outputs {

		address := out.PubKeyHash
		pubKeyByte, err := hex.DecodeString(address)
		if err != nil {
			fmt.Println("Error Converting:", err)

		}
		scripthash := SingleSha256(pubKeyByte)
		if isDelete {
			delete(ntx.ScriptHashMempoolTransactionIndex, hex.EncodeToString(scripthash))
			delete(ntx.ScriptMempoolTransactionIndex, address)
		} else {
			ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)] = append(ntx.ScriptHashMempoolTransactionIndex[hex.EncodeToString(scripthash)], hex.EncodeToString(tx.ID))

			ntx.ScriptMempoolTransactionIndex[address] = append(ntx.ScriptMempoolTransactionIndex[address], hex.EncodeToString(tx.ID))
		}
	}

	//ntx.TransactionByID[hex.EncodeToString(tx.ID)] = tx.ToString()
	log.Println("SegWit Transactions Indexed!!!")
}
func GetP2PWKHScript(address string) []byte {
	_, r_pubKey, _ := wallet.DecodeBech32(address)
	decodedData, err := trx.ConvertBits(r_pubKey[1:], 5, 8, false)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	pubLen := byte(len(decodedData))
	outputs := "OP_0 OP_PUSHBYTES_20 /" + hex.EncodeToString(decodedData) + "/"
	pubkey, err := trx.DecodeScriptPubKey(outputs, pubLen)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	return pubkey
}
func SingleSha256(data []byte) []byte {
	sha := sha256.Sum256(data)
	//sha_two := sha256.Sum256(sha[:])
	return sha[:] //ripemd.Sum(nil)
}
func GetP2PKHScript(address string) []byte {
	r_pubKey, err := wallet.Base58Decode(address)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	pubByte, err := hex.DecodeString(hex.EncodeToString(r_pubKey)[2:42])
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	pubLen := byte(len(pubByte))
	outputs := "OP_DUP OP_HASH160 OP_PUSHBYTES_20 /" + hex.EncodeToString(r_pubKey)[2:42] + "/ OP_EQUALVERIFY OP_CHECKSIG"
	pubkey, err := trx.DecodeScriptPubKey(outputs, pubLen)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	return pubkey
}
func GetP2SHScript(address string) []byte {
	r_pubKey, err := wallet.Base58Decode(address)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	pubByte, err := hex.DecodeString(hex.EncodeToString(r_pubKey)[2:42])
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	pubLen := byte(len(pubByte))
	outputs := "OP_HASH160 OP_PUSHBYTES_20 /" + hex.EncodeToString(r_pubKey)[2:42] + "/ OP_EQUAL"
	pubkey, err := trx.DecodeScriptPubKey(outputs, pubLen)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return nil
	}
	return pubkey
}
func GetAddressFromScriptHash(out trx.TXOutput) string {
	//Process ScriptPubKeyHash
	pubKeyHash, Addrtype, err := ExtractPubKeyHash(out.PubKeyHash)
	if err != nil {
		log.Println("Unable to Process ScriptPubKey", err)
	}
	var address string
	if Addrtype == "P2PKH" || Addrtype == "P2SH" {
		if Addrtype == "P2PKH" {
			pubKeyHash = "00" + pubKeyHash
		} else if Addrtype == "P2SH" {
			pubKeyHash = "05" + pubKeyHash
		}

		fmt.Println("OuptScript PUBKey:-", pubKeyHash, "Addrtype", Addrtype)
		versionedPayload, _ := hex.DecodeString(pubKeyHash)
		//checksum of address
		checksum := wallet.CheckSumLegacy(versionedPayload)
		//Add the 4 checksum bytes at the end of extended RIPEMD-160 hash to form the binary Bitcoin address.
		binaryAddress := append(versionedPayload, checksum...)
		fmt.Printf("CheckSume %x binaryAddr: %x\n", checksum, binaryAddress)
		address = wallet.Base58Encode(binaryAddress)
	} else if Addrtype == "P2PWKH" {
		pubKeyByte, _ := hex.DecodeString(pubKeyHash)
		bech32Address, err := wallet.EncodeBech32(pubKeyByte)
		if err != nil {
			return ""
		}
		address = bech32Address
	}
	return address
}
func getSegAddress(witness [][]byte) string {

	//signatureA = append(signatureA, hex.EncodeToString(witness[0]))
	publKeyA := witness[1]
	pubKeyHash := elliptical.Hash160(publKeyA)
	bech32Address, err := wallet.EncodeBech32(pubKeyHash)
	if err != nil {
		return ""
	}
	return bech32Address
}
func getAddressFromSig(input trx.TXInput) string {
	var address string

	//signature
	if input.Sig[:2] == "47" {
		sliptSig := strings.Split(input.Sig[2:], "0121")
		//signature = sliptSig[0]
		publkey_, err := hex.DecodeString(sliptSig[1])
		if err != nil {
			log.Println("Unable to Decode PubKey", err)
		}
		pubKeyHash := elliptical.Hash160(publkey_)
		versionedPayload := append([]byte{0x00}, pubKeyHash...)

		//checksum of address
		checksum := wallet.CheckSumLegacy(versionedPayload)

		//Add the 4 checksum bytes at the end of extended RIPEMD-160 hash to form the binary Bitcoin address.
		binaryAddress := append(versionedPayload, checksum...)
		//Convert the binary address to Base58.
		address = wallet.Base58Encode(binaryAddress)
	} else if input.Sig[:4] == "0047" {
		sliptSig := strings.Split(input.Sig[4:], "0147")

		publkey_, err := hex.DecodeString(sliptSig[1])
		if err != nil {
			log.Println("Unable to Decode PubKey", err)
		}
		fmt.Println("Publick from SigScript:", sliptSig[1])
		pubKeyHash := elliptical.Hash160(publkey_)
		//pubKeyHash := hash160(redeemScripthex)
		versionedPayload := append([]byte{0x05}, pubKeyHash...)

		//checksum of address
		checksum := wallet.CheckSumLegacy(versionedPayload)

		//Add the 4 checksum bytes at the end of extended RIPEMD-160 hash to form the binary Bitcoin address.
		binaryAddress := append(versionedPayload, checksum...)
		//Convert the binary address to Base58.
		address = wallet.Base58Encode(binaryAddress)
	}
	return address
}
