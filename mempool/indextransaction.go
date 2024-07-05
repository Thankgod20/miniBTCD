package mempool

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Thankgod20/miniBTCD/trx"
	"github.com/Thankgod20/miniBTCD/wallet"
)

type IndexTrx struct {
	AddressTransactionIndex map[string][]string //[][]byte
	TransactionByID         map[string]string
	mutex                   sync.Mutex
}

func NewMIndexTrx() *IndexTrx {
	return &IndexTrx{AddressTransactionIndex: make(map[string][]string), TransactionByID: make(map[string]string)}
}
func (ntx *IndexTrx) IndexTransaction(tx *trx.Transaction) {
	ntx.mutex.Lock()
	defer ntx.mutex.Unlock()
	for _, input := range tx.Inputs {

		address := getAddressFromSig(input)
		//log.Println("Input Address", address)

		ntx.AddressTransactionIndex[address] = append(ntx.AddressTransactionIndex[address], hex.EncodeToString(tx.ID))
	}

	for _, out := range tx.Outputs {

		address := getAddressFromScriptHash(out)
		//log.Println("Out Address", address)
		ntx.AddressTransactionIndex[address] = append(ntx.AddressTransactionIndex[address], hex.EncodeToString(tx.ID))
	}
	ntx.TransactionByID[hex.EncodeToString(tx.ID)] = tx.ToString()
	log.Println("Legacy Transactions Indexed!!!")
}
func (ntx *IndexTrx) IndexSegTransaction(tx *trx.SegWit) {
	ntx.mutex.Lock()
	defer ntx.mutex.Unlock()
	for _, input := range tx.Witness {

		address := getSegAddress(input)
		//log.Println("Input Sign Address", address)
		ntx.AddressTransactionIndex[address] = append(ntx.AddressTransactionIndex[address], hex.EncodeToString(tx.ID))
	}

	for _, out := range tx.Outputs {

		address := getAddressFromScriptHash(out)
		//log.Println("Out Sign Address", address)
		ntx.AddressTransactionIndex[address] = append(ntx.AddressTransactionIndex[address], hex.EncodeToString(tx.ID))
	}
	ntx.TransactionByID[hex.EncodeToString(tx.ID)] = tx.ToString()
	log.Println("SegWit Transactions Indexed!!!")
}
func getAddressFromScriptHash(out trx.TXOutput) string {
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
	pubKeyHash := hash160(publKeyA)
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
		pubKeyHash := hash160(publkey_)
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
		pubKeyHash := hash160(publkey_)
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
