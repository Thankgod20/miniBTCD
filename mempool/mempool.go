// mempool.go
package mempool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/Thankgod20/miniBTCD/elliptical"
	"github.com/Thankgod20/miniBTCD/trx"
)

type Mempool struct {
	Miner        string
	transactions map[string]*[]byte //trx.Transaction
	mutex        sync.Mutex
}

func NewMempool() *Mempool {
	return &Mempool{transactions: make(map[string]*[]byte)}
}

func (m *Mempool) AddTransaction(tx *trx.Transaction) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	//log.Println("AddIng TX,", tx.ToString())
	trxhex, err := tx.ToHex(false)
	if err != nil {
		log.Println("Error Converting Trx to Hex AddTransaction:", err)
	}
	//log.Println("\n", trxhex)
	trxbyte, err := hex.DecodeString(trxhex)
	if err != nil {
		log.Println("Error Converting DecodeString to Hex AddTransaction:", err)
	}

	m.transactions[hex.EncodeToString(tx.ID)] = &trxbyte
	log.Printf("Trnx: %s Added Mempool", hex.EncodeToString(tx.ID))
}
func (m *Mempool) AddSegWitTransaction(tx *trx.SegWit) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	trxhex, err := tx.ToHex(false)
	if err != nil {
		log.Println("Error Converting Trx to Hex AddTransaction:", err)
	}
	trxbyte, err := hex.DecodeString(trxhex)
	m.transactions[hex.EncodeToString(tx.ID)] = &trxbyte
	log.Printf("Trnx: %s Added Mempool", hex.EncodeToString(tx.ID))
}
func (m *Mempool) RemoveTransaction(txID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.transactions, txID)
}

func (m *Mempool) GetTransactions() [][]byte { //[]*trx.Transaction {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	var transactions [][]byte //*trx.Transaction
	for _, tx := range m.transactions {
		transactions = append(transactions, *tx)
	}
	return transactions
}
func (m *Mempool) GetTransaction(trxID string) ([]byte, bool) { //[]*trx.Transaction {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	trx, exist := m.transactions[trxID]
	if !exist {
		return nil, false
	}
	return *trx, true
}

// SubmitTransaction validates and adds a transaction to the mempool
func (m *Mempool) SubmitTransaction(trnx *trx.Transaction, untrnx *trx.Transaction, utxoSet *UTXOSet) string {
	tx := trnx
	unTx := untrnx
	txID := hex.EncodeToString(tx.ID)

	// Check if the transaction is already in the mempool
	m.mutex.Lock()
	if _, exists := m.transactions[txID]; exists {
		m.mutex.Unlock()
		return ("transaction already in the mempool")
	}
	m.mutex.Unlock()
	// Check Transaction Balance
	//amount comparison
	var utxosAmount int
	var trxTotalAmount int
	// Check if all inputs are in UTXO set and signatures are valid
	for i, input := range unTx.Inputs {
		prevTxID := hex.EncodeToString(input.ID)
		log.Println("frist PrevInput", prevTxID)
		utxoKey := fmt.Sprintf("%s:%d", prevTxID, input.Out)
		txo, exists := utxoSet.UTXOs[utxoKey]
		if !exists {
			return ("input UTXO not found")
		}
		var signature string
		var publKey []byte
		var isP2SH bool = false
		//signature
		if input.Sig[:2] == "47" || input.Sig[:2] == "48" {
			sliptSig := strings.Split(input.Sig[2:], "0121")
			signature = sliptSig[0]
			publkey_, err := hex.DecodeString(sliptSig[1])
			if err != nil {
				log.Println("Unable to Decode PubKey", err)
			}
			//fmt.Println("Publick from SigScript:", sliptSig[1])
			publKey = publkey_
			isP2SH = false
		} else if input.Sig[:4] == "0047" || input.Sig[:4] == "0048" {
			sliptSig := strings.Split(input.Sig[4:], "01475121")
			signature = sliptSig[0]
			publkey_, err := hex.DecodeString(sliptSig[1][:len(sliptSig[1])-4])
			if err != nil {
				log.Println("Unable to Decode PubKey", err)
			}
			fmt.Println("Publick from SigScript:", sliptSig[1][:len(sliptSig[1])-4])
			publKey = publkey_
			isP2SH = true
		}

		//Process ScriptPubKeyHash
		pubKeyHash, _, err := ExtractPubKeyHash(txo.PubKeyHash)
		if err != nil {
			log.Println("Unable to Process ScriptPubKey", err)
		}
		log.Println("PubKey Obtained", pubKeyHash)

		//Get raw Tran
		// Verify signature
		if !VerifySignature(pubKeyHash, signature, isP2SH, i, publKey, txo.PubKeyHash, tx) { //input.Sig, pubKey) {
			log.Println("invalid signature")
			return ("invalid signature")
		}
		utxosAmount += txo.Value
		tx.ToHex(false)
	}
	for _, output := range tx.Outputs {
		log.Println(" Output:-", output.Value)
		trxTotalAmount += output.Value
	}
	log.Println("Total Amount Comparison", trxTotalAmount, utxosAmount)
	if utxosAmount > trxTotalAmount {
		// Add the transaction to the mempool
		m.AddTransaction(unTx)

		log.Println("Successful\n")
		return "Successful"
	} else {
		log.Println("Insufficient Bitcoin for Transaction")
		return "Insufficient Bitcoin for Transaction"
	}
	//

}

// SubmitTransaction validates and adds a transaction to the mempool
func (m *Mempool) SubmitSegWitTransaction(trnx *trx.SegWit, untrnx *trx.SegWit, utxoSet *UTXOSet) string {
	tx := trnx
	unTx := untrnx
	txID := hex.EncodeToString(tx.ID)

	// Check if the transaction is already in the mempool
	m.mutex.Lock()
	if _, exists := m.transactions[txID]; exists {
		m.mutex.Unlock()
		return ("transaction already in the mempool")
	}
	m.mutex.Unlock()
	// Check Transaction Balance
	var utxosAmount int
	var signatureA []string
	var publKeyA [][]byte
	for _, witness := range tx.Witness {
		signatureA = append(signatureA, hex.EncodeToString(witness[0]))
		publKeyA = append(publKeyA, witness[1])
	}
	// Check if all inputs are in UTXO set and signatures are valid
	for i, input := range tx.Inputs {
		prevTxID := hex.EncodeToString(input.ID)
		utxoKey := fmt.Sprintf("%s:%d", prevTxID, input.Out)
		txo, exists := utxoSet.UTXOs[utxoKey]
		if !exists {
			return ("input UTXO not found")
		}
		var signature string
		var publKey []byte

		//signature
		signature = signatureA[i] //hex.EncodeToString(tx.Witness[i][0])
		//pubKey
		publKey = publKeyA[i] //tx.Witness[i][1]
		//Process ScriptPubKeyHash
		pubKeyHash, _, err := ExtractPubKeyHash(txo.PubKeyHash)
		if err != nil {
			log.Println("Unable to Process ScriptPubKey", err)
		}
		log.Println("PubKey Obtained", pubKeyHash, "TXO", txo.PubKeyHash)

		// Verify Witness
		if !VerifyWitness(pubKeyHash, signature, i, txo.Value, publKey, tx) { //input.Sig, pubKey) {
			log.Println("invalid signature")
			return ("invalid signature")
		}
		log.Printf("Signature %d Verified !!!!!", i)
		for _, input := range tx.Inputs {
			input.ID = trx.ReverseBytes(input.ID)

		}
		log.Printf("Input ID Normalizes ")
		log.Println(" Output Seg:-", txo.Value, i)
		utxosAmount += txo.Value
	}

	//amount comparison

	var trxTotalAmount int
	for _, output := range unTx.Outputs {

		trxTotalAmount += output.Value
	}
	log.Println("Total Amount Comparison", trxTotalAmount, utxosAmount)
	if utxosAmount > trxTotalAmount {
		// Add the transaction to the mempool
		m.AddSegWitTransaction(unTx)

		//Add miner Transaction
		//minerFee := utxosAmount - trxTotalAmount
		//log.Println("Miner Fee Added")
		//minerTx := trx.CreateCoinbase("Reward", m.Miner, minerFee)
		//minerTxToString := minerTx.ToString()
		//m.AddTransaction(minerTx)
		log.Println("Successful\n") // "Miner Tx\n", minerTxToString)
		return "Successful"
	} else {
		log.Println("Insufficient Bitcoin for Transaction")
		return "Insufficient Bitcoin for Transaction"
	}
	//

}

// ExtractPubKeyHash extracts the pubKeyHash from a hex-encoded ScriptPubKey
func ExtractPubKeyHash(scriptPubKey string) (string, string, error) {
	scriptBytes, err := hex.DecodeString(scriptPubKey)
	if err != nil {
		return "", "", err
	}
	//fmt.Println("scriptBytes", scriptBytes, scriptPubKey, len(scriptBytes))
	if len(scriptBytes) == 25 && scriptBytes[0] == 0x76 && scriptBytes[1] == 0xa9 && scriptBytes[2] == 0x14 && scriptBytes[23] == 0x88 && scriptBytes[24] == 0xac {
		// P2PKH
		return hex.EncodeToString(scriptBytes[3:23]), "P2PKH", nil
	} else if len(scriptBytes) == 23 && scriptBytes[0] == 0xa9 && scriptBytes[1] == 0x14 && scriptBytes[22] == 0x87 {
		// P2SH
		return hex.EncodeToString(scriptBytes[2:22]), "P2SH", nil
	} else if len(scriptBytes) == 22 && scriptBytes[0] == 0xc0 && scriptBytes[1] == 0x14 {
		// COINBASE
		return hex.EncodeToString(scriptBytes[2:]), "COINBASE", nil
	} else if len(scriptBytes) == 22 && scriptBytes[0] == 0x00 && scriptBytes[1] == 0x14 {
		// P2PWKH
		return hex.EncodeToString(scriptBytes[2:]), "P2PWKH", nil
	}

	return "", "", errors.New("unsupported scriptPubKey format")
}

// double SHA-256 hash of the input data
func doubleSha256(data []byte) []byte {
	sha := sha256.Sum256(data)
	sha_two := sha256.Sum256(sha[:])
	return sha_two[:] //ripemd.Sum(nil)
}

// VerifySignature verifies if the signature is valid for the given hash and public key
func VerifySignature(pubKeyHash string, signature string, isP2SH bool, index int, pubKeyx []byte, txoPubKeyHash string, tx *trx.Transaction) bool {
	pubKey := pubKeyx

	isCompressed := false
	failedCompressed := false
	if pubKey[0] != 0x04 || len(pubKey) != 65 {
		log.Println("! PubKey Not Decompressed") //, pubKey)
		decomPubKey, err := elliptical.DecompressPubKey(pubKey)
		if err != nil {
			failedCompressed = true
			log.Println("Error Decompressing Pubkey", err)
		}
		if failedCompressed {
			decomPubKey = pubKey
			//decomPubKey, _, _ = DecompressPubKeyTx(hex.EncodeToString(pubKey))
		}
		log.Println("Decompressed PubKey:-", hex.EncodeToString(decomPubKey))
		pubKey = decomPubKey
		isCompressed = true
	}

	hash, err := hex.DecodeString(pubKeyHash) //sha256.Sum256([]byte(pubKeyHash))
	if err != nil {
		log.Println("Unable to Decode PubKey to byte", err)
	}
	log.Println("Checking Hash160 of Addr....")
	if isP2SH {
		pubKey = append([]byte{0x51, 0x21}, pubKey...)
		pubKey = append(pubKey, []byte{0x52, 0xae}...)
		log.Printf("P2SH Redemm Script:%x", pubKey)
	}
	wpubKey := elliptical.Hash160(pubKey)
	if isCompressed {
		if isP2SH {
			pubKeyx = append([]byte{0x51, 0x21}, pubKeyx...)
			pubKeyx = append(pubKeyx, []byte{0x52, 0xae}...)
			log.Printf("P2SH Compressed Redemm Script:%x", pubKeyx)
		}
		wpubKey = elliptical.Hash160(pubKeyx)
	}
	log.Printf("Compare:%x and %x", hash, wpubKey)
	if bytes.Equal(hash, wpubKey) {
		//get the hex of the transcations
		for i := range tx.Inputs {
			tx.Inputs[i].Sig = ""
		}
		tx.Inputs[index].Sig = txoPubKeyHash
		trxhex, err := tx.ToHex(false)
		if err != nil {
			return false
		}
		fmt.Println("SignedTx", trxhex)
		toBytes, err := hex.DecodeString(trxhex + "01000000") //tx.Hash()
		if err != nil {
			log.Fatal(err)
		}
		//double hash the message
		dataToSign := doubleSha256(toBytes)
		fmt.Println("script PubKey", pubKeyHash, "Spender Pubkey", hex.EncodeToString(wpubKey), "Trna Hex", trxhex)
		r := big.NewInt(0)
		s := big.NewInt(0)
		// Define signature structure

		var sign elliptical.Signature

		//decode from DER
		log.Println("Signature:", signature, signature[:len(signature)-2])
		sigBytes, err := hex.DecodeString(signature)
		if err != nil {
			log.Println("Error", err)
			return false
		}
		_, err = asn1.Unmarshal(sigBytes, &sign)
		if err != nil {
			log.Println("Error", err)
			return false
		}
		r = sign.R
		s = sign.S
		log.Println("Signatures", r, s)
		//r.SetBytes(sigBytes[:len(sigBytes)/2])
		//s.SetBytes(sigBytes[len(sigBytes)/2:])
		if isP2SH {
			pubKey = pubKey[2 : len(pubKey)-2]
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)
		if x == nil {
			_, x, y = elliptical.DecompressPubKeyTx(hex.EncodeToString(pubKey))
			pubkey := elliptical.Point{X: x, Y: y}
			istrue := elliptical.Verify(pubkey, sign, dataToSign)
			return istrue
		}
		rawPubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		ecdsayes := ecdsa.Verify(&rawPubKey, dataToSign, r, s)

		if ecdsayes {
			return ecdsayes
		} else {
			_, x, y = elliptical.DecompressPubKeyTx(hex.EncodeToString(pubKeyx))
			pubkey := elliptical.Point{X: x, Y: y}
			istrue := elliptical.Verify(pubkey, sign, dataToSign)
			return istrue
		}
		//return ecdsa.Verify(&rawPubKey, dataToSign, r, s)
	} else {
		return false
	}
}

// VerifySignature verifies if the signature is valid for the given hash and public key
func VerifyWitness(pubKeyHash string, signature string, index int, prvInputVal int, pubKeyx []byte, tx *trx.SegWit) bool {
	pubKey := pubKeyx
	log.Printf("PubKey of Owner: %x", pubKey)
	isCompressed := false
	failedCompressed := false
	if pubKey[0] != 0x04 || len(pubKey) != 65 {
		log.Println("PubKey Not Decompressed") //, pubKey)
		decomPubKey, err := elliptical.DecompressPubKey(pubKey)
		if err != nil {
			failedCompressed = true
			log.Println("Error Decompressing Pubkey", err)
		}
		if failedCompressed {
			decomPubKey = pubKey
			//decomPubKey, _, _ = DecompressPubKeyTx(hex.EncodeToString(pubKey))
		}
		log.Println("Decompressed PubKey:-", hex.EncodeToString(decomPubKey))
		pubKey = decomPubKey
		isCompressed = true
	}

	hash, err := hex.DecodeString(pubKeyHash) //sha256.Sum256([]byte(pubKeyHash))
	if err != nil {
		log.Println("Unable to Decode PubKey to byte", err)
	}
	log.Println("Checking Hash160 of Addr....")
	wpubKey := elliptical.Hash160(pubKey)
	if isCompressed {
		wpubKey = elliptical.Hash160(pubKeyx)
	}
	log.Println("Comparing PubKeys\nFrom trns.Out", pubKeyHash, "\nSpender PubKey", hex.EncodeToString(wpubKey))
	if bytes.Equal(hash, wpubKey) {
		for i := range tx.Witness {
			tx.Witness[i] = [][]byte{}
		}
		//get the hex of the transcations
		sigHash := signature[len(signature)-2:]
		// Convert the string to an integer
		value, err := strconv.ParseUint(sigHash, 16, 32)
		if err != nil {
			fmt.Println("Error converting string to uint32:", err)

		}
		// Convert the parsed value to uint32
		sigHashType := uint32(value)
		PreImage, message := ConstructSegWitPreimage(tx, index, prvInputVal, hex.EncodeToString(wpubKey), sigHashType)
		log.Println("PreImage:-", hex.EncodeToString(PreImage), "\nMessage:-", hex.EncodeToString(message))
		//toHex, _ := tx.ToHex(true)

		r := big.NewInt(0)
		s := big.NewInt(0)
		// Define signature structure

		var sign elliptical.Signature //ECDSASignature

		//decode from DER
		log.Println("Signature:", signature, signature[:len(signature)-2])
		sigBytes, err := hex.DecodeString(signature)
		if err != nil {
			return false
		}
		_, err = asn1.Unmarshal(sigBytes, &sign)
		if err != nil {
			return false
		}
		r = sign.R
		s = sign.S
		log.Printf("Signatures:%x\n", sign)
		log.Println("Signatures", r, s)

		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)
		if x == nil {

			_, x, y = elliptical.DecompressPubKeyTx(hex.EncodeToString(pubKey))
			pubkey := elliptical.Point{X: x, Y: y}
			istrue := elliptical.Verify(pubkey, sign, message)
			return istrue
		}
		log.Println("X:", x)
		log.Println("Y:", y)
		rawPubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		ecdsayes := ecdsa.Verify(&rawPubKey, message, r, s)
		if ecdsayes {
			return ecdsayes
		} else {
			_, x, y = elliptical.DecompressPubKeyTx(hex.EncodeToString(pubKeyx))
			pubkey := elliptical.Point{X: x, Y: y}
			istrue := elliptical.Verify(pubkey, sign, message)
			return istrue
		}
		//return ecdsa.Verify(&rawPubKey, message, r, s)
	} else {
		return false
	}
}
func ConstructSegWitPreimage(tx *trx.SegWit, inputIndex int, inputAmount int, publicKeyHash string, sighashType uint32) ([]byte, []byte) {
	// Helper function to perform double SHA256 hashing
	ddoubleSha256 := func(data []byte) []byte {
		firstHash := sha256.Sum256(data)
		secondHash := sha256.Sum256(firstHash[:])
		return secondHash[:]
	}

	// 1. Version
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, uint32(tx.Version))

	// 2. hashPrevouts
	var hashPrevouts []byte
	if sighashType&0x80 == 0 {
		var serializedInputs bytes.Buffer
		for _, input := range tx.Inputs {
			inID := trx.ReverseBytes(input.ID)
			log.Printf("InputID %x", inID)
			serializedInputs.Write(inID)
			vout := make([]byte, 4)
			binary.LittleEndian.PutUint32(vout, uint32(input.Out))
			serializedInputs.Write(vout)
		}
		hashPrevouts = ddoubleSha256(serializedInputs.Bytes())
	} else {
		hashPrevouts = make([]byte, 32)
	}
	log.Printf("hashPrevouts %x", hashPrevouts)
	// 3. hashSequence
	var hashSequence []byte
	if sighashType&0x80 == 0 && sighashType&0x1f != 0x02 && sighashType&0x1f != 0x03 {
		var serializedSequences bytes.Buffer
		for _, input := range tx.Inputs {
			sequence := make([]byte, 4)
			binary.LittleEndian.PutUint32(sequence, input.Sequence)
			serializedSequences.Write(sequence)
		}
		hashSequence = ddoubleSha256(serializedSequences.Bytes())
	} else {
		hashSequence = make([]byte, 32)
	}
	log.Printf("hashSequence %x", hashSequence)
	// 4. outpoint (for the input we're signing)
	input := tx.Inputs[inputIndex]
	var outpoint bytes.Buffer
	inID := input.ID //trx.ReverseBytes(input.ID)
	outpoint.Write(inID)
	vout := make([]byte, 4)
	binary.LittleEndian.PutUint32(vout, uint32(input.Out))
	outpoint.Write(vout)

	// 5. scriptCode
	scriptcode := "1976a914" + publicKeyHash + "88ac"
	scriptcodeBytes, err := hex.DecodeString(scriptcode)
	if err != nil {
		log.Fatal("Error decoding script code:", err)
	}

	// 6. value (input amount)
	amount := make([]byte, 8)
	binary.LittleEndian.PutUint64(amount, uint64(inputAmount))
	log.Println("Input Amount:", inputAmount)
	// 7. nSequence (for the input we're signing)
	sequence := make([]byte, 4)
	binary.LittleEndian.PutUint32(sequence, input.Sequence)
	log.Println("Input Sequence:", input.Sequence)
	// 8. hashOutputs
	var hashOutputs []byte
	if sighashType&0x1f != 0x02 && sighashType&0x1f != 0x03 {
		var serializedOutputs bytes.Buffer
		for _, output := range tx.Outputs {
			value := make([]byte, 8)
			binary.LittleEndian.PutUint64(value, uint64(output.Value))
			serializedOutputs.Write(value)
			var scriptpubkeyHash []byte
			if strings.Contains(output.PubKeyHash, "OP") {
				pubKeyHash := strings.Split(output.PubKeyHash, "/")
				pubKeyHashBytes, err := hex.DecodeString(pubKeyHash[1])
				if err != nil {
					log.Println("Error decoding PubKeyHash:", err)
				}
				pubKeyHashLen := byte(len(pubKeyHashBytes))
				scriptpubkeyHash, err = trx.DecodeScriptPubKey(output.PubKeyHash, pubKeyHashLen)
				if err != nil {
					log.Println("Error decoding script pub key:", err)
				}
				log.Println("Script Type:", pubKeyHash[0], "Decoded ", hex.EncodeToString(scriptpubkeyHash))
			} else {
				scriptpubkey, err := hex.DecodeString(output.PubKeyHash)
				if err != nil {
					log.Println("Error decoding script pub key:", err)
				}
				scriptpubkeyHash = scriptpubkey
			}
			serializedOutputs.WriteByte(byte(len(scriptpubkeyHash)))
			serializedOutputs.Write(scriptpubkeyHash)
		}
		hashOutputs = ddoubleSha256(serializedOutputs.Bytes())
	} else if sighashType&0x1f == 0x02 && inputIndex < len(tx.Outputs) {
		var serializedOutputs bytes.Buffer
		output := tx.Outputs[inputIndex]
		value := make([]byte, 8)
		binary.LittleEndian.PutUint64(value, uint64(output.Value))
		serializedOutputs.Write(value)
		var scriptpubkeyHash []byte
		if strings.Contains(output.PubKeyHash, "OP") {
			pubKeyHash := strings.Split(output.PubKeyHash, "/")
			pubKeyHashBytes, err := hex.DecodeString(pubKeyHash[1])
			if err != nil {
				log.Println("Error decoding PubKeyHash:", err)
			}
			pubKeyHashLen := byte(len(pubKeyHashBytes))
			scriptpubkeyHash, err = trx.DecodeScriptPubKey(output.PubKeyHash, pubKeyHashLen)
			if err != nil {
				log.Println("Error decoding script pub key:", err)
			}
			log.Println("Script Type:", pubKeyHash[0], "Decoded ", hex.EncodeToString(scriptpubkeyHash))
		} else {
			scriptpubkey, err := hex.DecodeString(output.PubKeyHash)
			if err != nil {
				log.Println("Error decoding script pub key:", err)
			}
			scriptpubkeyHash = scriptpubkey
		}
		serializedOutputs.WriteByte(byte(len(scriptpubkeyHash)))
		serializedOutputs.Write(scriptpubkeyHash)
		hashOutputs = ddoubleSha256(serializedOutputs.Bytes())
	} else {
		hashOutputs = make([]byte, 32)
	}
	log.Printf("hashOutputs %x", hashOutputs)
	// 9. nLocktime
	locktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktime, tx.Locktime)

	// 10. sighash type
	sighashTypeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sighashTypeBytes, sighashType)

	// Combine to create the preimage
	var preimage bytes.Buffer
	preimage.Write(version)          // 1
	preimage.Write(hashPrevouts)     // 2
	preimage.Write(hashSequence)     // 3
	preimage.Write(outpoint.Bytes()) // 4
	preimage.Write(scriptcodeBytes)  // 5
	preimage.Write(amount)           // 6
	preimage.Write(sequence)         // 7
	preimage.Write(hashOutputs)      // 8
	preimage.Write(locktime)         // 9
	preimage.Write(sighashTypeBytes) // 10

	// Double SHA256 the preimage
	message := ddoubleSha256(preimage.Bytes())

	return preimage.Bytes(), message
}
