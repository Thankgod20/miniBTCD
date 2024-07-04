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
	"minibtcd/trx"
	"strings"
	"sync"

	"golang.org/x/crypto/ripemd160"
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
	for _, input := range tx.Inputs {
		prevTxID := hex.EncodeToString(input.ID)
		utxoKey := fmt.Sprintf("%s:%d", prevTxID, input.Out)
		txo, exists := utxoSet.UTXOs[utxoKey]
		if !exists {
			return ("input UTXO not found")
		}
		var signature string
		var publKey []byte
		//signature
		if input.Sig[:2] == "47" {
			sliptSig := strings.Split(input.Sig[2:], "0121")
			signature = sliptSig[0]
			publkey_, err := hex.DecodeString(sliptSig[1])
			if err != nil {
				log.Println("Unable to Decode PubKey", err)
			}
			//fmt.Println("Publick from SigScript:", sliptSig[1])
			publKey = publkey_
		}
		//Process ScriptPubKeyHash
		pubKeyHash, _, err := ExtractPubKeyHash(txo.PubKeyHash)
		if err != nil {
			log.Println("Unable to Process ScriptPubKey", err)
		}
		log.Println("PubKey Obtained", pubKeyHash)

		//Get raw Tran
		// Verify signature
		if !VerifySignature(pubKeyHash, signature, publKey, tx) { //input.Sig, pubKey) {
			log.Println("invalid signature")
			return ("invalid signature")
		}
		utxosAmount += txo.Value
	}
	for _, output := range tx.Outputs {
		trxTotalAmount += output.Value
	}
	log.Println("Total Amount Comparison", trxTotalAmount, utxosAmount)
	if utxosAmount > trxTotalAmount {
		// Add the transaction to the mempool
		m.AddTransaction(unTx)
		//log.Printf("Transaction: %s Added To Mempool", txID)
		//Add miner Transaction
		//minerFee := utxosAmount - trxTotalAmount
		//log.Println("Miner Fee Added")
		//minerTx := trx.CreateCoinbase("Reward", m.Miner, minerFee)
		//minerTxToString := minerTx.ToString()
		//m.AddTransaction(minerTx)
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
		utxosAmount += txo.Value
	}

	//amount comparison

	var trxTotalAmount int
	for _, output := range tx.Outputs {
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
func VerifySignature(pubKeyHash string, signature string, pubKeyx []byte, tx *trx.Transaction) bool {
	pubKey := pubKeyx
	isCompressed := false
	if pubKey[0] != 0x04 || len(pubKey) != 65 {
		log.Println("! PubKey Not Decompressed") //, pubKey)
		decomPubKey, err := DecompressPubKey(pubKey)
		if err != nil {
			log.Println("Error Decompressing Pubkey", err)
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
	wpubKey := hash160(pubKey)
	if isCompressed {
		wpubKey = hash160(pubKeyx)
	}
	if bytes.Equal(hash, wpubKey) {
		//get the hex of the transcations
		for i := range tx.Inputs {
			tx.Inputs[i].Sig = ""
		}
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
		//fmt.Println("script PubKey", pubKeyHash, "Spender Pubkey", hex.EncodeToString(wpubKey), "Trna Hex", trxhex)
		r := big.NewInt(0)
		s := big.NewInt(0)
		// Define signature structure
		type ECDSASignature struct {
			R, S *big.Int
		}
		var sign ECDSASignature

		//decode from DER
		//log.Println("Signature:", signature, signature[:len(signature)-2])
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
		log.Println("Signatures", r, s)
		//r.SetBytes(sigBytes[:len(sigBytes)/2])
		//s.SetBytes(sigBytes[len(sigBytes)/2:])

		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)
		rawPubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

		return ecdsa.Verify(&rawPubKey, dataToSign, r, s)
	} else {
		return false
	}
}

// VerifySignature verifies if the signature is valid for the given hash and public key
func VerifyWitness(pubKeyHash string, signature string, index int, prvInputVal int, pubKeyx []byte, tx *trx.SegWit) bool {
	pubKey := pubKeyx
	isCompressed := false
	if pubKey[0] != 0x04 || len(pubKey) != 65 {
		log.Println("PubKey Not Decompressed") //, pubKey)
		decomPubKey, err := DecompressPubKey(pubKey)
		if err != nil {
			log.Println("Error Decompressing Pubkey", err)
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
	wpubKey := hash160(pubKey)
	if isCompressed {
		wpubKey = hash160(pubKeyx)
	}
	log.Println("Comparing PubKeys\nFrom trns.Out", pubKeyHash, "\nSpender PubKey", hex.EncodeToString(wpubKey))
	if bytes.Equal(hash, wpubKey) {
		for i := range tx.Witness {
			tx.Witness[i] = [][]byte{}
		}
		//get the hex of the transcations
		PreImage, message := ConstructSegWitPreimage(tx, index, prvInputVal, hex.EncodeToString(wpubKey))
		log.Println("PreImage:-", hex.EncodeToString(PreImage), "\nMessage:-", hex.EncodeToString(message))
		//toHex, _ := tx.ToHex(true)
		//log.Println("Hexx", toHex)
		r := big.NewInt(0)
		s := big.NewInt(0)
		// Define signature structure
		type ECDSASignature struct {
			R, S *big.Int
		}
		var sign ECDSASignature

		//decode from DER
		//log.Println("Signature:", signature, signature[:len(signature)-2])
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
		log.Println("Signatures", r, s)
		//r.SetBytes(sigBytes[:len(sigBytes)/2])
		//s.SetBytes(sigBytes[len(sigBytes)/2:])

		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)
		rawPubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

		return ecdsa.Verify(&rawPubKey, message, r, s)
	} else {
		return false
	}
}
func ConstructSegWitPreimage(tx *trx.SegWit, inputIndex int, inputAmount int, publicKeyHash string) ([]byte, []byte) {
	// Helper function to perform double SHA256 hashing
	ddoubleSha256 := func(data []byte) []byte {
		firstHash := sha256.Sum256(data)
		secondHash := sha256.Sum256(firstHash[:])
		return secondHash[:]
	}

	// 1. Version
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, uint32(tx.Version))

	// 2. Serialize and hash the TXIDs and VOUTs for the inputs
	var serializedInputs bytes.Buffer
	for _, input := range tx.Inputs {
		inID := trx.ReverseBytes(input.ID)
		serializedInputs.Write(inID)
		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, uint32(input.Out))
		serializedInputs.Write(vout)
		//log.Println("hashInputs", hex.EncodeToString(inID))
		//log.Println("hashInputs Non", hex.EncodeToString((input.ID)))
	}
	//log.Println("TRX", tx.ToString())
	hashInputs := ddoubleSha256(serializedInputs.Bytes())
	//log.Println("hashInputs x", hex.EncodeToString(hashInputs))
	// 3. Serialize and hash the sequences for the inputs
	var serializedSequences bytes.Buffer
	for _, input := range tx.Inputs {
		sequence := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequence, input.Sequence)
		serializedSequences.Write(sequence)
	}
	hashSequences := ddoubleSha256(serializedSequences.Bytes())
	//log.Println("hashSequences x", hex.EncodeToString(hashSequences))
	// 4. Serialize the TXID and VOUT for the input we're signing
	input := tx.Inputs[inputIndex]
	var serializedInput bytes.Buffer
	inID := (input.ID)
	serializedInput.Write(inID)
	vout := make([]byte, 4)
	binary.LittleEndian.PutUint32(vout, uint32(input.Out))
	serializedInput.Write(vout)
	log.Println("ReverseBytes x", hex.EncodeToString(inID))
	// 5. Create a scriptcode for the input we're signing
	//log.Println("The PublicHash", publicKeyHash)
	scriptcode := "1976a914" + publicKeyHash + "88ac"
	scriptcodeBytes, err := hex.DecodeString(scriptcode)
	if err != nil {
		log.Fatal("Eroro", err)
	}

	// 6. Find the input amount
	amount := make([]byte, 8)
	binary.LittleEndian.PutUint64(amount, uint64(inputAmount))
	//log.Println("Amount", inputAmount, "In Hex", hex.EncodeToString(amount))
	// 7. Grab the sequence for the input we're signing
	sequence := make([]byte, 4)
	binary.LittleEndian.PutUint32(sequence, input.Sequence)

	// 8. Serialize and hash all the outputs
	var serializedOutputs bytes.Buffer
	for _, output := range tx.Outputs {
		value := make([]byte, 8)
		binary.LittleEndian.PutUint64(value, uint64(output.Value))
		serializedOutputs.Write(value)
		//scriptpubkey := output.PubKeyHash
		//fmt.Println(output.PubKeyHash)
		var scriptpubkeyHash []byte
		if strings.Contains(output.PubKeyHash, "OP") {
			//split Strings
			pubKeyHash := strings.Split(output.PubKeyHash, "/")
			// Convert PubKeyHash to bytes
			pubKeyHashBytes, err := hex.DecodeString(pubKeyHash[1]) //(output.PubKeyHash)
			if err != nil {
				fmt.Println("Error decoding PubKeyHash:", err)

			}
			// Calculate the length of PubKeyHash
			pubKeyHashLen := byte(len(pubKeyHashBytes))

			// Deocde ScriptPubKey ASM to byte
			scriptpubkeyHash, err = trx.DecodeScriptPubKey(output.PubKeyHash, pubKeyHashLen)
			if err != nil {
				log.Println("DDDDD", err)
			}
			log.Println("Script Type:", pubKeyHash[0], "Decoded ", hex.EncodeToString(scriptpubkeyHash))
		} else {
			scriptpubkey, err := hex.DecodeString(output.PubKeyHash)
			if err != nil {
				log.Println("DDDDD", err)
			}
			scriptpubkeyHash = scriptpubkey
		}
		//log.Println("scriptpubkeyHash", hex.EncodeToString(scriptpubkeyHash))
		serializedOutputs.WriteByte(byte(len(scriptpubkeyHash)))
		serializedOutputs.Write(scriptpubkeyHash)
	}
	hashOutputs := ddoubleSha256(serializedOutputs.Bytes())

	// 9. Grab the locktime
	locktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktime, tx.Locktime)

	// 10. Combine to create a hash preimage
	var preimage bytes.Buffer
	preimage.Write(version)
	preimage.Write(hashInputs)
	preimage.Write(hashSequences)
	preimage.Write(serializedInput.Bytes())
	preimage.Write(scriptcodeBytes)
	preimage.Write(amount)
	preimage.Write(sequence)
	preimage.Write(hashOutputs)
	preimage.Write(locktime)

	// 11. Add signature hash type to the end of the hash preimage
	sighashType := make([]byte, 4)
	binary.LittleEndian.PutUint32(sighashType, 0x01)
	preimage.Write(sighashType)

	// 12. Hash the preimage
	message := ddoubleSha256(preimage.Bytes())

	return preimage.Bytes(), message
}

// DecompressPubKey decompresses a compressed public key
func DecompressPubKey(pubKey []byte) ([]byte, error) {
	log.Println("Decompressing Pubkey...")
	if len(pubKey) != 33 || (pubKey[0] != 0x02 && pubKey[0] != 0x03) {
		return nil, errors.New("invalid compressed public key format")
	}
	//fmt.Println("pubKey[1:]", pubKey[1:])
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(pubKey[1:])
	y := decompressYCoordinate(curve, pubKey[0] == 0x03, x)
	//fmt.Println("X,Y", x, y)
	if y == nil {
		return nil, errors.New("failed to decompress public key")
	}

	decompressedPubKey := elliptic.Marshal(curve, x, y)
	return decompressedPubKey, nil
}

// decompressYCoordinate computes the y-coordinate from the x-coordinate for a given curve
func decompressYCoordinate(curve elliptic.Curve, isOdd bool, x *big.Int) *big.Int {
	// P-256 parameters
	p := curve.Params().P
	a := big.NewInt(-3)
	b := new(big.Int)
	b.SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

	// Calculate x^3 + ax + b (mod p)
	xCubed := new(big.Int).Exp(x, big.NewInt(3), p)
	ax := new(big.Int).Mul(a, x)
	ax.Mod(ax, p)
	result := new(big.Int).Add(xCubed, ax)
	result.Add(result, b)
	result.Mod(result, p)

	// Calculate the modular square root (y-coordinate)
	y := new(big.Int).ModSqrt(result, p)
	if y == nil {
		return nil //, fmt.Errorf("no valid y-coordinate for x = %s", x.Text(16))
	}
	if y.Bit(0) != 0 {
		if !isOdd {
			y = new(big.Int).Sub(curve.Params().P, y)
		}
	} else {
		if isOdd {
			y = new(big.Int).Sub(curve.Params().P, y)
		}
	}
	return y //, nil
}
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

//0200000014dd1ee33405701cf208a34128a8ce42027d2a967562283153c6b0ca98788ecc82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8de2350dfe7c8264e83000b1de255a03f6ddff550f72ac90aa3118015a78e2453

//000000001976a914628ba348bd752bfe879f1b31c203d6e551f3855e88ac

//0008af2f00000000ffffffffac5a3fb4dc4f2509e5ed01c5058a66004dde67a12566858c24cec095d9dd51ce0000000001000000  or
//0200000014dd1ee33405701cf208a34128a8ce42027d2a967562283153c6b0ca98788ecc82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8de2350dfe7c8264e83000b1de255a03f6ddff550f72ac90aa3118015a78e2453000000001976a914628ba348bd752bfe879f1b31c203d6e551f3855e88ac009ce4a600000000ffffffffac5a3fb4dc4f2509e5ed01c5058a66004dde67a12566858c24cec095d9dd51ce0000000001000000
