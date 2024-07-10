// wallet.go
package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"strings"

	"github.com/Thankgod20/miniBTCD/trx"

	"golang.org/x/crypto/pbkdf2"
)

const SatoshiPerBitcoin = 100000000

// bc1qe02jal267rk7n7272vt3zafx9ruay394v98xf0
// 3Ag5RYpyspx4j8q9HFY1aJA3nLcK25AFHy
// 19z4W1LYKvdgdy8iA9sR9fo7dpKbTsZsQG
// bc1qv296xj9aw54lapulrvcuyq7ku4gl8p27yh9cc8
// 3FJaijzLa6FA2a6KDoZ733iBu18pHhiECk
// go run main.go --newWallet="My New Wallet" --p2sh //go run main.go --wallet --balance="19z4W1LYKvdgdy8iA9sR9fo7dpKbTsZsQG"
type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte
	Address    string
}

func NewWallet() *Wallet {
	private, public := newKeyPair()
	address, err := publicKeyToBech32Address(public)
	if err != nil {
		log.Fatal(err)
	}
	wallet := Wallet{private, public, address}
	return &wallet
}

func newKeyPair() (*ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	return private, pubKey
}

// NewWalletFromSeed creates a new wallet from a seed
func NewWalletFromSeed(seed string) (*Wallet, error) {
	private, public, err := newKeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	address, err := publicKeyToBech32Address(public)
	if err != nil {
		return nil, err
	}
	var publicKey []byte
	if private.PublicKey.Y.Bit(0) == 0 {
		publicKey = append([]byte{0x02}, private.PublicKey.X.Bytes()...)
	} else {
		publicKey = append([]byte{0x03}, private.PublicKey.X.Bytes()...)
	}
	fmt.Printf("Private Key: %x, public key %x\n", private.D.Bytes(), publicKey)
	wallet := Wallet{private, public, address}
	return &wallet, nil
}
func NewP2PKHWalletFromSeed(seed string) (*Wallet, error) {
	private, public, err := newKeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	address, err := publicKeyToP2PKHAddress(public)
	if err != nil {
		return nil, err
	}
	wallet := Wallet{private, public, address}
	return &wallet, nil
}
func NewP2SHWalletFromSeed(seed string) (*Wallet, error) {
	private, public, err := newKeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	address, err := publicKeyToP2SHAddress(public)
	if err != nil {
		return nil, err
	}
	wallet := Wallet{private, public, address}
	return &wallet, nil
}

// newKeyPairFromSeed generates a new private-public key pair from a seed
func newKeyPairFromSeed(seed string) (*ecdsa.PrivateKey, []byte, error) {
	curve := elliptic.P256()
	seedBytes := pbkdf2.Key([]byte(seed), []byte("minibtcd"), 4096, 32, sha256.New)

	private := new(ecdsa.PrivateKey)
	private.PublicKey.Curve = curve
	private.D = new(big.Int).SetBytes(seedBytes)
	private.PublicKey.X, private.PublicKey.Y = curve.ScalarBaseMult(seedBytes)

	if private.PublicKey.X == nil {
		return nil, nil, errors.New("failed to generate key pair from seed")
	}

	//pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	var pubKey []byte
	if private.PublicKey.Y.Bit(0) == 0 {
		pubKey = append([]byte{0x02}, private.PublicKey.X.Bytes()...)
	} else {
		pubKey = append([]byte{0x03}, private.PublicKey.X.Bytes()...)
	}
	//x := new(big.Int).SetBytes(private.PublicKey.X.Bytes())
	//y := new(big.Int).SetBytes(private.PublicKey.Y.Bytes())
	//fmt.Println("PubKey X", x, y)
	return private, pubKey, nil
}

func (w *Wallet) CreateTransaction(to string, amount int, fee float64, collected map[string]*trx.TXOutput /*utxoSet *mempool.UTXOSet*/) (string, error) {
	//Wallet address to publicKeyHash

	// Create the transaction

	//tx.SetID()
	//w.Sign(tx)

	segWit, tx, hexx, pubKeyHash, txoPubHash, err := w.rawTrnx(to, amount, fee, collected)
	if err != nil {

		log.Println("Error Initaitng Trnx:", err)
	}
	var signTrxHex string
	if tx != nil {
		rawHex := hexx + "01000000"

		signedTrx := w.Sign(tx, rawHex, pubKeyHash, txoPubHash)

		signTrxHex_, err := signedTrx.ToHex(true)
		if err != nil {
			log.Println("Error Signed Trnx:", err)
		}
		signTrxHex = signTrxHex_
		log.Println("\nRaw Transaction:\n", rawHex, "\n\n")
	} else {
		rawHex := hexx + "01000000"
		prevInputValue := []int{}
		for _, output := range collected {
			prevInputValue = append(prevInputValue, output.Value)
		}
		signedTrx := w.SignSegWit(segWit, rawHex, pubKeyHash, prevInputValue) //w.Sign(tx, rawHex, pubKeyHash)

		signTrxHex_, err := signedTrx.ToHex(true)
		if err != nil {
			log.Println("Error Signed Trnx:", err)
		}
		signTrxHex = signTrxHex_
		log.Println("\nRaw Transaction:\n", rawHex, "\n\n")
	}
	return signTrxHex, nil
}
func (w *Wallet) rawTrnx(to string, amount int, fee float64, collected map[string]*trx.TXOutput /**mempool.UTXOSet*/) (*trx.SegWit, *trx.Transaction, string, string, []string, error) {
	//Wallet address to publicKeyHash

	var pubKeyHashStr string
	var scriptpubKey string

	if strings.HasPrefix(w.Address, "bc1") {
		pubKey := w.PublicKey
		pubKeyHash := hash160(pubKey)
		pubkeylen := byte(len(pubKeyHash))
		pubKeyHashStr = hex.EncodeToString(pubKeyHash)
		// Script of the P2PKH
		pubKeyHashStrx := "OP_0 OP_PUSHBYTES_20 /" + pubKeyHashStr + "/"

		// Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStrx, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		// Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)
		log.Println("PubKeyHashStr:-", pubKeyHashStr)
		log.Println("Script:-", scriptpubKey)
		//fmt.Println("pubKeyHashStr", pubKeyHashStr, "Script", scriptpubKey)
	} else if strings.HasPrefix(w.Address, "1") {
		pubKey := w.PublicKey
		pubKeyHash := hash160(pubKey)
		pubkeylen := byte(len(pubKeyHash))
		pubKeyHashStr = hex.EncodeToString(pubKeyHash)

		//Script of the P2PKH
		pubKeyHashStrx := "OP_DUP OP_HASH160 OP_PUSHBYTES_20 /" + pubKeyHashStr + "/ OP_EQUALVERIFY OP_CHECKSIG"

		//Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStrx, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		//Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)
		log.Println("PubKeyHashStr:-", pubKeyHashStr)
		log.Println("Script:-", scriptpubKey)
		//fmt.Println("pubKeyHashStr", pubKeyHashStr, "Script", scriptpubKey)
	} else {
		pubKey := w.PublicKey
		pubKeyHash := hash160(pubKey)
		pubkeylen := byte(len(pubKeyHash))
		pubKeyHashStr = hex.EncodeToString(pubKeyHash)
		// Script of the P2PKH
		pubKeyHashStrx := "OP_HASH160 OP_PUSHBYTES_20 /" + pubKeyHashStr + "/ OP_EQUAL"

		// Script byte of the P2PKH
		scriptpubKeybyte, err := trx.DecodeScriptPubKey(pubKeyHashStrx, pubkeylen)
		if err != nil {
			log.Println("error decoding scriptpubkey for balance:", err)
		}
		// Script hex of the P2PKH
		scriptpubKey = hex.EncodeToString(scriptpubKeybyte)
		log.Println("PubKeyHashStr:-", pubKeyHashStr)
		log.Println("Script:-", scriptpubKey)
	}

	// for coin base transactions
	/*
		pubKeyByte, err := hex.DecodeString(pubKeyHashStr)
		if err != nil {
			return nil, nil, "", "", errors.New("failed to Decode  PubKey Byte Wallet")
		}

		coinbase := hex.EncodeToString([]byte{0xc0, byte(len(pubKeyByte))})
		fmt.Println("Length of privateKey")*/

	// Find enough UTXOs to cover the amount
	//collected, total := utxoSet.FindUTXO(w.Address, amount) //(scriptpubKey, coinbase+pubKeyHashStr, amount)
	total := 0
	var txoPubHash []string
	for _, output := range collected {
		//fmt.Println("OutpUt", output.Value)
		txoPubHash = append(txoPubHash, output.PubKeyHash)
		total += output.Value
	}
	log.Println("Wallet Balance", total)
	if total < (amount * SatoshiPerBitcoin) {
		return nil, nil, "", "", nil, errors.New("not enough funds")
	}
	var inputs []trx.TXInput
	var outputs []trx.TXOutput
	var inputsSig []trx.SegTXInput
	if strings.HasPrefix(w.Address, "bc1") {
		inputsSig = []trx.SegTXInput{}
		outputs = []trx.TXOutput{}
		// Create inputs from collected UTXOs
		for id, _ := range collected {
			txID, _ := hex.DecodeString(id[:64])
			index := int(id[65] - '0')
			input := trx.SegTXInput{ID: txID, Out: index, Sig: "", Sequence: uint32(math.MaxUint32)}
			inputsSig = append(inputsSig, input)
		}
	} else {
		inputs = []trx.TXInput{}
		outputs = []trx.TXOutput{}
		// Create inputs from collected UTXOs
		for id, _ := range collected {
			txID, _ := hex.DecodeString(id[:64])
			index := int(id[65] - '0')
			input := trx.TXInput{ID: txID, Out: index, Sig: ""}
			inputs = append(inputs, input)
		}
	}
	var feeEx int = 0
	var feeTig int = int(fee * SatoshiPerBitcoin)
	if total > amount {
		feeTig = 0
		feeEx = int(fee * SatoshiPerBitcoin)
	}
	// Create outputs

	if strings.HasPrefix(to, "1") {
		// P2PKH address
		r_pubKey, _ := Base58Decode(to)

		outputs = append(outputs, trx.TXOutput{Value: (amount * SatoshiPerBitcoin) - feeTig, PubKeyHash: "OP_DUP OP_HASH160 OP_PUSHBYTES_20 /" + hex.EncodeToString(r_pubKey)[2:42] + "/ OP_EQUALVERIFY OP_CHECKSIG"})
	} else if strings.HasPrefix(to, "3") {
		// P2SH address
		r_pubKey, _ := Base58Decode(to)

		outputs = append(outputs, trx.TXOutput{Value: (amount * SatoshiPerBitcoin) - feeTig, PubKeyHash: "OP_HASH160 OP_PUSHBYTES_20 /" + hex.EncodeToString(r_pubKey)[2:42] + "/ OP_EQUAL"})
	} else if strings.HasPrefix(to, "bc1") {
		// Bech32 address (P2WPKH or P2WSH)
		_, r_pubKey, _ := DecodeBech32(to)
		decodedData, err := convertBits(r_pubKey[1:], 5, 8, false)
		if err != nil {
			fmt.Println("Error Converting:", err)
			return nil, nil, "", "", nil, err
		}
		outputs = append(outputs, trx.TXOutput{Value: (amount * SatoshiPerBitcoin) - feeTig, PubKeyHash: "OP_0 OP_PUSHBYTES_20 /" + hex.EncodeToString(decodedData) + "/"})
	} else {
		return nil, nil, "", "", nil, errors.New("invalid address type")
	}
	// If there's change, send it back to the wallet address
	if total > (amount * SatoshiPerBitcoin) {
		fmt.Println("Total And Maont", total, amount)
		if strings.HasPrefix(w.Address, "1") {
			// P2PKH address

			outputs = append(outputs, trx.TXOutput{Value: total - (amount * SatoshiPerBitcoin) - feeEx, PubKeyHash: "OP_DUP OP_HASH160 OP_PUSHBYTES_20 /" + pubKeyHashStr + "/ OP_EQUALVERIFY OP_CHECKSIG"})
		} else if strings.HasPrefix(w.Address, "3") {
			// P2SH address

			outputs = append(outputs, trx.TXOutput{Value: total - (amount * SatoshiPerBitcoin) - feeEx, PubKeyHash: "OP_HASH160 OP_PUSHBYTES_20 /" + pubKeyHashStr + "/ OP_EQUAL"})
		} else if strings.HasPrefix(w.Address, "bc1") {

			outputs = append(outputs, trx.TXOutput{Value: total - (amount * SatoshiPerBitcoin) - feeEx, PubKeyHash: "OP_0 OP_PUSHBYTES_20 /" + pubKeyHashStr + "/"})
		} else {
			return nil, nil, "", "", nil, errors.New("invalid address type")
		}
		//outputs = append(outputs, trx.TXOutput{Value: total - (amount * SatoshiPerBitcoin), PubKeyHash: pubKeyHashStr})
	}

	if strings.HasPrefix(w.Address, "bc1") {
		tx := &trx.SegWit{Version: 2, Marker: 0x00, Flag: 0x01, Inputs: inputsSig, Outputs: outputs}
		to_hex, err := tx.ToHex(false)
		if err != nil {
			log.Println("Error Hexing", err)
		}
		return tx, nil, to_hex, pubKeyHashStr, txoPubHash, nil

	} else {
		tx := &trx.Transaction{Version: 2, Inputs: inputs, Outputs: outputs}
		to_hex, err := tx.ToHex(false)
		if err != nil {
			log.Println("Error Hexing", err)
		}
		//fmt.Println("Transction Hash", hex.EncodeToString(tx.Hash()))
		return nil, tx, to_hex, pubKeyHashStr, txoPubHash, nil
	}
}
func (w *Wallet) Sign(tx *trx.Transaction, trnxhexx string, publicKeyHash string, txoPubHash []string) *trx.Transaction {
	var signature []string
	for i, _ := range tx.Inputs {
		for i, _ := range tx.Inputs {
			tx.Inputs[i].Sig = ""
		}
		tx.Inputs[i].Sig = txoPubHash[i]
		trnxhex, _ := tx.ToHex(true)
		log.Println("First Signing:", trnxhex)
		toBytes, err := hex.DecodeString(trnxhex + "01000000") //tx.Hash()
		if err != nil {
			log.Fatal(err)
		}
		dataToSign := doubleSha256(toBytes)
		r, s, err := ecdsa.Sign(rand.Reader, w.PrivateKey, dataToSign)
		if err != nil {
			log.Fatal(err)
		}
		// Define signature structure
		type ECDSASignature struct {
			R, S *big.Int
		}
		// Create signature object
		sign := ECDSASignature{R: r, S: s}

		//fmt.Println("R Signed", sign.R, sign.S)
		//signature := append(r.Bytes(), s.Bytes()...)
		// Encode to DER
		derBytes, err := asn1.Marshal(sign)
		if err != nil {
			fmt.Println("Error encoding to DER:", err)
			return nil
		}

		signature_ := hex.EncodeToString(derBytes) + "01"
		signature = append(signature, signature_)
		//log.Println("Signature DEREND:-", signature, i, r, s, publicKeyHash)

		// Get the public key in uncompressed format
		//uncompressed format of public key
		//publicKey := append([]byte{0x04}, w.PrivateKey.PublicKey.X.Bytes()...)
		//publicKey = append(publicKey, w.PrivateKey.PublicKey.Y.Bytes()...)

		//compressed format of the public key
		// Get the public key in compressed format

	}

	for i, _ := range tx.Inputs {
		var publicKey []byte
		if w.PrivateKey.PublicKey.Y.Bit(0) == 0 {
			publicKey = append([]byte{0x02}, w.PrivateKey.PublicKey.X.Bytes()...)
		} else {
			publicKey = append([]byte{0x03}, w.PrivateKey.PublicKey.X.Bytes()...)
		}
		if strings.HasPrefix(w.Address, "1") {
			tx.Inputs[i].Sig = "OP_PUSHBYTES_71 /" + signature[i] + "/ OP_PUSHBYTES_33 /" + hex.EncodeToString(publicKey) + "/" //hex.EncodeToString(signature)
		} else {
			tx.Inputs[i].Sig = "OP_0 OP_PUSHBYTES_71 /" + signature[i] + "/ OP_PUSHBYTES_71 OP_1 OP_PUSHBYTES_33 /" + hex.EncodeToString(publicKey) + "/ OP_2 OP_CHECKMULTISIG"
		}
	}
	return tx
}

func (w *Wallet) SignSegWit(tx *trx.SegWit, trnxhex string, publicKeyHash string, prevInputValue []int) *trx.SegWit {
	for i, _ := range tx.Inputs {

		_, message := w.ConstructSegWitPreimage(tx, i, prevInputValue[i], publicKeyHash)
		//log.Println("PreImage:-", hex.EncodeToString(PreImage))
		//log.Println("Message:-", hex.EncodeToString(message))

		r, s, err := ecdsa.Sign(rand.Reader, w.PrivateKey, message)
		if err != nil {
			log.Fatal(err)
		}
		// Define signature structure
		type ECDSASignature struct {
			R, S *big.Int
		}
		// Create signature object
		sign := ECDSASignature{R: r, S: s}

		//fmt.Println("R Signed", sign.R, sign.S)
		//signature := append(r.Bytes(), s.Bytes()...)
		// Encode to DER
		derBytes, err := asn1.Marshal(sign)
		if err != nil {
			fmt.Println("Error encoding to DER:", err)
			return nil
		}

		signature := hex.EncodeToString(derBytes) + "01"
		//log.Println("Signature DEREND:-", signature, i, r, s, publicKeyHash)

		//compressed format of the public key
		// Get the public key in compressed format
		var publicKey []byte
		if w.PrivateKey.PublicKey.Y.Bit(0) == 0 {
			publicKey = append([]byte{0x02}, w.PrivateKey.PublicKey.X.Bytes()...)
		} else {
			publicKey = append([]byte{0x03}, w.PrivateKey.PublicKey.X.Bytes()...)
		}
		witness := "OP_PUSHBYTES_71 /" + signature + "/ OP_PUSHBYTES_33 /" + hex.EncodeToString(publicKey) + "/" //hex.EncodeToString(signature)
		//split Strings
		witnessSigScript := strings.Split(witness, "/")
		// Convert PubKeyHash to bytes
		witnessSigSciptByte, err := hex.DecodeString(witnessSigScript[1]) //(output.PubKeyHash)
		if err != nil {
			fmt.Println("Error decoding PubKeyHash:", err)

		}
		// Calculate the length of PubKeyHash
		witnessbytelen := byte(len(witnessSigSciptByte))

		// Deocde ScriptPubKey ASM to byte
		witnesData_, err := trx.DecodeScriptPubKey(witness, witnessbytelen)
		if err != nil {
			log.Println("DDDDD", err)
		}
		witnesData := append([]byte{0x02}, witnesData_...)
		log.Println("WitnessData", hex.EncodeToString(witnesData))
		signByte, err := hex.DecodeString(signature)
		if err != nil {
			log.Println("Convering Witness to Byte Failed:", err)
		}
		//var signWitn [][]byte

		//signWitn = append(signWitn, signByte)
		signWitn := [][]byte{signByte, publicKey}
		tx.Witness = append(tx.Witness, signWitn)
		//tx.Witness[i][0] = signByte
		//tx.Witness[i][1] = publicKey
	}
	return tx
}

func (w *Wallet) ConstructSegWitPreimage(tx *trx.SegWit, inputIndex int, inputAmount int, publicKeyHash string) ([]byte, []byte) {
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
		serializedInputs.Write(input.ID)
		vout := make([]byte, 4)
		binary.LittleEndian.PutUint32(vout, uint32(input.Out))
		serializedInputs.Write(vout)
		//log.Println("hashInputs", hex.EncodeToString(input.ID))
	}
	hashInputs := ddoubleSha256(serializedInputs.Bytes())

	// 3. Serialize and hash the sequences for the inputs
	var serializedSequences bytes.Buffer
	for _, input := range tx.Inputs {
		sequence := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequence, input.Sequence)
		serializedSequences.Write(sequence)
	}
	hashSequences := ddoubleSha256(serializedSequences.Bytes())

	// 4. Serialize the TXID and VOUT for the input we're signing
	input := tx.Inputs[inputIndex]
	var serializedInput bytes.Buffer
	serializedInput.Write(input.ID)
	vout := make([]byte, 4)
	binary.LittleEndian.PutUint32(vout, uint32(input.Out))
	serializedInput.Write(vout)

	// 5. Create a scriptcode for the input we're signing
	//fmt.Println("The PublicHash", publicKeyHash)
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
			//	log.Println("Script Type:", pubKeyHash[0], "Decoded ", hex.EncodeToString(scriptpubkeyHash))
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

//02000000a48f5a0b53ca26b7f7e846a4b9e3d8994dd3267cd8407b1d7ff55968c881af8182a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be88cd5f0264ed6a38c776f2c682d9ad0efc0dbb88cf49139b17eceef211cd897b

//0000000001976a914628ba348bd752bfe879f1b31c203d6e551f3855e88ac

//0008af2f00000000fffffffff125c538b7697c7c34f97c10c88d8c2dd06f175005403be5e1d7b497eba3f97c0000000001000000
//02000000a48f5a0b53ca26b7f7e846a4b9e3d8994dd3267cd8407b1d7ff55968c881af8182a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be88cd5f0264ed6a38c776f2c682d9ad0efc0dbb88cf49139b17eceef211cd897b0000000001976a914628ba348bd752bfe879f1b31c203d6e551f3855e88ac

//00d2496b00000000

//fffffffff125c538b7697c7c34f97c10c88d8c2dd06f175005403be5e1d7b497eba3f97c0000000001000000
