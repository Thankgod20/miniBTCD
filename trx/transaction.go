// transaction.go
package trx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

const SatoshiPerBitcoin = 100000000

type Transaction struct {
	Version  int32
	ID       []byte
	Inputs   []TXInput
	Outputs  []TXOutput
	Locktime uint32
}

type TXInput struct {
	ID       []byte
	Out      int
	Sig      string
	Sequence uint32
}

type TXOutput struct {
	Value      int
	PubKeyHash string
}

// SetID sets the transaction ID as a SHA-256 hash of the transaction
func (tx *Transaction) SetID() {
	hexStr, _ := tx.ToHex(false)
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Println("Error Seting ID", err)
	}
	txID := computeTransactionID(txBytes)
	tx.ID = txID
}

// Hash returns a SHA-256 hash of the transaction for signing
func (tx *Transaction) Hash() []byte {
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = []byte{}
	var encoded bytes.Buffer
	gob.NewEncoder(&encoded).Encode(txCopy)
	hash = sha256.Sum256(encoded.Bytes())

	return hash[:]
}

// NewTransaction creates a new transaction with the given inputs and outputs
func NewTransaction(version int32, inputs []TXInput, outputs []TXOutput, locktime uint32) *Transaction {
	tx := &Transaction{
		Version:  version,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
	}
	tx.SetID()
	return tx
}
func CreateGenesisCoinbase(coinbaseData string, toAddress string, amount int) *Transaction {
	var pubKey []byte
	var pubKeyHashStr string
	var err error
	if strings.HasPrefix(toAddress, "bc1") {
		// Bech32 address (P2WPKH or P2WSH)
		_, r_pubKey, _ := DecodeBech32(toAddress)
		decodedData, err := ConvertBits(r_pubKey[1:], 5, 8, false)
		if err != nil {
			log.Println("Error Converting:", err)
			return nil
		}
		//coinbase script
		//rawPubkey := hex.EncodeToString(decodedData)
		scriptleng := byte(len(decodedData))
		DpubKey := append([]byte{0xc0, 0x10, scriptleng}, decodedData...)
		pubKeyHashStr = hex.EncodeToString(DpubKey)
		//pubKeyHashStr = hex.EncodeToString(decodedData)
	} else if strings.HasPrefix(toAddress, "1") {
		pubKey, err = Base58Decode(toAddress)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}

		//pubKeyHash := doubleSha256(pubKey)//hash160(pubKey)
		pubKeyHashstrOne := hex.EncodeToString(pubKey)[2:42]
		/*pubKeyHashstrOneByte, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}
		pubKeyHash := hash160(pubKeyHashstrOneByte)*/

		//coinbase script
		rawPubkey, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Println("Coinbase Decode PubKey error", err)
		}
		scriptleng := byte(len(rawPubkey))
		DpubKey := append([]byte{0xc0, scriptleng}, rawPubkey...)
		pubKeyHashStr = hex.EncodeToString(DpubKey) //pubKeyHashstrOne //hex.EncodeToString(pubKeyHash)
	} else if strings.HasPrefix(toAddress, "3") {
		pubKey, err = Base58Decode(toAddress)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}

		//pubKeyHash := doubleSha256(pubKey)//hash160(pubKey)
		pubKeyHashstrOne := hex.EncodeToString(pubKey)[2:42]
		/*pubKeyHashstrOneByte, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}
		pubKeyHash := hash160(pubKeyHashstrOneByte)*/

		//coinbase script
		rawPubkey, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Println("Coinbase Decode PubKey error", err)
		}
		scriptleng := byte(len(rawPubkey))
		DpubKey := append([]byte{0xc0, 0x07, scriptleng}, rawPubkey...)
		pubKeyHashStr = hex.EncodeToString(DpubKey) //pubKeyHashstrOne //hex.EncodeToString(pubKeyHash)
	}

	//fmt.Println("Public Key of To", pubKeyHashStr, " ", hex.EncodeToString(pubKey), " ", toAddress)
	hexString := "0000000000000000000000000000000000000000000000000000000000000000"
	inputID, err := hex.DecodeString(hexString)
	if err != nil {
		log.Println("Error decoding hex string:", err)

	}
	coinbaseByte := []byte(coinbaseData)
	Signature := hash160(coinbaseByte)
	txin := TXInput{
		ID: inputID, //[]byte{}, // Genesis coinbase transaction has no ID
		//Out:      -1,       // Genesis coinbase transaction has no output
		Sig:      hex.EncodeToString(Signature), // coinbaseData,
		Sequence: uint32(math.MaxUint32),
	}
	txout := TXOutput{
		Value:      amount * SatoshiPerBitcoin,
		PubKeyHash: pubKeyHashStr,
	}
	tx := NewTransaction(2, []TXInput{txin}, []TXOutput{txout}, 0)
	return tx
}
func CreateCoinbase(coinbaseData string, toAddress string, amount int) *Transaction {
	var pubKey []byte
	var pubKeyHashStr string
	var err error
	if strings.HasPrefix(toAddress, "bc1") {
		// Bech32 address (P2WPKH or P2WSH)
		_, r_pubKey, _ := DecodeBech32(toAddress)
		decodedData, err := ConvertBits(r_pubKey[1:], 5, 8, false)
		if err != nil {
			log.Println("Error Converting:", err)
			return nil
		}
		//coinbase script
		//rawPubkey := hex.EncodeToString(decodedData)
		scriptleng := byte(len(decodedData))
		DpubKey := append([]byte{0xc0, 0x10, scriptleng}, decodedData...)
		pubKeyHashStr = hex.EncodeToString(DpubKey)
		//pubKeyHashStr = hex.EncodeToString(decodedData)
	} else if strings.HasPrefix(toAddress, "1") {
		pubKey, err = Base58Decode(toAddress)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}

		//pubKeyHash := doubleSha256(pubKey)//hash160(pubKey)
		pubKeyHashstrOne := hex.EncodeToString(pubKey)[2:42]
		/*pubKeyHashstrOneByte, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}
		pubKeyHash := hash160(pubKeyHashstrOneByte)*/

		//coinbase script
		rawPubkey, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Println("Coinbase Decode PubKey error", err)
		}
		scriptleng := byte(len(rawPubkey))
		DpubKey := append([]byte{0xc0, scriptleng}, rawPubkey...)
		pubKeyHashStr = hex.EncodeToString(DpubKey) //pubKeyHashstrOne //hex.EncodeToString(pubKeyHash)
	} else if strings.HasPrefix(toAddress, "3") {
		pubKey, err = Base58Decode(toAddress)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}

		//pubKeyHash := doubleSha256(pubKey)//hash160(pubKey)
		pubKeyHashstrOne := hex.EncodeToString(pubKey)[2:42]
		/*pubKeyHashstrOneByte, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Panicln("Unable to Deocode PubKey")
		}
		pubKeyHash := hash160(pubKeyHashstrOneByte)*/

		//coinbase script
		rawPubkey, err := hex.DecodeString(pubKeyHashstrOne)
		if err != nil {
			log.Println("Coinbase Decode PubKey error", err)
		}
		scriptleng := byte(len(rawPubkey))
		DpubKey := append([]byte{0xc0, 0x07, scriptleng}, rawPubkey...)
		pubKeyHashStr = hex.EncodeToString(DpubKey) //pubKeyHashstrOne //hex.EncodeToString(pubKeyHash)
	}
	//fmt.Println("Public Key of To", pubKeyHashStr, " ", hex.EncodeToString(pubKey), " ", toAddress)
	txin := TXInput{
		ID:  []byte{}, // Genesis coinbase transaction has no ID
		Out: -1,       // Genesis coinbase transaction has no output
		Sig: coinbaseData,
	}
	txout := TXOutput{
		Value:      amount * SatoshiPerBitcoin,
		PubKeyHash: pubKeyHashStr,
	}
	tx := NewTransaction(2, []TXInput{txin}, []TXOutput{txout}, 0)
	return tx
}

// HexToTransaction converts a hexadecimal string to a Transaction object
func HexToTransaction(hexStr string) (*Transaction, error) {
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	var tx Transaction
	err = json.Unmarshal(txBytes, &tx)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func TransactionToHex(tx *Transaction, isSigned bool) (string, error) {
	// Version
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, uint32(tx.Version))

	// Inputs
	var inputsBytes bytes.Buffer
	for _, input := range tx.Inputs {
		// Previous Transaction ID (reversed)
		inputTxid := make([]byte, 32)
		if isSigned {
			copy(inputTxid[:], (input.ID))
		} else {
			copy(inputTxid[:], ReverseBytes(input.ID))
		}
		inputsBytes.Write(inputTxid)

		// Output Index
		outputIndexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(outputIndexBytes, uint32(input.Out))
		inputsBytes.Write(outputIndexBytes)

		// Script Length
		if input.Sig != "" { //For Raw Transations
			if strings.Contains(input.Sig, "OP") {
				scrpSig := strings.Split(input.Sig, "/")

				pubKeyHashLen := byte(len(scrpSig[3]))
				scriptpubkeyHash, err := DecodeScriptPubKey(input.Sig, pubKeyHashLen)
				if err != nil {
					log.Println("DDDDD", err)
				}
				//fmt.Println("ScriptSig:", hex.EncodeToString(scriptpubkeyHash))
				input.Sig = hex.EncodeToString(scriptpubkeyHash)
			}
		}
		// Script Length
		if input.Out != -1 { // (only if not coinbase)

			scriptSigBytes, err := hex.DecodeString(input.Sig)
			if err != nil {
				return "", err
			}
			inputsBytes.WriteByte(byte(len(scriptSigBytes)))
			inputsBytes.Write(scriptSigBytes)
		} else { // (assuming no script for coinbase)
			inputsBytes.WriteByte(0x00)
		}
		// Sequence
		sequenceBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequenceBytes, input.Sequence) //0xffffffff)
		inputsBytes.Write(sequenceBytes)
	}

	// Outputs
	var outputsBytes bytes.Buffer
	for _, output := range tx.Outputs {
		// Value (in satoshis)
		valueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueBytes, uint64(output.Value))

		outputsBytes.Write(valueBytes)
		var scriptpubkeyHash []byte
		if strings.Contains(output.PubKeyHash, "OP") {
			//split Strings
			pubKeyHash := strings.Split(output.PubKeyHash, "/")
			// Convert PubKeyHash to bytes
			pubKeyHashBytes, err := hex.DecodeString(pubKeyHash[1]) //(output.PubKeyHash)
			if err != nil {
				fmt.Println("Error decoding PubKeyHash:", err)
				return "", err
			}
			// Calculate the length of PubKeyHash
			pubKeyHashLen := byte(len(pubKeyHashBytes))

			// Deocde ScriptPubKey ASM to byte
			scriptpubkeyHash, err = DecodeScriptPubKey(output.PubKeyHash, pubKeyHashLen)
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
		/*
			scriptSig := append([]byte{OP_One, OP_Two, pubKeyHashLen}, pubKeyHashBytes...) //append([]byte{0x76, 0xa9, pubKeyHashLen}, pubKeyHashBytes...)
			scriptSig = append(scriptSig, OP_Three, OP_Four)                               //append(scriptSig, 0x88, 0xac)
			//script, _ := hex.DecodeString("76" + output.PubKeyHash) // P2PKH script prefix (OP_DUP OP_HASH160 len hash160 OP_EQUALVERIFY OP_CHECKSIG)*/

		// Calculate the length of the P2PKH script
		scriptSig := scriptpubkeyHash
		scriptSigLength := len(scriptSig)
		outputsBytes.WriteByte(byte(scriptSigLength))
		outputsBytes.Write(scriptSig)
	}

	// Locktime
	locktimeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktimeBytes, tx.Locktime)

	// Concatenate all parts
	var transactionHex bytes.Buffer
	transactionHex.Write(versionBytes)
	transactionHex.WriteByte(byte(len(tx.Inputs))) // Input count
	transactionHex.Write(inputsBytes.Bytes())
	transactionHex.WriteByte(byte(len(tx.Outputs))) // Output count
	transactionHex.Write(outputsBytes.Bytes())
	transactionHex.Write(locktimeBytes)

	return hex.EncodeToString(transactionHex.Bytes()), nil
}
func (tx *Transaction) ToHex(isSigned bool) (string, error) {
	// Version
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, uint32(tx.Version))

	// Inputs
	var inputsBytes bytes.Buffer
	for _, input := range tx.Inputs {
		// Previous Transaction ID (reversed)
		inputTxid := make([]byte, 32)
		if isSigned {
			copy(inputTxid[:], (input.ID))
		} else {
			copy(inputTxid[:], ReverseBytes(input.ID))
		}
		inputsBytes.Write(inputTxid)

		// Output Index
		outputIndexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(outputIndexBytes, uint32(input.Out))
		inputsBytes.Write(outputIndexBytes)

		// Script Length
		if input.Sig != "" { //For Raw Transations
			if strings.Contains(input.Sig, "OP") {
				scrpSig := strings.Split(input.Sig, "/")

				pubKeyHashLen := byte(len(scrpSig[3]))
				scriptpubkeyHash, err := DecodeScriptPubKey(input.Sig, pubKeyHashLen)
				if err != nil {
					log.Println("DDDDD", err)
				}
				//fmt.Println("ScriptSig:", hex.EncodeToString(scriptpubkeyHash))
				input.Sig = hex.EncodeToString(scriptpubkeyHash)
			}
		}
		// Script Length
		if input.Out != -1 { // (only if not coinbase)

			scriptSigBytes, err := hex.DecodeString(input.Sig)
			if err != nil {
				return "", err
			}
			inputsBytes.WriteByte(byte(len(scriptSigBytes)))
			inputsBytes.Write(scriptSigBytes)
		} else { // (assuming no script for coinbase)
			inputsBytes.WriteByte(0x00)
		}
		// Sequence
		sequenceBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequenceBytes, input.Sequence) //0xffffffff)
		inputsBytes.Write(sequenceBytes)
	}

	// Outputs
	var outputsBytes bytes.Buffer
	for _, output := range tx.Outputs {
		// Value (in satoshis)
		valueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueBytes, uint64(output.Value))

		outputsBytes.Write(valueBytes)
		var scriptpubkeyHash []byte
		if strings.Contains(output.PubKeyHash, "OP") {
			//split Strings
			pubKeyHash := strings.Split(output.PubKeyHash, "/")
			// Convert PubKeyHash to bytes
			pubKeyHashBytes, err := hex.DecodeString(pubKeyHash[1]) //(output.PubKeyHash)
			if err != nil {
				fmt.Println("Error decoding PubKeyHash:", err)
				return "", err
			}
			// Calculate the length of PubKeyHash
			pubKeyHashLen := byte(len(pubKeyHashBytes))

			// Deocde ScriptPubKey ASM to byte
			scriptpubkeyHash, err = DecodeScriptPubKey(output.PubKeyHash, pubKeyHashLen)
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
		/*
			scriptSig := append([]byte{OP_One, OP_Two, pubKeyHashLen}, pubKeyHashBytes...) //append([]byte{0x76, 0xa9, pubKeyHashLen}, pubKeyHashBytes...)
			scriptSig = append(scriptSig, OP_Three, OP_Four)                               //append(scriptSig, 0x88, 0xac)
			//script, _ := hex.DecodeString("76" + output.PubKeyHash) // P2PKH script prefix (OP_DUP OP_HASH160 len hash160 OP_EQUALVERIFY OP_CHECKSIG)*/

		// Calculate the length of the P2PKH script
		scriptSig := scriptpubkeyHash
		scriptSigLength := len(scriptSig)
		outputsBytes.WriteByte(byte(scriptSigLength))
		outputsBytes.Write(scriptSig)
	}

	// Locktime
	locktimeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktimeBytes, tx.Locktime)

	// Concatenate all parts
	var transactionHex bytes.Buffer
	transactionHex.Write(versionBytes)
	transactionHex.WriteByte(byte(len(tx.Inputs))) // Input count
	transactionHex.Write(inputsBytes.Bytes())
	transactionHex.WriteByte(byte(len(tx.Outputs))) // Output count
	transactionHex.Write(outputsBytes.Bytes())
	transactionHex.Write(locktimeBytes)

	return hex.EncodeToString(transactionHex.Bytes()), nil
}

// DecodeScriptPubKey converts a scriptPubKey string to a byte slice
func DecodeScriptPubKey(scriptPubKey string, pubKeyHashLen byte) ([]byte, error) {
	// Split the scriptPubKey by spaces
	parts := strings.Fields(scriptPubKey)

	// Create a byte slice to hold the result
	result := []byte{}

	for _, part := range parts {
		switch {
		case part == "OP_DUP":
			result = append(result, 0x76)
		case part == "OP_HASH160":
			result = append(result, 0xa9)
		case part == "OP_EQUALVERIFY":
			result = append(result, 0x88)
		case part == "OP_CHECKSIG":
			result = append(result, 0xac)
		case part == "OP_0":
			result = append(result, 0x00)
		case part == "OP_1":
			result = append(result, 0x51)
		case part == "OP_2":
			result = append(result, 0x52)
		case part == "OP_CHECKMULTISIG":
			result = append(result, 0xae)
		case part == "OP_EQUAL":
			result = append(result, 0x87)
		case strings.HasPrefix(part, "OP_PUSHBYTES_"):
			// Extract the number of bytes to push
			numBytes := strings.TrimPrefix(part, "OP_PUSHBYTES_")
			switch numBytes {
			case "20":
				result = append(result, pubKeyHashLen)
			case "33":
				result = append(result, 0x21)
			case "71":
				result = append(result, 0x47)
			default:
				return nil, fmt.Errorf("unsupported OP_PUSHBYTES: %s", numBytes)
			}
		default:
			// If it's not an opcode, it should be the pubKeyHash
			if strings.HasPrefix(part, "/") && strings.HasSuffix(part, "/") {
				pubKeyHashStr := strings.Trim(part, "/")
				pubKeyHash, err := hex.DecodeString(pubKeyHashStr)
				if err != nil {
					return nil, err
				}
				result = append(result, pubKeyHash...)
			} else {
				return nil, fmt.Errorf("unknown script part: %s", part)
			}
		}
	}

	return result, nil
}

// FromHex decodes a raw transaction in hex format into a Transaction struct.
func FromHex(txHex string) (*Transaction, error) {

	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewReader(txBytes)

	// Read Version
	var version uint32
	err = binary.Read(buf, binary.LittleEndian, &version)
	if err != nil {
		return nil, fmt.Errorf("version error:%v", err)
	}

	// Read input count
	inputCount, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("inputcount error:%v", err)
	}

	inputs := make([]TXInput, inputCount)
	for i := 0; i < int(inputCount); i++ {
		input := TXInput{}

		// Read previous transaction ID
		input.ID = make([]byte, 32)
		_, err := buf.Read(input.ID)
		if err != nil {
			return nil, fmt.Errorf("inputID error:%v", err)
		}

		// Reverse bytes to get the actual transaction ID
		input.ID = ReverseBytes(input.ID)

		// Read output index
		var outIndex uint32
		err = binary.Read(buf, binary.LittleEndian, &outIndex)
		if err != nil {
			return nil, fmt.Errorf("outputIndex error:%v", err)
		}
		input.Out = int(outIndex)

		// Read script length
		scriptLen, err := buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("scriptlength error:%v", err)
		}

		// Read signature script
		sig := make([]byte, scriptLen)
		_, err = buf.Read(sig)
		if err != nil {
			return nil, fmt.Errorf("sig error:%v", err)
		}
		input.Sig = hex.EncodeToString(sig)

		// Read sequence
		var sequence uint32 //sequence := make([]byte, 4)

		err = binary.Read(buf, binary.LittleEndian, &sequence)
		if err != nil {
			return nil, fmt.Errorf("outputIndex error:%v", err)
		}
		input.Sequence = uint32(sequence)

		inputs[i] = input
	}

	// Read output count
	outputCount, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("output count error:%v", err)
	}

	outputs := make([]TXOutput, outputCount)
	for i := 0; i < int(outputCount); i++ {
		output := TXOutput{}

		// Read value
		var outvalue uint64
		err = binary.Read(buf, binary.LittleEndian, &outvalue)
		if err != nil {
			return nil, fmt.Errorf("output error:%v", err)
		}
		output.Value = int(outvalue)
		// Read script length
		scriptLen, err := buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("script lenght error:%v", err)
		}

		// Read public key script
		pubKeyScript := make([]byte, scriptLen)
		_, err = buf.Read(pubKeyScript)
		if err != nil {
			return nil, fmt.Errorf("pubKeyScript error:%v", err)
		}
		output.PubKeyHash = hex.EncodeToString(pubKeyScript)

		outputs[i] = output
	}

	// Read locktime
	var locktime uint32
	err = binary.Read(buf, binary.LittleEndian, &locktime)
	if err != nil {
		return nil, fmt.Errorf("locktime error:%v", err)
	}
	// Compute the transaction ID (double SHA-256 hash of the serialized transaction)
	txID := computeTransactionID(txBytes)
	return &Transaction{
		Version:  int32(version),
		ID:       txID,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
	}, nil
}

// computeTransactionID calculates the transaction ID by performing a double SHA-256 hash on the transaction bytes.
func computeTransactionID(txBytes []byte) []byte {
	hash1 := sha256.Sum256(txBytes)
	hash2 := sha256.Sum256(hash1[:])
	txID := ReverseBytes(hash2[:])
	//log.Printf("Treanscion:%x\n", txID)
	return txID
}

// String converts a Transaction object to a string representation
func (tx *Transaction) ToString() string {
	var lines []string

	//lines = append(lines, fmt.Sprintf("Transaction ID: %x", tx.ID))
	lines = append(lines, fmt.Sprintf("\"version\": %d,", tx.Version))
	lines = append(lines, fmt.Sprintf("\"locktime\": %d,", tx.Locktime))
	lines = append(lines, ("\"vin\": ["))
	for i, input := range tx.Inputs {
		lines = append(lines, ("  {"))
		var sliptSig []string
		if input.Sig != "" {
			if input.Sig[:2] == "47" || input.Sig[:2] == "48" {
				sliptSig = strings.Split(input.Sig[2:], "0121")
			} else if input.Sig[:4] == "0047" || input.Sig[:4] == "0048" {
				sliptSig = strings.Split(input.Sig[4:], "0147")
			}
		}
		scriptasm := func(sliptSig []string) string {
			if len(sliptSig) > 1 {
				return sliptSig[0] + "[ALL]" + sliptSig[1]
			}
			return ""
		}(sliptSig)
		lines = append(lines, fmt.Sprintf("    \"scriptSig\":{\"asm\":\"%s\",\"hex\":\"%s\"},", scriptasm, input.Sig))
		lines = append(lines, fmt.Sprintf("    \"txid\":      \"%x\",", input.ID))
		lines = append(lines, fmt.Sprintf("    \"vout\":       %d", input.Out))
		if (i + 1) == len(tx.Inputs) {
			lines = append(lines, ("  }"))
		} else {
			lines = append(lines, ("  },"))
		}
	}
	lines = append(lines, ("],"))
	lines = append(lines, ("\"vout\": ["))
	for i, output := range tx.Outputs {
		lines = append(lines, fmt.Sprintf("  { \"n\": %d,", i))
		//address
		address := GetAddressFromScriptHash(output)
		var asm string
		var scripttype string
		if strings.HasPrefix(address, "1") {
			asm = GetP2PKHScript(address)
			scripttype = "pubkeyhash"
		} else if strings.HasPrefix(address, "3") {
			asm = GetP2SHScript(address)
			scripttype = "scripthash"
		} else if strings.HasPrefix(address, "bc1") {
			asm = GetP2PWKHScript(address)
			scripttype = "bech32"
		}
		lines = append(lines, fmt.Sprintf("    \"scriptPubKey\":{ \"addresses\":[\"%s\"],\"asm\":\"%s\",\"hex\":\"%s\",\"reqSigs\":%d,\"type\": \"%s\"},", address, asm, output.PubKeyHash, 1, scripttype))
		valueInBtc := float64(output.Value) / float64(SatoshiPerBitcoin)
		lines = append(lines, fmt.Sprintf("    \"value\":  %f", (valueInBtc)))
		if (i + 1) == len(tx.Outputs) {
			lines = append(lines, ("  }"))
		} else {
			lines = append(lines, ("  },"))
		}
	}
	lines = append(lines, ("],"))

	return strings.Join(lines, "\n")
}
func ReverseBytes(data []byte) []byte {
	for i := 0; i < len(data)/2; i++ {
		j := len(data) - i - 1
		data[i], data[j] = data[j], data[i]
	}
	return data
}
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// hash160 returns the RIPEMD-160 hash of the SHA-256 hash of the input data
func doubleSha256(data []byte) []byte {
	sha := sha256.Sum256(data)
	sha_two := sha256.Sum256(sha[:])
	return sha_two[:] //ripemd.Sum(nil)
}

//0100000001e636e0d4ecdd9e530b8542ee29dc7bd0b3db59561d0a12e1e420e536bb22dc09010000006b483045022100b95ef71baebf456275693eca9d474ed13acbabe2ca94a4b42510f3a16f20b9ec022075a93a7064b60fe82887f2ba65f6e5280b277ffdbf15e83e1116ef2b51aeb229012102be8f7ea648d3522731589bca6aaade20fd6767910f77f1c7ae2c51d1048c2abcfeffffff02eb1a6002000000001976a914cb4f45b4ecfe54b25106a919237cf34ce193c1b988ac1d6ca351130000001976a91455ae51684c43435da751ac8d2173b2652eb6410588ac6f1a0600

//4730440220419190915d69763af10b48448a28ea20bd9207f2da75ec41b7a6cc52969c5678022026ae3e03f59405a2c2efe5cd37f95e1f82f45dd4f7cd2c688c58ec7d10d250bd0121
//0298d002f19b185122928f1598a1867ea06f2616dd3f0ad5037f93cb378a46478d
