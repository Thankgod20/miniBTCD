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
	"strings"
)

type SegWit struct {
	Version  int32
	Marker   byte
	Flag     byte
	ID       []byte
	Inputs   []SegTXInput
	Outputs  []TXOutput
	Locktime uint32
	Witness  [][][]byte // Witness data
}

type SegTXInput struct {
	ID       []byte
	Out      int
	Sig      string
	Sequence uint32
	//
}

// SetID sets the transaction ID as a SHA-256 hash of the transaction
func (tx *SegWit) SetID() {
	hexStr, _ := tx.ToHex(false)
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Println("Error Seting ID", err)
	}
	txID := computeTransactionID(txBytes)
	tx.ID = txID
}

// Hash returns a SHA-256 hash of the transaction for signing
func (tx *SegWit) Hash() []byte {
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = []byte{}
	var encoded bytes.Buffer
	gob.NewEncoder(&encoded).Encode(txCopy)
	hash = sha256.Sum256(encoded.Bytes())

	return hash[:]
}

// NewTransaction creates a new transaction with the given inputs and outputs
func NewSegWitTransaction(version int32, inputs []SegTXInput, outputs []TXOutput, locktime uint32, witness [][][]byte) *SegWit {
	tx := &SegWit{
		Version:  version,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
		Witness:  witness,
	}
	tx.Marker = 0x00
	tx.Flag = 0x01
	tx.SetID()
	return tx
}

func CreateGenesisSegWitCoinbase(coinbaseData string, toAddress string, amount int) *SegWit {
	pubKeyHash := hash160([]byte(toAddress))
	pubKeyHashStr := hex.EncodeToString(pubKeyHash)
	txin := SegTXInput{
		ID:       []byte{}, // Genesis coinbase transaction has no ID
		Out:      -1,       // Genesis coinbase transaction has no output
		Sig:      coinbaseData,
		Sequence: uint32(0xffffffff), //byte{0xffffffff},
		//Witness: [][]byte{},
	}
	txout := TXOutput{
		Value:      amount * SatoshiPerBitcoin,
		PubKeyHash: pubKeyHashStr,
	}
	tx := NewSegWitTransaction(2, []SegTXInput{txin}, []TXOutput{txout}, 0, [][][]byte{})
	return tx
}

func CreateSigWitCoinbase(coinbaseData string, toAddress string, amount int) *SegWit {
	pubKeyHash := hash160([]byte(toAddress))
	pubKeyHashStr := hex.EncodeToString(pubKeyHash)
	txin := SegTXInput{
		ID:       []byte{}, // Genesis coinbase transaction has no ID
		Out:      -1,       // Genesis coinbase transaction has no output
		Sig:      coinbaseData,
		Sequence: uint32(0xffffffff), //Witness: [][]byte{},
	}
	txout := TXOutput{
		Value:      amount * SatoshiPerBitcoin,
		PubKeyHash: pubKeyHashStr,
	}
	tx := NewSegWitTransaction(2, []SegTXInput{txin}, []TXOutput{txout}, 0, [][][]byte{})
	return tx
}

// HexToTransaction converts a hexadecimal string to a Transaction object
func HexToSigWit(hexStr string) (*SegWit, error) {
	txBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	var tx SegWit
	err = json.Unmarshal(txBytes, &tx)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func SegWitToHex(tx *SegWit) (string, error) {
	// Version
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, uint32(tx.Version))
	//Marker
	markerBytes := tx.Marker
	// Flag
	flagBytes := tx.Flag

	// Inputs
	var inputsBytes bytes.Buffer
	for _, input := range tx.Inputs {
		// Previous Transaction ID (reversed)
		inputTxid := make([]byte, 32)
		copy(inputTxid[:], ReverseBytes(input.ID))
		inputsBytes.Write(inputTxid)

		// Output Index
		outputIndexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(outputIndexBytes, uint32(input.Out))
		inputsBytes.Write(outputIndexBytes)

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
		binary.LittleEndian.PutUint32(sequenceBytes, input.Sequence)
		inputsBytes.Write(sequenceBytes)
	}

	// Outputs
	var outputsBytes bytes.Buffer
	for _, output := range tx.Outputs {
		// Value (in satoshis)
		valueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueBytes, uint64(output.Value))

		outputsBytes.Write(valueBytes)

		// Convert PubKeyHash to bytes
		pubKeyHashBytes, err := hex.DecodeString(output.PubKeyHash)
		if err != nil {
			fmt.Println("Error decoding PubKeyHash:", err)
			return "", err
		}
		// Calculate the length of PubKeyHash
		pubKeyHashLen := byte(len(pubKeyHashBytes))

		// Script (P2PKH script)
		// Construct the scriptsig: "76" (OP_DUP) + "a9" (OP_HASH160) + length byte + PubKeyHash + "88" (OP_EQUALVERIFY) + "ac" (OP_CHECKSIG)
		scriptSig := append([]byte{0x76, 0xa9, pubKeyHashLen}, pubKeyHashBytes...)
		scriptSig = append(scriptSig, 0x88, 0xac)
		//script, _ := hex.DecodeString("0014" + output.PubKeyHash) // P2PKH script prefix (OP_DUP OP_HASH160 len hash160 OP_EQUALVERIFY OP_CHECKSIG)

		// Calculate the length of the P2PKH script
		scriptSigLength := len(scriptSig)
		outputsBytes.WriteByte(byte(scriptSigLength))

		//Write Script
		outputsBytes.Write(scriptSig)
	}

	// Locktime
	locktimeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktimeBytes, tx.Locktime)

	// Witness (if any)
	/*
		var witnessBytes bytes.Buffer
		for _, input := range tx.Inputs {
			for _, witness := range input.Witness {
				witnessBytes.WriteByte(byte(len(witness)))
				witnessBytes.Write(witness)
			}
		}*/
	var witnessBytes bytes.Buffer
	for _, Inputwitness := range tx.Witness {
		witnessBytes.WriteByte(byte(len(Inputwitness)))
		for _, witness := range Inputwitness {
			witnessBytes.WriteByte(byte(len(witness)))
			witnessBytes.Write(witness)
		}
	}
	// Concatenate all parts
	var transactionHex bytes.Buffer
	transactionHex.Write(versionBytes)
	transactionHex.WriteByte(markerBytes)
	transactionHex.WriteByte(flagBytes)
	transactionHex.WriteByte(byte(len(tx.Inputs))) // Input count
	transactionHex.Write(inputsBytes.Bytes())
	transactionHex.WriteByte(byte(len(tx.Outputs))) // Output count
	transactionHex.Write(outputsBytes.Bytes())
	transactionHex.Write(witnessBytes.Bytes())
	transactionHex.Write(locktimeBytes)

	return hex.EncodeToString(transactionHex.Bytes()), nil
}

func (tx *SegWit) ToHex(isSigned bool) (string, error) {
	// Version
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, uint32(tx.Version))

	//Marker
	markerBytes := tx.Marker
	// Flag
	flagBytes := tx.Flag //[]byte{tx.Flag}
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
		if input.Out != -1 && tx.Marker != 0x00 { // (only if not coinbase)

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
		//
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
		} /*
			// Convert PubKeyHash to bytes
			pubKeyHashBytes, err := hex.DecodeString(output.PubKeyHash)
			if err != nil {
				fmt.Println("Error decoding PubKeyHash:", err)
				return "", err
			}
			// Calculate the length of PubKeyHash
			pubKeyHashLen := byte(len(pubKeyHashBytes))

			// Script (P2PKH script)
			// Construct the scriptsig: "76" (OP_DUP) + "a9" (OP_HASH160) + length byte + PubKeyHash + "88" (OP_EQUALVERIFY) + "ac" (OP_CHECKSIG)
			scriptSig := append([]byte{0x76, 0xa9, pubKeyHashLen}, pubKeyHashBytes...)
			scriptSig = append(scriptSig, 0x88, 0xac)
			//script, _ := hex.DecodeString("76" + output.PubKeyHash) // P2PKH script prefix (OP_DUP OP_HASH160 len hash160 OP_EQUALVERIFY OP_CHECKSIG)

			// Calculate the length of the P2PKH script
			scriptSigLength := len(scriptSig)
			outputsBytes.WriteByte(byte(scriptSigLength))
			outputsBytes.Write(scriptSig)*/
		scriptSig := scriptpubkeyHash
		scriptSigLength := len(scriptSig)
		outputsBytes.WriteByte(byte(scriptSigLength))
		outputsBytes.Write(scriptSig)
	}

	// Locktime
	locktimeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktimeBytes, tx.Locktime)

	// Witness (if any)
	/*
		var witnessBytes bytes.Buffer
		for _, input := range tx.Inputs {
			for _, witness := range input.Witness {
				witnessBytes.WriteByte(byte(len(witness)))
				witnessBytes.Write(witness)
			}
		}*/

	var witnessBytes bytes.Buffer
	for _, Inputwitness := range tx.Witness {
		witnessBytes.WriteByte(byte(len(Inputwitness)))
		for _, witness := range Inputwitness {
			//fmt.Println("Data Length", len(witness))
			witnessBytes.WriteByte(byte(len(witness)))
			witnessBytes.Write(witness)
		}
	}
	if len(tx.Witness) == 0 {
		//log.Println("WitnessByte", hex.EncodeToString([]byte{0x00}))
	}
	// Concatenate all parts
	var transactionHex bytes.Buffer
	transactionHex.Write(versionBytes)
	transactionHex.WriteByte(markerBytes)
	transactionHex.WriteByte(flagBytes)            //transactionHex.Write(flagBytes)
	transactionHex.WriteByte(byte(len(tx.Inputs))) // Input count
	transactionHex.Write(inputsBytes.Bytes())
	transactionHex.WriteByte(byte(len(tx.Outputs))) // Output count
	transactionHex.Write(outputsBytes.Bytes())
	if len(tx.Witness) == 0 {
		transactionHex.Write([]byte{0x00}) //log.Println("WitnessByte", hex.EncodeToString([]byte{0x00}))
	} else {
		transactionHex.Write(witnessBytes.Bytes())
	}
	transactionHex.Write(locktimeBytes)

	return hex.EncodeToString(transactionHex.Bytes()), nil
}

// FromHex decodes a raw transaction in hex format into a Transaction struct.
func FromSegWitHex(txHex string) (*SegWit, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewReader(txBytes)
	/*
		extractByte := func(start, end int64) []byte {
			return txBytes[start:end]
		}*/

	// Read Version
	var version uint32
	err = binary.Read(buf, binary.LittleEndian, &version)
	if err != nil {
		return nil, fmt.Errorf("version error:%v", err)
	}

	//Read marker
	var marker byte
	binary.Read(buf, binary.LittleEndian, &marker)

	// Read flag
	var flag byte
	binary.Read(buf, binary.LittleEndian, &flag)

	// Read input count
	inputCount, err := buf.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("inputcount error:%v", err)
	}

	inputs := make([]SegTXInput, inputCount)
	for i := 0; i < int(inputCount); i++ {
		input := SegTXInput{}

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
		//startPosz := buf.Size() - int64(buf.Len())
		var outvalue uint64
		err = binary.Read(buf, binary.LittleEndian, &outvalue)
		if err != nil {
			return nil, fmt.Errorf("output error:%v", err)
		}
		//endPosz := buf.Size() - int64(buf.Len())
		//	extratBytz := extractByte(startPosz, endPosz)
		//	fmt.Println("Script Length:", (outvalue), startPosz, endPosz, hex.EncodeToString(extratBytz))
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

	// Read Witness
	var witnessInputData [][][]byte
	for i := 0; i < int(inputCount); i++ {
		witnessCount, err := buf.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("witness count error: %v", err)
		}

		witness := make([][]byte, witnessCount)
		for j := 0; j < int(witnessCount); j++ {
			//startPos := buf.Size() - int64(buf.Len())
			witnessLength, err := buf.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("witness length error: %v", err)
			}
			//endPos := buf.Size() - int64(buf.Len())
			//extratByt := extractByte(startPos, endPos)
			//fmt.Println("Script Length:", (witnessCount), startPos, endPos, hex.EncodeToString(extratByt))
			witnessItem := make([]byte, witnessLength)
			_, err = buf.Read(witnessItem)
			if err != nil {
				return nil, fmt.Errorf("witness item error: %v", err)
			}
			witness[j] = witnessItem //witnessItem
			//witnessData = append(witnessData, witnessItem)
		}
		witnessInputData = append(witnessInputData, witness)
	}

	// Read locktime
	var locktime uint32
	err = binary.Read(buf, binary.LittleEndian, &locktime)
	if err != nil {
		return nil, fmt.Errorf("locktime error:%v", err)
	}
	// Compute the transaction ID (double SHA-256 hash of the serialized transaction)
	txID := computeTransactionID(txBytes)
	return &SegWit{
		Version:  int32(version),
		Marker:   marker,
		Flag:     flag,
		ID:       txID,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
		Witness:  witnessInputData,
	}, nil
}

// String converts a Transaction object to a string representation
func (tx *SegWit) ToString() string {
	var lines []string
	//log.Println("len(tx.Witness)", len(tx.Witness))
	lines = append(lines, fmt.Sprintf("Transaction ID: %x", tx.ID))
	lines = append(lines, fmt.Sprintf("Version: %d", tx.Version))
	lines = append(lines, fmt.Sprintf("Marker: %d", tx.Marker))
	lines = append(lines, fmt.Sprintf("Flag: %d", tx.Flag))
	for i, input := range tx.Inputs {
		lines = append(lines, fmt.Sprintf("  Input %d:", i))
		lines = append(lines, fmt.Sprintf("    TXID:      %x", input.ID))
		lines = append(lines, fmt.Sprintf("    Out:       %d", input.Out))
		lines = append(lines, fmt.Sprintf("    Signature: %s", input.Sig))
		lines = append(lines, fmt.Sprintf("    Sequence: %d", input.Sequence))
		if len(tx.Witness[i]) > 0 {
			lines = append(lines, fmt.Sprintf("    Witness: [\"%x\",\"%x\"]", tx.Witness[i][0], tx.Witness[i][1]))
		} else {
			lines = append(lines, fmt.Sprintf("    Witness: []"))
		}

	}

	for i, output := range tx.Outputs {
		lines = append(lines, fmt.Sprintf("  Output %d:", i))
		lines = append(lines, fmt.Sprintf("    Value:  %d", output.Value))
		lines = append(lines, fmt.Sprintf("    PubKeyHash: %s", output.PubKeyHash))
	} /*
		for j, witnessInput := range tx.Witness {
			lines = append(lines, fmt.Sprintf("  InputWitness %d:", j))
			for i, witness := range witnessInput {
				lines = append(lines, fmt.Sprintf("   Witness %d:", i))
				lines = append(lines, fmt.Sprintf("     %x", witness))

			}
		}*/
	lines = append(lines, fmt.Sprintf("Locktime: %d", tx.Locktime))
	return strings.Join(lines, "\n")
}

//020000000001026811a32e6593d24725431c90bfe45a58ee4b984f747e4dfe2bd76ce753d03420010000000000000080afd6c40dc833b96ce158ee04580a8d4cb5702333944842d6f31caa73efa8dce10700000000000000800171c60500000000001976a9146c95fdba7e444ddc6458fd606926e6a46f62da2b88ac024730440220316399e1e37742027406857d61e8f0f653913b30de66a413481aca7f911b7c8a02207613b757e07eee4a34afffeccb7b174f5e7cf834d7d4d918912101cdc0cce589012102ff05492985d9a401aa0e90d58db8b3bd568a190cf85cfe06863d482c31aaaf3102483045022100fc20174fd42b6795841014b33dd84416dbe31bd9dc6616746afdb4012eac40440220143dfbcc33754d5250e235b41473252e95dea69c02b860c2da70088d84df8ca30121034b8f756a62acc401c90659c8d034828eb1ab8c3d7e25e568c33e671f636100b000000000

//76a9146c95fdba7e444ddc6458fd606926e6a46f62da2b88ac
//76a91478302883615a511996a1971abaad678b9c095dfd88a9
