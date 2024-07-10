package trx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

func SegTxID(bytesData []byte) []byte {

	// Convert hexadecimal string to byte slice
	/*bytesData, err := hex.DecodeString(data)
	if err != nil {
		fmt.Println("Error decoding hex string:", err)
		return nil
	}
	*/
	// Use bytes.Reader for better byte handling
	reader := bytes.NewReader(bytesData)

	// Read version (4 bytes)
	version := make([]byte, 4)
	if _, err := reader.Read(version); err != nil {
		fmt.Println("Error reading version:", err)
		return nil
	}

	// Read marker and flag (2 bytes)
	markerAndFlag := make([]byte, 2)
	if _, err := reader.Read(markerAndFlag); err != nil {
		fmt.Println("Error reading marker and flag:", err)
		return nil
	}

	// Read input count (1 byte for simplicity, but could be varint)
	// Read input count
	inputCount, err := reader.ReadByte()
	if err != nil {
		fmt.Errorf("inputcount error:%v", err)
		return nil
	}

	// Read inputs
	inputs := make([]byte, 0)
	for i := (0); i < int(inputCount); i++ {
		input, err := readInput(reader)
		if err != nil {
			fmt.Println("Error reading input:", err)
			return nil
		}
		inputs = append(inputs, input...)
	}

	// Read output count
	outputCount, err := reader.ReadByte()
	if err != nil {
		fmt.Errorf("output count error:%v", err)
		return nil
	}

	outputs := make([]byte, 0)
	for i := (0); i < int(outputCount); i++ {
		output, err := readOutput(reader)
		if err != nil {
			fmt.Println("Error reading output:", err)
			return nil
		}
		outputs = append(outputs, output...)
	}
	// Read Witness
	var witnessInputData [][][]byte
	for i := 0; i < int(inputCount); i++ {
		witnessCount, err := reader.ReadByte()
		if err != nil {
			fmt.Errorf("witness count error: %v", err)
			return nil
		}

		witness := make([][]byte, witnessCount)
		for j := 0; j < int(witnessCount); j++ {
			//startPos := buf.Size() - int64(buf.Len())
			witnessLength, err := reader.ReadByte()
			if err != nil {
				fmt.Errorf("witness length error: %v", err)
				return nil
			}

			witnessItem := make([]byte, witnessLength)
			_, err = reader.Read(witnessItem)
			if err != nil {
				fmt.Errorf("witness item error: %v", err)
				return nil
			}
			witness[j] = witnessItem //witnessItem
			//witnessData = append(witnessData, witnessItem)
		}
		witnessInputData = append(witnessInputData, witness)
	}

	// Read locktime (4 bytes)
	locktime := make([]byte, 4)
	if _, err := reader.Read(locktime); err != nil {
		fmt.Println("Error reading locktime:", err)
		return nil
	}

	// Concatenate version, input count, inputs, output count, outputs, and locktime
	strippedBytes := append(version, []byte{inputCount}...)

	strippedBytes = append(strippedBytes, inputs...)

	strippedBytes = append(strippedBytes, []byte{outputCount}...)

	strippedBytes = append(strippedBytes, outputs...)

	strippedBytes = append(strippedBytes, locktime...)
	//fmt.Printf("SegTrx: %x\n", strippedBytes)
	// SHA-256 (first round)
	hash1 := sha256.Sum256(strippedBytes)

	// SHA-256 (second round)
	hash2 := sha256.Sum256(hash1[:])

	txID := ReverseBytes(hash2[:])
	return txID
}

// readVarInt reads a variable length integer from the reader
func readVarInt(r io.Reader) ([]byte, error) {
	firstByte := make([]byte, 1)
	if _, err := r.Read(firstByte); err != nil {
		return nil, err
	}

	varint := firstByte
	if firstByte[0] == 0xfd {
		extraBytes := make([]byte, 2)
		if _, err := r.Read(extraBytes); err != nil {
			return nil, err
		}
		varint = append(varint, extraBytes...)
	} else if firstByte[0] == 0xfe {
		extraBytes := make([]byte, 4)
		if _, err := r.Read(extraBytes); err != nil {
			return nil, err
		}
		varint = append(varint, extraBytes...)
	} else if firstByte[0] == 0xff {
		extraBytes := make([]byte, 8)
		if _, err := r.Read(extraBytes); err != nil {
			return nil, err
		}
		varint = append(varint, extraBytes...)
	}

	return varint, nil
}

// readInput reads an input from the reader
func readInput(r io.Reader) ([]byte, error) {
	input := make([]byte, 36) // 32 bytes for txid + 4 bytes for vout
	if _, err := r.Read(input); err != nil {
		return nil, err
	}

	// Read scriptSig length (varint)
	scriptSigLen, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	input = append(input, scriptSigLen...)

	// Read scriptSig
	scriptSig := make([]byte, varIntToUint64(scriptSigLen))
	if _, err := r.Read(scriptSig); err != nil {
		return nil, err
	}
	input = append(input, scriptSig...)

	// Read sequence (4 bytes)
	sequence := make([]byte, 4)
	if _, err := r.Read(sequence); err != nil {
		return nil, err
	}
	input = append(input, sequence...)

	return input, nil
}

// readOutput reads an output from the reader
func readOutput(r io.Reader) ([]byte, error) {
	output := make([]byte, 8) // 8 bytes for value
	if _, err := r.Read(output); err != nil {
		return nil, err
	}

	// Read scriptPubKey length (varint)
	scriptPubKeyLen, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	output = append(output, scriptPubKeyLen...)

	// Read scriptPubKey
	scriptPubKey := make([]byte, varIntToUint64(scriptPubKeyLen))
	if _, err := r.Read(scriptPubKey); err != nil {
		return nil, err
	}
	output = append(output, scriptPubKey...)

	return output, nil
}

// reverseHex reverses the byte order of a hexadecimal string
func reverseHex(hexStr string) string {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Println("Error decoding hex string:", err)
		return ""
	}

	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	return hex.EncodeToString(bytes)
}

// varIntToUint64 converts a variable length integer to a uint64
func varIntToUint64(varint []byte) uint64 {
	switch len(varint) {
	case 1:
		return uint64(varint[0])
	case 3:
		return uint64(varint[1]) | uint64(varint[2])<<8
	case 5:
		return uint64(varint[1]) | uint64(varint[2])<<8 | uint64(varint[3])<<16 | uint64(varint[4])<<24
	case 9:
		return uint64(varint[1]) | uint64(varint[2])<<8 | uint64(varint[3])<<16 | uint64(varint[4])<<24 |
			uint64(varint[5])<<32 | uint64(varint[6])<<40 | uint64(varint[7])<<48 | uint64(varint[8])<<56
	default:
		return 0
	}
}
