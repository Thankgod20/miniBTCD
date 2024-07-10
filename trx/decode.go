package trx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
)

// DecodeBech32 decodes a Bech32 encoded string
func DecodeBech32(bech32 string) (string, []byte, error) {
	const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	if len(bech32) < 8 || len(bech32) > 90 {
		return "", nil, errors.New("invalid bech32 string length")
	}

	for i := 0; i < len(bech32); i++ {
		if bech32[i] < 33 || bech32[i] > 126 {
			return "", nil, errors.New("bech32 string contains invalid characters")
		}
	}

	bech32 = strings.ToLower(bech32)

	sepIndex := strings.LastIndex(bech32, "1")
	if sepIndex == -1 || sepIndex == 0 || sepIndex+7 > len(bech32) {
		return "", nil, errors.New("invalid bech32 separator position")
	}

	hrp := bech32[:sepIndex]
	data := make([]byte, len(bech32[sepIndex+1:]))
	for i, char := range bech32[sepIndex+1:] {
		idx := strings.IndexByte(alphabet, byte(char))
		if idx == -1 {
			return "", nil, errors.New("invalid character in data part")
		}
		data[i] = byte(idx)
	}

	if !verifyChecksum(hrp, data) {
		return "", nil, errors.New("checksum verification failed")
	}

	return hrp, data[:len(data)-6], nil
}
func ConvertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	ret := []byte{}
	maxv := uint32(1<<toBits) - 1
	maxAcc := uint32(1<<(fromBits+toBits-1)) - 1

	for _, value := range data {
		if value>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data range: value %d exceeds %d bits", value, fromBits)
		}
		acc = ((acc << fromBits) | uint32(value)) & maxAcc

		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>uint32(bits))&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid padding")
	}
	return ret, nil
}

// VerifyChecksum verifies the Bech32 checksum
func verifyChecksum(hrp string, data []byte) bool {
	values := append(hrpExpand(hrp), data...)
	return polyMod(values) == 1
}

// HRPExpand expands the HRP for checksum calculation
func hrpExpand(hrp string) []byte {
	hrpLen := len(hrp)
	exp := make([]byte, hrpLen*2+1)
	for i := 0; i < hrpLen; i++ {
		exp[i] = hrp[i] >> 5
		exp[i+hrpLen+1] = hrp[i] & 31
	}
	exp[hrpLen] = 0
	return exp
}

// PolyMod calculates the Bech32 checksum
func polyMod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		if (b & 1) != 0 {
			chk ^= 0x3b6a57b2
		}
		if (b & 2) != 0 {
			chk ^= 0x26508e6d
		}
		if (b & 4) != 0 {
			chk ^= 0x1ea119fa
		}
		if (b & 8) != 0 {
			chk ^= 0x3d4233dd
		}
		if (b & 16) != 0 {
			chk ^= 0x2a1462b3
		}
	}
	return chk
}

// decodeBase58 decodes a Base58 encoded string.
func Base58Decode(input string) ([]byte, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Create a map for quick lookups of character indexes.
	alphabetMap := make(map[rune]int)
	for i, c := range alphabet {
		alphabetMap[(c)] = i
	}

	// Convert the input string to a big integer.
	value := big.NewInt(0)
	base := big.NewInt(58)
	for _, char := range input {
		index, ok := alphabetMap[(char)]
		if !ok {
			return nil, errors.New("invalid character in base58 string")
		}
		value.Mul(value, base)
		value.Add(value, big.NewInt(int64(index)))
	}

	// Count leading zeros.
	zeros := 0
	for zeros < len(input) && input[zeros] == alphabet[0] {
		zeros++
	}

	// Convert the big integer to a byte slice.
	decoded := value.Bytes()

	// Add leading zeros.
	result := make([]byte, zeros+len(decoded))
	copy(result[zeros:], decoded)

	return result, nil
}
func CheckSumLegacy(versionedPayload []byte) []byte {

	// Step 4: SHA-256 hash of the extended RIPEMD-160 result.
	firstSHA := sha256.Sum256(versionedPayload)
	secondSHA := sha256.Sum256(firstSHA[:])

	// Step 5: Take the first 4 bytes of the second SHA-256 hash. This is the address checksum.
	checksum := secondSHA[:4]

	return checksum
}

// CreateChecksum creates a Bech32 checksum
func bech32Checksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, []byte{0, 0, 0, 0, 0, 0}...)
	mod := polyMod(values) ^ 1
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	return checksum
}
func bech32Encode(hrp string, data []byte) (string, error) {
	const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	// Calculate the checksum
	checksum := bech32Checksum(hrp, data)

	// Combine the data and checksum
	combined := append(data, checksum...)

	// Encode the combined data and checksum to a Bech32 string
	var result string
	for _, value := range combined {
		if value >= 32 {
			return "", fmt.Errorf("invalid data value: %d", value)
		}
		result += string(alphabet[value])
	}

	return hrp + "1" + result, nil
}

// encodeBech32 encodes a byte array to a Bech32 address
func EncodeBech32(data []byte) (string, error) {
	// Bech32 encoding parameters
	const hrp = "bc"  // Human-readable part for mainnet
	const version = 0 // Witness version

	// Convert the data to a 5-bit array
	data5, err := ConvertBits(data, 8, 5, true)
	//fmt.Println("data5", data5)
	if err != nil {
		return "", err
	}

	// Prepend the version byte
	versionData := append([]byte{version}, data5...)

	// Create the Bech32 address
	bech32Address, err := bech32Encode(hrp, versionData)
	if err != nil {
		return "", err
	}
	return bech32Address, nil
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

// Base58Encode encodes a byte slice into a Base58 string.
func Base58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zeros.
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// Convert the input to a big integer.
	value := new(big.Int).SetBytes(input)

	// Convert the big integer to a Base58 string.
	result := make([]byte, 0, len(input)*136/100)
	for value.Sign() > 0 {
		mod := new(big.Int)
		value.DivMod(value, big.NewInt(58), mod)
		result = append(result, alphabet[mod.Int64()])
	}

	// Add leading zeros.
	for i := 0; i < zeros; i++ {
		result = append(result, alphabet[0])
	}

	// Reverse the result.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func GetAddressFromScriptHash(out TXOutput) string {
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
		checksum := CheckSumLegacy(versionedPayload)
		//Add the 4 checksum bytes at the end of extended RIPEMD-160 hash to form the binary Bitcoin address.
		binaryAddress := append(versionedPayload, checksum...)
		fmt.Printf("CheckSume %x binaryAddr: %x\n", checksum, binaryAddress)
		address = Base58Encode(binaryAddress)
	} else if Addrtype == "P2PWKH" {
		pubKeyByte, _ := hex.DecodeString(pubKeyHash)
		bech32Address, err := EncodeBech32(pubKeyByte)
		if err != nil {
			return ""
		}
		address = bech32Address
	}
	return address
}
func GetP2PWKHScript(address string) string {
	_, r_pubKey, _ := DecodeBech32(address)
	decodedData, err := ConvertBits(r_pubKey[1:], 5, 8, false)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return ""
	}
	//pubLen := byte(len(decodedData))
	outputs := "OP_0 OP_PUSHBYTES_20 " + hex.EncodeToString(decodedData)

	return outputs
}
func SingleSha256(data []byte) []byte {
	sha := sha256.Sum256(data)
	//sha_two := sha256.Sum256(sha[:])
	return sha[:] //ripemd.Sum(nil)
}
func GetP2PKHScript(address string) string {
	r_pubKey, err := Base58Decode(address)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return ""
	}

	//pubLen := byte(len(pubByte))
	outputs := "OP_DUP OP_HASH160 OP_PUSHBYTES_20 " + hex.EncodeToString(r_pubKey)[2:42] + " OP_EQUALVERIFY OP_CHECKSIG"

	return outputs
}
func GetP2SHScript(address string) string {
	r_pubKey, err := Base58Decode(address)
	if err != nil {
		fmt.Println("Error Converting:", err)
		return ""
	}

	outputs := "OP_HASH160 OP_PUSHBYTES_20 " + hex.EncodeToString(r_pubKey)[2:42] + " OP_EQUAL"

	return outputs
}
