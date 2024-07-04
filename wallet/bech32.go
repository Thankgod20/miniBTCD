// bech32.go
package wallet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

// hash160 returns the RIPEMD-160 hash of the SHA-256 hash of the input data
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

// publicKeyToBech32Address converts a public key to a Bech32 address
func publicKeyToBech32Address(publicKey []byte) (string, error) {
	// Convert the public key to a public key hash
	pubKeyHash := hash160(publicKey)

	// Create the Bech32 address
	bech32Address, err := encodeBech32(pubKeyHash)
	if err != nil {
		return "", err
	}
	return bech32Address, nil
}
func publicKeyToP2PKHAddress(publicKey []byte) (string, error) {
	// Convert the public key to a public key hash
	pubKeyHash := hash160(publicKey)
	versionedPayload := append([]byte{0x00}, pubKeyHash...)

	//checksum of address
	checksum := checkSumLegacy(versionedPayload)

	//Add the 4 checksum bytes at the end of extended RIPEMD-160 hash to form the binary Bitcoin address.
	binaryAddress := append(versionedPayload, checksum...)
	//Convert the binary address to Base58.
	address := Base58Encode(binaryAddress)
	return address, nil
}
func publicKeyToP2SHAddress(publicKey []byte) (string, error) {
	// Convert the public key to a public key hash
	pubKeyHash := hash160(publicKey)
	versionedPayload := append([]byte{0x05}, pubKeyHash...)

	//checksum of address
	checksum := checkSumLegacy(versionedPayload)

	//Add the 4 checksum bytes at the end of extended RIPEMD-160 hash to form the binary Bitcoin address.
	binaryAddress := append(versionedPayload, checksum...)
	//Convert the binary address to Base58.
	address := Base58Encode(binaryAddress)
	return address, nil
}
func checkSumLegacy(versionedPayload []byte) []byte {

	// Step 4: SHA-256 hash of the extended RIPEMD-160 result.
	firstSHA := sha256.Sum256(versionedPayload)
	secondSHA := sha256.Sum256(firstSHA[:])

	// Step 5: Take the first 4 bytes of the second SHA-256 hash. This is the address checksum.
	checksum := secondSHA[:4]

	return checksum
}

// encodeBech32 encodes a byte array to a Bech32 address
func encodeBech32(data []byte) (string, error) {
	// Bech32 encoding parameters
	const hrp = "bc"  // Human-readable part for mainnet
	const version = 0 // Witness version

	// Convert the data to a 5-bit array
	data5, err := convertBits(data, 8, 5, true)
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

// convertBits converts a byte array from one base to another
/*
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	var out []byte

	maxv := uint32((1 << toBits) - 1)
	for _, value := range data {
		acc = (acc << fromBits) | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}

	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	return out, nil
}*/
// ConvertBits converts between groups of bits
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
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

// bech32Encode encodes data to a Bech32 string
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

// VerifyChecksum verifies the Bech32 checksum
func verifyChecksum(hrp string, data []byte) bool {
	values := append(hrpExpand(hrp), data...)
	return polyMod(values) == 1
}

// Checksum calculates the checksum for the input byte slice.
func Checksum(input []byte) []byte {
	hash := sha256Sum(sha256Sum(input))
	return hash[:4]
}

// sha256Sum returns the SHA-256 checksum of the data.
func sha256Sum(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// Determine the type of Bitcoin address
func getAddressType(address string) (string, error) {
	if len(address) == 0 {
		return "", errors.New("address is empty")
	}

	// Check for Bech32 addresses
	if strings.HasPrefix(address, "bc1") || strings.HasPrefix(address, "tb1") {
		if isValidBech32(address) {
			if strings.HasPrefix(address, "bc1q") || strings.HasPrefix(address, "tb1q") {
				return "Bech32 (P2WPKH)", nil
			}
			if strings.HasPrefix(address, "bc1p") || strings.HasPrefix(address, "tb1p") {
				return "Bech32m (Taproot)", nil
			}
			return "Bech32 (P2WSH)", nil
		}
		return "", errors.New("invalid Bech32 address")
	}

	// Decode Base58Check addresses
	decoded, err := Base58Decode(address)
	if err != nil {
		return "", err
	}

	if len(decoded) < 4 {
		return "", errors.New("invalid address length")
	}

	// Verify the checksum
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	expectedChecksum := Checksum(payload)
	if !bytes.Equal(checksum, expectedChecksum) {
		return "", errors.New("invalid checksum")
	}

	// Determine address type based on prefix
	switch decoded[0] {
	case 0x00:
		return "P2PKH", nil
	case 0x05:
		return "P2SH", nil
	default:
		return "Unknown", nil
	}
}

// Validates Bech32 addresses using regex
func isValidBech32(address string) bool {
	bech32Regex := `^(bc1|tb1)[ac-hj-np-z02-9]{25,39}$`
	match, _ := regexp.MatchString(bech32Regex, address)
	return match
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

//const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

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
