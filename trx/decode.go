package trx

import (
	"errors"
	"fmt"
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
