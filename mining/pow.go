// pow.go
package mining

import (
	"bytes"
	"crypto/sha256"
	"log"
	"math/big"

	"github.com/Thankgod20/miniBTCD/blockchain"

	"strconv"
)

const targetBits = 2

type ProofOfWork struct {
	block  *blockchain.Block
	target *big.Int
}

func NewProofOfWork(b *blockchain.Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))
	log.Println("Target :", target)
	return &ProofOfWork{b, target}
}
func (pow *ProofOfWork) GetBits() []byte {

	// Calculate the exponent and coefficient
	exponent := (pow.target.BitLen() + 7) / 8
	exponentByte := byte(exponent)
	coefficient := new(big.Int).Div(pow.target, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(8*(exponent-3))), nil))
	// Pack exponent and coefficient into a single byte
	//var packedByte []byte
	Bits := append([]byte{exponentByte}, coefficient.Bytes()...)
	/*
		// Convert the big.Int to a hex string and pad with zeros if necessary
		hexConverted := fmt.Sprintf("%0*x", expectedLength, pow.target)
		targetBytes, _ := hex.DecodeString(hexConverted) //pow.target.Bytes()
		length := len(targetBytes)

		// If the target length is less than 3, we need to pad it
		if length <= 3 {
			compact := int(targetBytes[0])
			if length > 1 {
				compact = compact<<8 | int(targetBytes[1])
			}
			if length > 2 {
				compact = compact<<8 | int(targetBytes[2])
			}
			return compact << (8 * (3 - length))
		}

		// If the target length is greater than 3, we need to truncate it
		compact := int(targetBytes[0]) << 16
		compact |= int(targetBytes[1]) << 8
		compact |= int(targetBytes[2])
		exponent := len(targetBytes) - 3
		return compact | exponent<<24*/
	return Bits
}

func (pow *ProofOfWork) Run() (int, []byte, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := 0

	for nonce < (1<<63 - 1) {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}

	return nonce, pow.GetBits(), hash[:]
}

func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			pow.block.HashTransactions(),
			IntToHex(int64(pow.block.Timestamp)),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)
	return data
}

func IntToHex(n int64) []byte {
	return []byte(strconv.FormatInt(n, 16))
}
