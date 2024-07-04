package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"minibtcd/trx"
)

type MerkleTree struct {
	RootNode *MerkleNode
}

type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.Data = hash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		node.Data = hash[:]
	}

	node.Left = left
	node.Right = right

	return &node
}

// NewMerkleTree creates a new Merkle tree from a slice of data.
func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data) == 0 {
		return &MerkleTree{nil}
	}
	//log.Println("data", data)
	// Create leaf nodes
	var nodes []MerkleNode
	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, *node)
		//log.Println("nodes", nodes, " len(nodes)", len(nodes))
	}

	// Create parent nodes until only one node is left (the root)
	for len(nodes) > 1 {
		// If odd number of nodes, duplicate the last one
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}
		//log.Println("nodes", nodes)
		var newLevel []MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			node := NewMerkleNode(&nodes[i], &nodes[i+1], nil)
			newLevel = append(newLevel, *node)
		}
		//log.Println("newLevel", newLevel)
		nodes = newLevel
	}

	tree := MerkleTree{&nodes[0]}
	return &tree
}

// VerifyProof verifies the Merkle proof for a given data element.
func VerifyProof(rootHash, data []byte, proof [][]byte) bool {
	hash := sha256.Sum256(data)
	currentHash := hash[:]

	for _, siblingHash := range proof {
		currentHash = append(currentHash, siblingHash...)
		hash := sha256.Sum256(currentHash)
		currentHash = hash[:]
	}

	return bytes.Equal(currentHash, rootHash)
}

func (b *Block) VerifyTransaction(txID []byte) bool {
	merkleTree := NewMerkleTree(b.getTransactionIDs())
	return merkleTree.Contains(txID)
}

func (b *Block) getTransactionIDs() [][]byte {
	var txIDs [][]byte
	for _, tx := range b.Transactions {
		if IsSegWitTransaction(tx) {
			txS := hex.EncodeToString(tx)
			segTx, err := trx.FromSegWitHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			txIDs = append(txIDs, segTx.ID)
		} else {
			txS := hex.EncodeToString(tx)
			txn, err := trx.FromHex(txS)
			if err != nil {
				log.Println("Decode Genesis Hex Error:", err)
			}
			txIDs = append(txIDs, txn.ID)
		}
	}
	return txIDs
}

func (tree *MerkleTree) Contains(data []byte) bool {
	current := tree.RootNode
	hash := sha256.Sum256(data)
	dataHash := hash[:]

	for current.Left != nil && current.Right != nil {
		if current.Left.Contains(dataHash) {
			current = current.Left
		} else if current.Right.Contains(dataHash) {
			current = current.Right
		} else {
			return false
		}
	}

	return bytes.Equal(current.Data, dataHash)
}

func (node *MerkleNode) Contains(data []byte) bool {
	if node == nil {
		return false
	}
	return bytes.Equal(node.Data, data)
}
