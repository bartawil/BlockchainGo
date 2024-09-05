package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
)

// Struct to store plaintext and ciphertext blocks
type Block struct {
	Plaintext    string
	Ciphertext   string
	PreviousHash string
}

// Function to split data into blocks of fixed size
func splitIntoBlocks(data string, blockSize int) []string {
	var blocks []string
	for i := 0; i < len(data); i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		blocks = append(blocks, data[i:end])
	}
	return blocks
}

// Function to hash a block using SHA256
func hashBlock(block string, previousBlock string) string {
	hash := sha256.New()
	hash.Write([]byte(block + previousBlock))
	return hex.EncodeToString(hash.Sum(nil))
}

// Create a blockchain from a string of data
func createBlockchain(data string, blockSize int) []Block {
	plaintextBlocks := splitIntoBlocks(data, blockSize)
	var blockchain []Block

	var previousHash string

	for _, block := range plaintextBlocks {
		hashed := hashBlock(block, previousHash)
		newBlock := Block{Plaintext: block, Ciphertext: hashed, PreviousHash: previousHash}
		blockchain = append(blockchain, newBlock)
		previousHash = hashed
	}

	return blockchain
}

// Function to verify the integrity of a blockchain
func verifyBlockchain(blockchain []Block) bool {
	for i := 1; i < len(blockchain); i++ {
		currentBlock := blockchain[i]
		previousBlock := blockchain[i-1]

		// check if the previous hash matches the hash of the previous block
		if currentBlock.PreviousHash != previousBlock.Ciphertext {
			return false
		}
		// check if the hash of the plaintext matches the ciphertext
		if hashBlock(currentBlock.Plaintext, previousBlock.Ciphertext) != currentBlock.Ciphertext {
			return false
		}
	}
	return true
}

// Function to read a file and return its contents
func readFile(filePath string) ([]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func main() {
	filePath := "check.text"

	data, err := readFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	fmt.Print("File Content: ")
	fmt.Println(string(data))

	dataStr := string(data) // Convert []byte to string
	blockSize := 10

	blockchain := createBlockchain(dataStr, blockSize)
	for i, block := range blockchain {
		fmt.Printf("Block %d:\n", i+1)
		fmt.Println("Plaintext:", block.Plaintext)
		fmt.Println("Ciphertext:", block.Ciphertext)
		fmt.Println("PreviousHash:", block.PreviousHash)
		fmt.Println()
	}

	if verifyBlockchain(blockchain) {
		fmt.Println("Blockchain is valid!")
	} else {
		fmt.Println("Blockchain has been tampered with!")
	}
}
