package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Please provide two command line arguments.")
		os.Exit(1)
	}

	// Parse the command line argument
	k, success := new(big.Int).SetString(os.Args[1], 10)
	if !success {
		fmt.Println("Error parsing first argument:", os.Args[1])
		os.Exit(1)
	}

	// Initialize the elliptic curve
	curve := elliptic.P256()

	// Perform the sclar multiplication
	x1, y1 := curve.ScalarBaseMult(k.Bytes())

	// Convert the byte slices to hexadecimal strings
	y1Hex := hexutil.Encode(padBytes(y1.Bytes(), 32))
	x1Hex := hexutil.Encode(padBytes(x1.Bytes(), 32))

	// Concatenate the hexadecimal strings and remove the '0x' prefix from the second string
	result := x1Hex + y1Hex[2:]

	fmt.Println(result)
}

func padBytes(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}

	padding := make([]byte, length-len(b))
	return append(padding, b...)
}
