package main

import (
    "crypto/elliptic"
    "fmt"
    "math/big"
    "os"
		"github.com/ethereum/go-ethereum/common/hexutil"
)

func main() {
    if len(os.Args) != 5 {
        fmt.Println("Please provide two command line arguments.")
        os.Exit(1)
    }

    // Parse the command line arguments
    x1, success := new(big.Int).SetString(os.Args[1], 10)
    if !success {
        fmt.Println("Error parsing first argument:", os.Args[1])
        os.Exit(1)
    }

    y1, success := new(big.Int).SetString(os.Args[2], 10)
    if !success {
        fmt.Println("Error parsing second argument:", os.Args[2])
        os.Exit(1)
    }

    x2, success := new(big.Int).SetString(os.Args[3], 10)
    if !success {
        fmt.Println("Error parsing second argument:", os.Args[2])
        os.Exit(1)
    }


    y2, success := new(big.Int).SetString(os.Args[4], 10)
    if !success {
        fmt.Println("Error parsing second argument:", os.Args[2])
        os.Exit(1)
    }


    // Initialize the elliptic curve
    curve := elliptic.P256()

    // Check if the points are on the curve
    if (!curve.IsOnCurve(x1, y1) || !curve.IsOnCurve(x1, y1)) {
        fmt.Println("The points are not on the curve.")
        os.Exit(1)
    }

    // Add the two points
    x3, y3 := curve.Add(x1, y1, x2, y2)

    // Convert the byte slices to hexadecimal strings
    x3Hex := hexutil.Encode(padBytes(x3.Bytes(), 32))
    y3Hex := hexutil.Encode(padBytes(y3.Bytes(), 32))

    // Concatenate the hexadecimal strings and remove the '0x' prefix from the second string
    result := x3Hex + y3Hex[2:]

    fmt.Println(result)
}

func padBytes(b []byte, length int) []byte {
	if len(b) >= length {
			return b
	}

	padding := make([]byte, length-len(b))
	return append(padding, b...)
}