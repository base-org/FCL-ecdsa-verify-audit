package main

import (
    "fmt"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/json"
    "os"
    "github.com/ethereum/go-ethereum/common/hexutil"
)

type KeyPair struct {
    D string `json:"d"`
    X string `json:"x"`
    Y string `json:"y"`
}

type KeyPairs struct {
    Data []KeyPair `json:"data"`
}

func main() {
    var keyPairs []KeyPair

    for i := 0; i < 1000; i++ {
        privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {
            fmt.Println("Error generating key:", err)
            return
        }

        p := "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

        k := KeyPair{
            D: hexutil.Encode(padBytes(privateKey.D.Bytes(), 32)),
            X: hexutil.Encode(padBytes(privateKey.PublicKey.X.Bytes(), 32)),
            Y: hexutil.Encode(padBytes(privateKey.PublicKey.Y.Bytes(), 32)),
        };

        keyPairs = append(keyPairs, k)
    }

    file, err := os.Create("keys.json")
    if err != nil {
        fmt.Println("Error creating file:", err)
        return
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    if err := encoder.Encode(KeyPairs{Data: keyPairs}); err != nil {
        fmt.Println("Error encoding JSON:", err)
        return
    }
}

func padBytes(b []byte, length int) []byte {
    if len(b) >= length {
        return b
    }

    padding := make([]byte, length-len(b))
    return append(padding, b...)
}