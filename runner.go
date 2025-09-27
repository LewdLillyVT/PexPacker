package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type PexVersion int
type PayloadType int

type PexFileV8 struct {
	Version              PexVersion
	Filename             string
	PayloadType          PayloadType
	ObfuscatedData       []byte
	EncryptedSortMap     []byte
	IntegrityHash        []byte
	OriginalSize         int
	CompressedSize       int
	SortSalt             uint64
	MapKeySalt           []byte
	EncryptedExpiration  []byte
	TimeKeySalt          []byte
}

const (
	Executable PayloadType = iota
	Library
)

const (
	V1 PexVersion = iota
	V2
	V3
	V4
	V5
	V6
	V7
	V8
)

func xor(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func decompress(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return ioutil.ReadAll(reader)
}

func verifyIntegrity(data, expectedHash []byte) bool {
	hasher := sha256.New()
	hasher.Write(data)
	return bytes.Equal(hasher.Sum(nil), expectedHash)
}

func runPexFile(filePath string) error {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var pex PexFileV8
	if err := json.Unmarshal(fileData, &pex); err != nil {
		return err
	}

	fmt.Printf("Running PEX V8 File: %s\n", pex.Filename)
	fmt.Printf("Original Size: %d bytes\n", pex.OriginalSize)
	fmt.Printf("Compressed Size: %d bytes\n", pex.CompressedSize)

	key := []byte("pex_v8_key")
	compressedData := xor(pex.ObfuscatedData, key)

	fmt.Println("Decompressing data...")
	originalData, err := decompress(compressedData)
	if err != nil {
		return err
	}

	fmt.Println("Verifying integrity...")
	if !verifyIntegrity(originalData, pex.IntegrityHash) {
		return fmt.Errorf("integrity verification failed")
	}

	fmt.Println("✓ Integrity verified")
	outputPath := filepath.Join(os.TempDir(), pex.Filename)
	if err := ioutil.WriteFile(outputPath, originalData, 0755); err != nil {
		return err
	}

	fmt.Printf("Unpacked file saved to: %s\n", outputPath)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: runner <pex-file>")
		return
	}
	filePath := os.Args[1]
	if err := runPexFile(filePath); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}