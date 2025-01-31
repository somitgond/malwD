// module defining functions related to file scanning

package main

import (
	"os"
	"log"
	"io"
	"fmt"
	"crypto/sha256"
)


func scan_file(file_path string) {
	file, err := os.Open(file_path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("SHA-256 checksum: %x\n", hash.Sum(nil))
}
