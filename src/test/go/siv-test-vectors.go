package main

import "crypto/rand"
import "fmt"
import "encoding/hex"
import "math/big"
import "os"

import "github.com/jacobsa/crypto/siv"

func main() {
	printTestCases()
}

// Generate a variety of test cases based on a Go implementation of AES-SIV.
// Output these test cases to STDOUT in a simple text format so that
// implementations in other languages can use them for functional testing.
func printTestCases() {
	keyLengths := []int{
		32, 48, 64,
	}
	plaintextLengths := []int{
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		32, 41, 58, 67,127,128,129,500,
	}
	adLengths := []int{
		0, 1, 2, 3, 4, 8, 36, 63, 126,
	}

	// Try to generate all possible edge case combinations
	for _, keyLength := range keyLengths {
		for _, isKeyZeros := range []bool{false, true} {
			for _, plaintextLength := range plaintextLengths {
				for _, isPlaintextZeros := range []bool{false, true} {
					for _, adLength := range adLengths {
						for _, areAdElemsEmpty := range []bool{false, true} {
							key := make([]byte, keyLength)
							if !isKeyZeros {
								// Set key to random bytes
								rand.Read(key)
							}

							plaintext := make([]byte, plaintextLength)
							if !isPlaintextZeros {
								// Set plaintext to random bytes
								rand.Read(plaintext)
							}

							ad := make([][]byte, adLength)
							for adIdx := range ad {
								if areAdElemsEmpty {
									ad[adIdx] = make([]byte, 0)
								} else {
									randomLen, err := rand.Int(rand.Reader, big.NewInt(128))
									if err != nil {
										fmt.Println("rand.Int failed")
										os.Exit(7)
									}
									ad[adIdx] = make([]byte, randomLen.Int64() + 1)
								}

								// Fill with random bytes
								rand.Read(ad[adIdx])
							}

							printTestCase(key, plaintext, ad)
						}
					}
				}
			}
		}
	}
}

// Print a single test case to STDOUT.
func printTestCase(key []byte, plaintext []byte, associatedData [][]byte) {
	// CTR mode encryption key
	fmt.Printf("%s;", hex.EncodeToString(key[len(key)/2:]))

	// MAC (authentication) key
	fmt.Printf("%s;", hex.EncodeToString(key[:len(key)/2]))

	// Plaintext
	fmt.Printf("%s;", hex.EncodeToString(plaintext))

	// Additional associated data
	fmt.Printf("%v;", len(associatedData))
	for _, adElem := range associatedData {
		fmt.Printf("%s;", hex.EncodeToString(adElem))
	}

	// Ciphertext
	ciphertext, err := siv.Encrypt(nil, key, plaintext, associatedData)
	if err != nil {
		fmt.Println("encrypt failed: ", err)
		os.Exit(7)
	}
	fmt.Println(hex.EncodeToString(ciphertext));
}
