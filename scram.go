package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

// generateNonce generates a random 16-byte nonce
func generateNonce() string {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(nonce)
}

// hmacSha256 function calculates the HMAC of a message
func hmacSha256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// xor function performs a bitwise XOR of two byte slices
func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("XOR input lengths are not equal")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// hi function computes SaltedPassword using PBKDF2
func hi(password, salt string, iterationCount int) []byte {
	normalizedPassword := []byte(password)
	saltedPassword := pbkdf2.Key(normalizedPassword, []byte(salt), iterationCount, sha256.Size, sha256.New)
	return saltedPassword
}
