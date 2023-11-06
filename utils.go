package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// generateNonce generates a random 16-byte nonce
func generateNonce() (string, error) {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}

// hmacSha256 function calculates the HMAC of a message
func hmacSha256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// xor function performs a bitwise XOR of two byte slices
func xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("unequal length")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

// hi function computes SaltedPassword using PBKDF2
func hi(password, salt string, iterationCount int) []byte {
	normalizedPassword := []byte(password)
	saltedPassword := pbkdf2.Key(normalizedPassword, []byte(salt), iterationCount, sha256.Size, sha256.New)
	return saltedPassword
}
