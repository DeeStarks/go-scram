package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const (
	IterationCount = 4096
)

type User struct {
	Iters   int
	Salt    string
	StoredK []byte
	ServerK []byte
}

var users = make(map[string]User)

// ServerCreateAccount function creates an identity for the user
// by specifying the user's username and plaintext password and
// storing the user's salt, iteration count, stored key, and server key
func ServerCreateAccount(username, password string) {
	salt, err := generateNonce()
	if err != nil {
		panic(err)
	}

	// calculate SaltedPassword using PBKDF2
	saltedPassword := hi(password, salt, IterationCount)

	clientKey := hmacSha256(saltedPassword, []byte("Client Key"))
	// the key idea of the StoredKey is that it can be used to verify a
	// ClientKey without having to store the ClientKey itself
	storedKey := sha256.Sum256(clientKey)
	// the serverKey is used by the server to prove its identity to the client
	serverKey := hmacSha256(saltedPassword, []byte("Server Key"))

	// the server stores the following:
	// 	- an iteration count for key derivation(i)
	// 	- a per-user randomly generated salt to be used during key derivation(salt)
	// 	- the StoredKey, used by the server to verify the client’s identity
	// 	- the ServerKey, used by the server to prove its identity to the client.
	users[username] = User{
		Iters:   IterationCount,
		Salt:    salt,
		StoredK: storedKey[:],
		ServerK: serverKey,
	}
}

// ServerInitiateAuthentication function initiates the SCRAM authentication process
// by sending a "Server First" message to the client which includes the
// user's salt, iteration count, and combined nonce
func ServerInitiateAuthentication(username, clientNonce string) (string, int, string, error) {
	user, ok := users[username]
	if !ok {
		return "", 0, "", errors.New("user not found")
	}

	serverNonce, err := generateNonce()
	if err != nil {
		return "", 0, "", err
	}

	combinedNonce := clientNonce + serverNonce
	return user.Salt, user.Iters, combinedNonce, nil
}

// serverVerifyClientProof function verifies the client's proof by
// calculating the ClientSignature based on the stored key and
// exclusive-ORing the client proof and the calculated client signature
// to recover the ClientKey and then verifying the correctness of the
// client key by applying the hash function and comparing the result
// to the stored key
func serverVerifyClientProof(username, combinedNonce string, clientProof []byte) bool {
	user := users[username]

	// calculating the ClientSignature based on the stored key
	authMessage := "r=" + combinedNonce
	clientSignature := hmacSha256(user.StoredK, []byte(authMessage))

	// exclusive-ORing to recover the ClientKey
	clientKey, err := xor(clientProof, clientSignature)
	if err != nil {
		return false
	}

	// verifing the correctness of the client key
	storedKey := sha256.Sum256(clientKey)
	return hmac.Equal(storedKey[:], user.StoredK)
}

// serverGenerateServerSignature function generates the server's signature
func serverGenerateServerSignature(username, combinedNonce string) string {
	user := users[username]

	authMessage := "r=" + combinedNonce
	serverSignature := hmacSha256(user.ServerK, []byte(authMessage))

	return base64.StdEncoding.EncodeToString(serverSignature)
}

// ServerCompleteAuthentication function verifies the client's proof
// and sends a "Server Final" message to the client which includes
// the server's signature
func ServerCompleteAuthentication(username, clientProof, combinedNonce string) (string, error) {
	clientProofBytes, _ := base64.StdEncoding.DecodeString(clientProof)

	// verify the client's proof
	if !serverVerifyClientProof(username, combinedNonce, clientProofBytes) {
		return "", errors.New("client proof verification failed")
	}

	signature := serverGenerateServerSignature(username, combinedNonce)

	return signature, nil
}
