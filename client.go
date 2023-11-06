package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func ClientAuthentication(username, password string) error {
	clientNonce := generateNonce()

	// send the authentication request to the server to begin the SCRAM process
	salt, iterationCount, combinedNonce, err := ServerInitiateAuthentication(username, clientNonce)
	if err != nil {
		return err // returns an error if the user does not exist
	}

	// calculate SaltedPassword using PBKDF2
	saltedPassword := hi(password, salt, iterationCount)

	clientKey := hmacSha256(saltedPassword, []byte("Client Key"))
	serverKey := hmacSha256(saltedPassword, []byte("Server Key"))
	storedKey := sha256.Sum256(clientKey)
	authMessage := "r=" + combinedNonce

	clientSignature := hmacSha256(storedKey[:], []byte(authMessage))

	// XORing the ClientKey with the ClientSignature will produce the ClientProof
	clientProof := base64.StdEncoding.EncodeToString(xor(clientKey, clientSignature))

	// send the client proof to the server to get he server's signature
	expectedServerSig, err := ServerCompleteAuthentication(username, clientProof, combinedNonce)
	if err != nil {
		return err // returns an error if the server proof verification fails
	}

	// verify the server's proof
	serverProof := hmacSha256(serverKey, []byte(authMessage))

	if expectedServerSig != base64.StdEncoding.EncodeToString(serverProof) {
		return errors.New("server proof verification failed")
	}

	return nil
}
