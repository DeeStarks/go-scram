package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func ClientAuthentication(username, password string) error {
	clientNonce, err := generateNonce()
	if err != nil {
		return err
	}

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
	clientProofB, err := xor(clientKey, clientSignature)
	if err != nil {
		return err
	}
	clientProof := base64.StdEncoding.EncodeToString(clientProofB)

	// send the client proof to the server to get he server's signature
	expectedServerSig, err := ServerCompleteAuthentication(username, clientProof, combinedNonce)
	if err != nil {
		return err // returns an error if the server proof verification fails
	}

	// verify the server's signature
	serverSignature := hmacSha256(serverKey, []byte(authMessage))

	if expectedServerSig != base64.StdEncoding.EncodeToString(serverSignature) {
		return errors.New("verification failed")
	}

	return nil
}
