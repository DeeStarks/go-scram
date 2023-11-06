# SCRAM (Salted Challenge Response Authentication Mechanism) Implementation in Go

This repository contains a simple Go implementation of SCRAM, a secure authentication protocol, demonstrating the server and client sides of the authentication process. SCRAM is designed to provide strong security and protection against common authentication vulnerabilities.

SCRAM is a widely used authentication mechanism that employs a combination of cryptographic functions and secure practices to protect user credentials during authentication. It enhances security by using a user-specific salt, iteration count, and cryptographic functions to ensure the confidentiality and integrity of authentication data.

## Server Implementation

> To create an identity on the server, an administrator creates a user account, specifying the username and plaintext password. The server first applies the key derivation function to compute the SaltedPassword.
> 
> ```py
> SaltedPassword = KeyDerive(password, salt, i)
> ClientKey = HMAC(SaltedPassword, "Client Key")
> StoredKey = H(ClientKey)
> ServerKey = HMAC(SaltedPassword, "Server Key")
> ```
> - **password**: is the plaintext password for the user.
> - **Hash(str)**: a cryptographic hash function
> - **HMAC(str, key)**: hash-based message authentication code
> - **KeyDerive(str, salt, i)**: a key derivation function
> - **i**: iteration count, a higher i value increases the cost of a brute-force attack, but also increases the time required for a user to authenticate to the server.
> - **salt**: A per-user randomly generated salt to be used during key derivation.
> The **StoredKey** is a cryptographic digest of the ClientKey. The StoredKey is used by the server to verify the client’s identity.
>
> *Cited from [Kafka authentication using SASL/SCRAM](https://medium.com/@hussein.joe.au/kafka-authentication-using-sasl-scram-740e55da1fbc)*

The server-side implementation includes the following key functionalities:

- User account creation with a randomly generated salt and secure password hashing.
- Sending a "Server First" message to initiate the authentication process, including the user's salt, iteration count, and combined nonce.
- Verification of the client's proof and generation of the server's signature.
- Sending a "Server Final" message that includes the server's signature.

## Client Implementation
The client-side implementation includes the following key functionalities:

- Initiation of the authentication process by sending an authentication request to the server.
- Calculation of the client proof and verification of the server's proof.
- Secure handling of user credentials and secure password hashing.


## References:
- [RFC 5802](https://tools.ietf.org/html/rfc5802)
- [Kafka authentication using SASL/SCRAM](https://medium.com/@hussein.joe.au/kafka-authentication-using-sasl-scram-740e55da1fbc)
