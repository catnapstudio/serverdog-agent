package databases

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// scramIterations and scramSaltSize are PostgreSQL's defaults (scram_iterations, SCRAM_DEFAULT_SALT_LEN).
const (
	scramIterations = 4096
	scramSaltSize   = 16
)

// scramVerifier returns the SCRAM-SHA-256 secret PostgreSQL stores for password, with a random salt. CREATE ROLE stores
// a value in this format as it is, so the plaintext never reaches the server or its log. Validate allows only letters
// and digits in a password, so SASLprep leaves it unchanged.
func scramVerifier(password string) (string, error) {
	salt := make([]byte, scramSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("make a salt: %w", err)
	}

	return scramSecret(password, salt, scramIterations)
}

// scramSecret builds "SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>" like PostgreSQL's scram_build_secret
// (RFC 5802 and RFC 7677).
func scramSecret(password string, salt []byte, iterations int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("derive the salted password: %w", err)
	}

	storedKey := sha256.Sum256(scramHMAC(salted, "Client Key"))
	serverKey := scramHMAC(salted, "Server Key")
	encode := base64.StdEncoding.EncodeToString

	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, encode(salt), encode(storedKey[:]), encode(serverKey)), nil
}

func scramHMAC(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))

	return mac.Sum(nil)
}
