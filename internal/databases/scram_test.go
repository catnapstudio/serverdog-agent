package databases

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

// The exchange in RFC 7677 §3: user "user", password "pencil".
const (
	rfcSalt        = "W22ZaJ0SNY7soEsUEjb6gQ=="
	rfcAuthMessage = "n=user,r=rOprNGfwEbeRWgbNEkqO," +
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," +
		"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	rfcClientProof     = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
	rfcServerSignature = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
)

func decode(t *testing.T, s string) []byte {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func hmacSHA256(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))

	return mac.Sum(nil)
}

func TestScramSecretMatchesRFC7677(t *testing.T) {
	secret, err := scramSecret("pencil", decode(t, rfcSalt), 4096)
	if err != nil {
		t.Fatal(err)
	}

	head, keys, ok := strings.Cut(secret, "$4096:"+rfcSalt+"$")
	if !ok || head != "SCRAM-SHA-256" {
		t.Fatalf("secret = %q", secret)
	}
	storedText, serverText, ok := strings.Cut(keys, ":")
	if !ok {
		t.Fatalf("secret = %q", secret)
	}
	storedKey, serverKey := decode(t, storedText), decode(t, serverText)

	// The server checks a proof by recovering ClientKey from it and hashing that into StoredKey (RFC 5802 §3).
	signature := hmacSHA256(storedKey, rfcAuthMessage)
	clientKey := decode(t, rfcClientProof)
	for i := range clientKey {
		clientKey[i] ^= signature[i]
	}
	if sum := sha256.Sum256(clientKey); !hmac.Equal(sum[:], storedKey) {
		t.Error("the RFC's client proof doesn't match StoredKey")
	}

	if got := base64.StdEncoding.EncodeToString(hmacSHA256(serverKey, rfcAuthMessage)); got != rfcServerSignature {
		t.Errorf("server signature = %s, want %s", got, rfcServerSignature)
	}
}

func TestScramVerifierUsesARandomSaltAndPostgresFormat(t *testing.T) {
	format := regexp.MustCompile(`^SCRAM-SHA-256\$4096:[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$`)

	first, err := scramVerifier(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := scramVerifier(password)
	if err != nil {
		t.Fatal(err)
	}

	if !format.MatchString(first) || !format.MatchString(second) {
		t.Errorf("verifiers = %q, %q", first, second)
	}
	if first == second {
		t.Error("two verifiers share a salt")
	}
	if strings.Contains(first, password) {
		t.Error("the verifier holds the password")
	}
}
