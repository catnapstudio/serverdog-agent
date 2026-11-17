package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

var now = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type issued struct {
	cert *x509.Certificate
	pem  []byte
	key  crypto.Signer
}

// issue makes a certificate for names signed by parent (self-signed when parent is nil).
func issue(t *testing.T, key crypto.Signer, names []string, notBefore, notAfter time.Time, parent *issued, isCA bool) issued {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	signerCert, signerKey := template, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	return issued{cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key}
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func invalid(t *testing.T, err error, contains string) {
	t.Helper()

	var problem *site.InvalidError
	if !errors.As(err, &problem) || !strings.Contains(problem.Reason, contains) {
		t.Errorf("err = %v, want an InvalidError mentioning %q", err, contains)
	}
}

func TestNames(t *testing.T) {
	cases := map[site.Redirect][]string{
		site.FromWWW:    {"orchard.com", "www.orchard.com"},
		site.ToWWW:      {"orchard.com", "www.orchard.com"},
		site.NoRedirect: {"orchard.com"},
	}

	for redirect, want := range cases {
		if got := Names(site.Domain{Name: "orchard.com", Redirect: redirect, Wildcards: true}); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", redirect, got, want)
		}
	}
}

func TestParseBundleNormalisesChainOrderAndKey(t *testing.T) {
	caKey := ecKey(t)
	ca := issue(t, caKey, []string{"Test CA"}, now.Add(-time.Hour), now.Add(time.Hour*24*365), nil, true)
	leafKey := rsaKey(t)
	leaf := issue(t, leafKey, []string{"orchard.com", "www.orchard.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), &ca, false)

	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})

	// The chain comes first, then the leaf: people paste them in any order.
	parsed, err := ParseBundle(append(append([]byte{}, ca.pem...), leaf.pem...), nil, pkcs1, now)
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.Leaf.Equal(leaf.cert) {
		t.Error("wrong leaf")
	}
	if !bytes.HasPrefix(parsed.Fullchain, leaf.pem) || !bytes.Contains(parsed.Fullchain, ca.pem) {
		t.Errorf("fullchain isn't leaf-first:\n%s", parsed.Fullchain)
	}
	if !bytes.HasPrefix(parsed.Key, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Errorf("key isn't PKCS#8:\n%s", parsed.Key)
	}
	if err := parsed.Covers([]string{"orchard.com", "www.orchard.com"}); err != nil {
		t.Error(err)
	}
}

func TestParseBundleAcceptsCRLFAndSEC1Keys(t *testing.T) {
	key := ecKey(t)
	leaf := issue(t, key, []string{"orchard.com"}, now.Add(-time.Hour), now.Add(time.Hour*24), nil, false)
	der, _ := x509.MarshalECPrivateKey(key)
	sec1 := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	crlf := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }

	if _, err := ParseBundle(crlf(leaf.pem), nil, crlf(sec1), now); err != nil {
		t.Fatal(err)
	}
}

func TestParseBundleRejects(t *testing.T) {
	key := ecKey(t)
	leaf := issue(t, key, []string{"orchard.com"}, now.Add(-time.Hour), now.Add(time.Hour*24), nil, false)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	otherDER, _ := x509.MarshalPKCS8PrivateKey(ecKey(t))
	otherKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER})

	expired := issue(t, key, []string{"orchard.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour), nil, false)
	future := issue(t, key, []string{"orchard.com"}, now.Add(24*time.Hour), now.Add(48*time.Hour), nil, false)
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})

	cases := []struct {
		name          string
		cert, key     []byte
		wantSubstring string
	}{
		{"mismatched key", leaf.pem, otherKey, "doesn't match"},
		{"expired", expired.pem, keyPEM, "expired"},
		{"not yet valid", future.pem, keyPEM, "isn't valid until"},
		{"encrypted key", leaf.pem, encrypted, "encrypted"},
		{"no certificate", []byte("hello"), keyPEM, "No certificate"},
		{"no key", leaf.pem, []byte("hello"), "No private key"},
	}

	for _, c := range cases {
		_, err := ParseBundle(c.cert, nil, c.key, now)
		t.Run(c.name, func(t *testing.T) { invalid(t, err, c.wantSubstring) })
	}
}

func TestCoversNamesTheMissingOne(t *testing.T) {
	key := ecKey(t)
	leaf := issue(t, key, []string{"orchard.com"}, now.Add(-time.Hour), now.Add(time.Hour*24), nil, false)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)

	parsed, err := ParseBundle(leaf.pem, nil, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), now)
	if err != nil {
		t.Fatal(err)
	}

	invalid(t, parsed.Covers([]string{"orchard.com", "www.orchard.com"}), "www.orchard.com")

	wildcard := issue(t, key, []string{"*.orchard.com"}, now.Add(-time.Hour), now.Add(time.Hour*24), nil, false)
	parsed, _ = ParseBundle(wildcard.pem, nil, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), now)
	if err := parsed.Covers([]string{"www.orchard.com"}); err != nil {
		t.Errorf("wildcard doesn't cover www: %v", err)
	}
}

func TestCSRMatchesItsKey(t *testing.T) {
	for _, keyType := range []KeyType{ECDSAP256, RSA2048} {
		key, keyPEM, err := GenerateKey(keyType)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(keyPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
			t.Errorf("%s key PEM = %s", keyType, keyPEM)
		}

		csrPEM, err := CreateCSR(key, []string{"orchard.com", "www.orchard.com"})
		if err != nil {
			t.Fatal(err)
		}

		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Fatalf("csr: %v", err)
		}
		if !slices.Equal(csr.DNSNames, []string{"orchard.com", "www.orchard.com"}) || csr.Subject.CommonName != "orchard.com" {
			t.Errorf("csr names = %v %q", csr.DNSNames, csr.Subject.CommonName)
		}
		if !csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
			t.Error("csr isn't for the key")
		}
	}

	if _, err := ParseKeyType("ed448"); err == nil {
		t.Error("unknown key type accepted")
	}
	if kt, _ := ParseKeyType(""); kt != ECDSAP256 {
		t.Errorf("default key type = %s", kt)
	}
}
