// Package certs reads, checks and creates certificates and keys, and knows where their files live.
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
	"fmt"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

type KeyType string

const (
	ECDSAP256 KeyType = "ecdsaP256"
	RSA2048   KeyType = "rsa2048"
)

// ParseKeyType accepts the stored names; empty means ECDSA P-256.
func ParseKeyType(value string) (KeyType, error) {
	switch KeyType(value) {
	case "", ECDSAP256:
		return ECDSAP256, nil
	case RSA2048:
		return RSA2048, nil
	default:
		return "", fmt.Errorf("unknown key type %q", value)
	}
}

// Names are what a domain's certificate covers: the domain, and its www name when the redirect uses it.
// Wildcard subdomains are never included (Let's Encrypt needs DNS validation for those).
func Names(domain site.Domain) []string {
	names := []string{domain.Name}
	if domain.Redirect == site.FromWWW || domain.Redirect == site.ToWWW {
		names = append(names, "www."+domain.Name)
	}

	return names
}

// Parsed is a validated certificate: the leaf first in Fullchain, the key as PKCS#8.
type Parsed struct {
	Leaf      *x509.Certificate
	Fullchain []byte
	Key       []byte
}

// Covers reports a clear error when the certificate doesn't cover one of names.
func (p Parsed) Covers(names []string) error {
	for _, name := range names {
		if err := p.Leaf.VerifyHostname(name); err != nil {
			return invalidError("certificate", "The certificate doesn't cover %s.", name)
		}
	}

	return nil
}

func invalidError(field, format string, args ...any) error {
	return &site.InvalidError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

func normalise(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

// ParseBundle checks an uploaded certificate (with its chain, in any order) against its private key.
func ParseBundle(certificatePEM, chainPEM, keyPEM []byte, now time.Time) (Parsed, error) {
	var certificates []*x509.Certificate

	rest := normalise(append(append(append([]byte{}, certificatePEM...), '\n'), chainPEM...))
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return Parsed{}, invalidError("certificate", "One of the certificates can't be read: %v.", err)
		}

		duplicate := false
		for _, seen := range certificates {
			duplicate = duplicate || seen.Equal(certificate)
		}
		if !duplicate {
			certificates = append(certificates, certificate)
		}
	}

	if len(certificates) == 0 {
		return Parsed{}, invalidError("certificate", "No certificate was found. Paste it in PEM format, starting with -----BEGIN CERTIFICATE-----.")
	}

	key, err := ParseKey(keyPEM)
	if err != nil {
		return Parsed{}, err
	}

	leaf := -1
	for i, certificate := range certificates {
		if public, ok := certificate.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok && public.Equal(key.Public()) {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		return Parsed{}, invalidError("privateKey", "The private key doesn't match the certificate.")
	}

	certificate := certificates[leaf]
	if now.Before(certificate.NotBefore) {
		return Parsed{}, invalidError("certificate", "The certificate isn't valid until %s.", certificate.NotBefore.UTC().Format("2 January 2006"))
	}
	if now.After(certificate.NotAfter) {
		return Parsed{}, invalidError("certificate", "The certificate expired on %s.", certificate.NotAfter.UTC().Format("2 January 2006"))
	}

	var fullchain bytes.Buffer
	pem.Encode(&fullchain, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	for i, other := range certificates {
		if i != leaf {
			pem.Encode(&fullchain, &pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})
		}
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Parsed{}, invalidError("privateKey", "The private key can't be stored: %v.", err)
	}

	return Parsed{Leaf: certificate, Fullchain: fullchain.Bytes(), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}, nil
}

// ParseKey reads a PKCS#8, PKCS#1 (RSA) or SEC1 (EC) private key. Encrypted keys are refused.
func ParseKey(keyPEM []byte) (crypto.Signer, error) {
	rest := normalise(keyPEM)

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			return nil, invalidError("privateKey", "The private key is encrypted. Remove its passphrase (for example with openssl pkey) and paste it again.")
		}

		var key any
		var err error

		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, invalidError("privateKey", "The private key can't be read: %v.", err)
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, invalidError("privateKey", "This kind of private key isn't supported.")
		}

		return signer, nil
	}

	return nil, invalidError("privateKey", "No private key was found. Paste it in PEM format, starting with -----BEGIN PRIVATE KEY-----.")
}

// GenerateKey returns a new key and its PKCS#8 PEM.
func GenerateKey(keyType KeyType) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	var err error

	if keyType == RSA2048 {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}

	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CreateCSR returns a PEM certificate signing request for names, the first being the common name.
func CreateCSR(key crypto.Signer, names []string) ([]byte, error) {
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create signing request: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Leaf returns the first certificate of a PEM bundle.
func Leaf(fullchainPEM []byte) (*x509.Certificate, error) {
	rest := normalise(fullchainPEM)

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no certificate in the bundle")
		}
		rest = remaining

		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// IssuerName is how the app shows who issued a certificate, e.g. "Let's Encrypt R11".
func IssuerName(certificate *x509.Certificate) string {
	issuer := certificate.Issuer
	switch {
	case len(issuer.Organization) > 0 && issuer.CommonName != "":
		return issuer.Organization[0] + " " + issuer.CommonName
	case issuer.CommonName != "":
		return issuer.CommonName
	case len(issuer.Organization) > 0:
		return issuer.Organization[0]
	default:
		return "Unknown issuer"
	}
}
