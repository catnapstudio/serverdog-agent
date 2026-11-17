// Package acmeclient gets and renews certificates from an ACME server (Let's Encrypt) with lego v5.
package acmeclient

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/http/webroot"
	"github.com/go-acme/lego/v5/registration"
)

type Issued struct {
	Fullchain  []byte
	PrivateKey []byte
	Leaf       *x509.Certificate
}

type Client interface {
	Obtain(ctx context.Context, names []string, keyType certs.KeyType) (Issued, error)
	// RenewalTime is when leaf should be renewed. The zero time means "not yet, ask again in 12 hours".
	RenewalTime(ctx context.Context, leaf *x509.Certificate, now time.Time) (time.Time, error)
}

// Lego talks to the ACME server at Directory with one account per server and directory, validating with HTTP-01 files in Webroot.
type Lego struct {
	Directory  string
	CABundle   string
	AccountDir string
	Webroot    string

	mu     sync.Mutex
	client *lego.Client
}

type account struct {
	key          crypto.Signer
	registration *acme.ExtendedAccount
}

func (a *account) GetEmail() string                       { return "" }
func (a *account) GetRegistration() *acme.ExtendedAccount { return a.registration }
func (a *account) GetPrivateKey() crypto.Signer           { return a.key }

func (l *Lego) Obtain(ctx context.Context, names []string, keyType certs.KeyType) (Issued, error) {
	client, err := l.acmeClient(ctx)
	if err != nil {
		return Issued{}, err
	}

	kind := certcrypto.EC256
	if keyType == certs.RSA2048 {
		kind = certcrypto.RSA2048
	}

	resource, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{Domains: names, KeyType: kind, Bundle: true})
	if err != nil {
		return Issued{}, err
	}

	leaf, err := certs.Leaf(resource.Certificate)
	if err != nil {
		return Issued{}, fmt.Errorf("read the issued certificate: %w", err)
	}

	return Issued{Fullchain: resource.Certificate, PrivateKey: resource.PrivateKey, Leaf: leaf}, nil
}

func (l *Lego) RenewalTime(ctx context.Context, leaf *x509.Certificate, now time.Time) (time.Time, error) {
	client, err := l.acmeClient(ctx)
	if err != nil {
		return Fallback(leaf), err
	}

	info, err := client.Certificate.GetRenewalInfo(ctx, leaf)
	if errors.Is(err, api.ErrNoARI) {
		return Fallback(leaf), nil
	}
	if err != nil {
		return Fallback(leaf), err
	}

	at := info.ShouldRenewAt(now, 12*time.Hour)
	if at == nil {
		return time.Time{}, nil
	}

	return *at, nil
}

// Fallback renews when a third of the certificate's lifetime remains.
func Fallback(leaf *x509.Certificate) time.Time {
	return leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
}

func (l *Lego) acmeClient(ctx context.Context) (*lego.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.client != nil {
		return l.client, nil
	}

	key, err := l.accountKey()
	if err != nil {
		return nil, err
	}

	user := &account{key: key}
	config := lego.NewConfig(user)
	config.CADirURL = l.Directory

	if l.CABundle != "" {
		pool, err := lego.CreateCertPool([]string{l.CABundle}, true)
		if err != nil {
			return nil, fmt.Errorf("read the ACME CA bundle: %w", err)
		}
		config.HTTPClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool}},
		}
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	provider, err := webroot.NewHTTPProvider(l.Webroot)
	if err != nil {
		return nil, fmt.Errorf("use the ACME webroot: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("use the ACME webroot: %w", err)
	}

	// Only an account the server doesn't know is registered. Any other error (an outage, a timeout) is returned and the
	// next request looks it up again; registering then would leave the server's real account unused.
	existing, err := client.Registration.ResolveAccountByKey(ctx)
	switch {
	case accountMissing(err):
		if existing, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
			return nil, fmt.Errorf("register with the ACME server: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("look up the ACME account: %w", err)
	}
	user.registration = existing

	l.client = client

	return client, nil
}

func accountMissing(err error) bool {
	var problem *acme.ProblemDetails

	return errors.As(err, &problem) && problem.Type == acme.AccountDoesNotExistErrorType
}

// accountKey loads or creates the server's account key for this directory (0600 in a 0700 directory).
func (l *Lego) accountKey() (crypto.Signer, error) {
	sum := sha256.Sum256([]byte(l.Directory))
	dir := filepath.Join(l.AccountDir, hex.EncodeToString(sum[:])[:16])
	file := filepath.Join(dir, "key.pem")

	data, err := os.ReadFile(file)
	if err == nil {
		return certs.ParseKey(data)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read the ACME account key: %w", err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the ACME account directory: %w", err)
	}

	key, keyPEM, err := certs.GenerateKey(certs.ECDSAP256)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(file, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write the ACME account key: %w", err)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		return nil, err
	}

	return key, nil
}
