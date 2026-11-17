package certs

import (
	"path"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

// Files are a certificate's files. They live in a root-owned directory, so root writes them (through apply).
func Files(p paths.Paths, siteID, certID string, fullchain, key []byte) []apply.File {
	return []apply.File{
		{Path: FullchainFile(p, siteID, certID), Content: fullchain, Mode: 0o600},
		{Path: KeyFile(p, siteID, certID), Content: key, Mode: 0o600},
	}
}

func FullchainFile(p paths.Paths, siteID, certID string) string {
	return p.File(path.Join(paths.CertificateDir(siteID, certID), "fullchain.pem"))
}

func KeyFile(p paths.Paths, siteID, certID string) string {
	return p.File(path.Join(paths.CertificateDir(siteID, certID), "privkey.pem"))
}

func RequestFile(p paths.Paths, siteID, certID string) string {
	return p.File(path.Join(paths.CertificateDir(siteID, certID), "request.csr"))
}

// ActiveLink points the domain's active link at certID (relative, so it stays valid under any root).
func ActiveLink(p paths.Paths, siteID, domain, certID string) apply.File {
	return apply.File{Path: p.File(paths.ActiveCertificateDir(siteID, domain)), Link: "../" + certID}
}

func RemoveActiveLink(p paths.Paths, siteID, domain string) apply.File {
	return apply.File{Path: p.File(paths.ActiveCertificateDir(siteID, domain)), Remove: true}
}

// Nginx is the domain's certificate as Nginx configs reference it: through the active link, so activating
// another certificate or renewing never changes the config.
func Nginx(siteID, domain string) nginx.Certificate {
	dir := paths.ActiveCertificateDir(siteID, domain)

	return nginx.Certificate{Fullchain: path.Join(dir, "fullchain.pem"), Key: path.Join(dir, "privkey.pem")}
}
