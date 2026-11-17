//go:build vmtest

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func certificatesClient() agentv1.CertificateServiceClient {
	return agentv1.NewCertificateServiceClient(conn)
}

func domainsClient() agentv1.DomainServiceClient {
	return agentv1.NewDomainServiceClient(conn)
}

func databasesClient() agentv1.DatabaseServiceClient {
	return agentv1.NewDatabaseServiceClient(conn)
}

// resolveHere points names at this VM in /etc/hosts, as DNS would for a real domain. The agent and Pebble both read it.
func resolveHere(t *testing.T, names ...string) {
	t.Helper()

	original, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.WriteFile("/etc/hosts", original, 0o644) })

	line := "\n127.0.0.1 " + strings.Join(names, " ") + "\n"
	if err := os.WriteFile("/etc/hosts", append(original, line...), 0o644); err != nil {
		t.Fatal(err)
	}
}

// waitForCertificate waits until the domain has an active issued certificate.
func waitForCertificate(t *testing.T, siteID, domain string) *agentv1.Certificate {
	t.Helper()

	var last *agentv1.Certificate
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		list, err := certificatesClient().ListCertificates(timeout(t), &agentv1.ListCertificatesRequest{SiteId: siteID})
		if err != nil {
			t.Fatal(err)
		}

		for _, c := range list.Certificates {
			if c.Domain != domain {
				continue
			}
			last = c
			if c.Active && c.State == agentv1.CertificateState_CERTIFICATE_STATE_ISSUED {
				return c
			}
			if c.State == agentv1.CertificateState_CERTIFICATE_STATE_FAILED {
				t.Fatalf("the certificate failed: %s", c.Error)
			}
		}
	}

	t.Fatalf("no certificate for %s; last seen: %v", domain, last)
	return nil
}

// getTLS requests https://name/ from this VM with name as SNI, returning the response and the certificate served.
// The issuer is Pebble's per-run root or a test CA, so the tests check names and issuers themselves.
func getTLS(name string) (int, string, http.Header, *x509.Certificate, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: name, InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:443")
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport:     transport,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	response, err := client.Get("https://" + name + "/")
	if err != nil {
		return 0, "", nil, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	return response.StatusCode, strings.TrimSpace(string(body)), response.Header, response.TLS.PeerCertificates[0], err
}

func expectRootOnly(t *testing.T, file string) {
	t.Helper()

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Errorf("%s: mode %v, uid %d", file, info.Mode(), info.Sys().(*syscall.Stat_t).Uid)
	}

	if dir, err := os.Stat("/etc/serverdog/certs"); err != nil || dir.Mode().Perm() != 0o700 {
		t.Errorf("/etc/serverdog/certs: %v %v", dir, err)
	}
}

func TestLetsEncryptCertificateIsIssuedAndServed(t *testing.T) {
	resolveHere(t, "secure.test", "www.secure.test")
	r := newRepo(t, map[string]string{"index.html": "secure\n"})
	s := createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "secure.test", r.URL))
	mustDeploy(t, s.Id)

	dns, err := domainsClient().CheckDns(timeout(t), &agentv1.CheckDnsRequest{SiteId: s.Id})
	if err != nil || len(dns.Domains) != 1 || !dns.Domains[0].Reachable {
		t.Errorf("CheckDns = %v %v", dns, err)
	}

	c := waitForCertificate(t, s.Id, "secure.test")
	if c.Source != agentv1.CertificateSource_CERTIFICATE_SOURCE_LETS_ENCRYPT || strings.Join(c.Names, " ") != "secure.test www.secure.test" || !strings.Contains(c.Issuer, "Pebble") {
		t.Errorf("certificate = %v", c)
	}
	expectRootOnly(t, "/etc/serverdog/certs/"+s.Id+"/"+c.Id+"/privkey.pem")

	code, body, _, leaf, err := getTLS("secure.test")
	if err != nil || code != 200 || body != "secure" {
		t.Fatalf("https://secure.test = %d %q %v", code, body, err)
	}
	if leaf.VerifyHostname("www.secure.test") != nil || !strings.Contains(leaf.Issuer.CommonName, "Pebble") {
		t.Errorf("served %v from %v", leaf.DNSNames, leaf.Issuer)
	}

	code, _, header, _, err := getTLS("www.secure.test")
	if err != nil || code != 301 || header.Get("Location") != "https://secure.test/" {
		t.Errorf("https://www.secure.test = %d %v %v", code, header, err)
	}

	s.ForceHttps, s.Hsts = true, true
	if _, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, ExpectedRevision: s.Revision, Actor: actor}); err != nil {
		t.Fatal(err)
	}

	code, _, header, err = get("secure.test")
	if err != nil || code != 301 || header.Get("Location") != "https://secure.test/" {
		t.Errorf("Force HTTPS: http://secure.test = %d %v %v", code, header, err)
	}
	if _, _, header, _, err := getTLS("secure.test"); err != nil || header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Errorf("HSTS = %v %v", header, err)
	}
}

// .invalid never resolves, whereas a developer's Mac often answers *.test with 127.0.0.1 and the VM's resolver passes that on.
func TestACertificateWaitsForDNS(t *testing.T) {
	domain := "nodns" + ids.New() + ".invalid"
	r := newRepo(t, map[string]string{"index.html": "waiting\n"})
	s := createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", domain, r.URL))

	var c *agentv1.Certificate
	for deadline := time.Now().Add(30 * time.Second); c == nil; time.Sleep(500 * time.Millisecond) {
		list, err := certificatesClient().ListCertificates(timeout(t), &agentv1.ListCertificatesRequest{SiteId: s.Id})
		if err != nil {
			t.Fatal(err)
		}
		if len(list.Certificates) == 1 && list.Certificates[0].Error != "" {
			c = list.Certificates[0]
		}
		if c == nil && time.Now().After(deadline) {
			t.Fatalf("DNS was never checked: %v", list.Certificates)
		}
	}

	if c.State != agentv1.CertificateState_CERTIFICATE_STATE_WAITING_FOR_DNS || !strings.Contains(c.Error, "doesn't resolve") || c.NextAttempt == "" || c.WaitingSince == "" {
		t.Errorf("certificate = %v", c)
	}

	again, err := certificatesClient().RequestLetsEncrypt(timeout(t), &agentv1.RequestLetsEncryptRequest{SiteId: s.Id, Domain: domain, Actor: actor})
	if err != nil || again.Certificate.Id != c.Id {
		t.Errorf("Request Now = %v %v", again, err)
	}

	dns, err := domainsClient().CheckDns(timeout(t), &agentv1.CheckDnsRequest{SiteId: s.Id, Domain: domain})
	if err != nil || dns.Domains[0].Reachable || len(dns.Domains[0].Names[0].Answers) != 0 {
		t.Errorf("CheckDns = %v %v", dns, err)
	}

	if logs := sh(t, "/", "journalctl", "-u", "serverdog-pebble", "--no-pager"); strings.Contains(logs, domain) {
		t.Error("Pebble was asked about a domain that doesn't resolve")
	}
}

func TestSigningRequestUploadActivateAndClone(t *testing.T) {
	ctx := timeout(t)
	certificates := certificatesClient()

	r := newRepo(t, map[string]string{"index.html": "upload\n"})
	s := createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "upload.test", r.URL))
	mustDeploy(t, s.Id)

	request, err := certificates.CreateSigningRequest(ctx, &agentv1.CreateSigningRequestRequest{SiteId: s.Id, Domain: "upload.test", KeyType: agentv1.KeyType_KEY_TYPE_RSA_2048, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	expectRootOnly(t, "/etc/serverdog/certs/"+s.Id+"/"+request.Certificate.Id+"/privkey.pem")

	leafPEM, caPEM := signCSR(t, request.Csr)
	installed, err := certificates.InstallCertificate(ctx, &agentv1.InstallCertificateRequest{
		SiteId: s.Id, Domain: "upload.test", CertificateId: request.Certificate.Id, Certificate: leafPEM, Chain: caPEM, Actor: actor,
	})
	if err != nil || !installed.Certificate.Active {
		t.Fatalf("InstallCertificate = %v %v", installed, err)
	}
	if code, body, _, leaf, err := getTLS("upload.test"); err != nil || code != 200 || body != "upload" || leaf.Issuer.CommonName != "ServerDog VM Test CA" {
		t.Errorf("signed certificate: %d %q %v %v", code, body, leaf, err)
	}

	certificatePEM, keyPEM, serial := selfSigned(t, "upload.test", "www.upload.test", "clone.test")
	uploaded, err := certificates.InstallCertificate(ctx, &agentv1.InstallCertificateRequest{
		SiteId: s.Id, Domain: "upload.test", Certificate: certificatePEM, PrivateKey: keyPEM, Actor: actor,
	})
	if err != nil || uploaded.Certificate.Active {
		t.Fatalf("a second certificate = %v %v", uploaded, err)
	}

	if _, err := certificates.ActivateCertificate(ctx, &agentv1.ActivateCertificateRequest{CertificateId: uploaded.Certificate.Id, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, leaf, err := getTLS("upload.test"); err != nil || leaf.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("after activating: %v %v", leaf, err)
	}

	r2 := newRepo(t, map[string]string{"index.html": "clone\n"})
	spec := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "clone.test", r2.URL)
	spec.Domains[0].Redirect = agentv1.Redirect_REDIRECT_NONE
	other := createSite(t, spec)
	mustDeploy(t, other.Id)

	clone, err := certificates.CloneCertificate(ctx, &agentv1.CloneCertificateRequest{SiteId: other.Id, Domain: "clone.test", FromCertificateId: uploaded.Certificate.Id, Actor: actor})
	if err != nil || !clone.Certificate.Active || clone.Certificate.Source != agentv1.CertificateSource_CERTIFICATE_SOURCE_CLONED {
		t.Fatalf("CloneCertificate = %v %v", clone, err)
	}

	if _, err := sitesClient().DeleteSite(ctx, &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/etc/serverdog/certs/" + s.Id); !os.IsNotExist(err) {
		t.Errorf("the deleted site's certificates are still there: %v", err)
	}
	if code, body, _, leaf, err := getTLS("clone.test"); err != nil || code != 200 || body != "clone" || leaf.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("the clone after deleting its source: %d %q %v", code, body, err)
	}
}

func selfSigned(t *testing.T, names ...string) (certificatePEM, keyPEM string, serial *big.Int) {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ = rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), serial
}

// signCSR signs a PEM certificate request with a throwaway "ServerDog VM Test CA".
func signCSR(t *testing.T, csrPEM string) (leafPEM, caPEM string) {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ServerDog VM Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	block, _ := pem.Decode([]byte(csrPEM))
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: request.Subject, DNSNames: request.DNSNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}, ca, request.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

// query runs statement as user over TCP, the way the site would.
func query(engine, database, user, password, statement string) error {
	var cmd *exec.Cmd
	if engine == "postgres" {
		cmd = exec.Command("psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-U", user, "-d", database, "-c", statement)
		cmd.Env = append(os.Environ(), "PGPASSWORD="+password)
	} else {
		cmd = exec.Command("mariadb", "-h", "127.0.0.1", "-u", user, database, "-e", statement)
		cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, output)
	}

	return nil
}

func dropDatabase(engine, name, user string) {
	if engine == "postgres" {
		exec.Command("runuser", "-u", "postgres", "--", "psql", "-X", "-c", `DROP DATABASE IF EXISTS "`+name+`"`, "-c", `DROP ROLE IF EXISTS "`+user+`"`).Run()
		return
	}

	command := rootSQL(engine, fmt.Sprintf("DROP DATABASE IF EXISTS `%[1]s`; DROP USER IF EXISTS '%[2]s'@'localhost', '%[2]s'@'127.0.0.1';", name, user))
	exec.Command(command[0], command[1:]...).Run()
}

func TestDatabaseForASite(t *testing.T) {
	ctx := timeout(t)
	r := newRepo(t, map[string]string{"index.html": "db\n"})
	spec := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "db.test", r.URL)
	spec.EnvironmentFile = ".env"
	s := createSite(t, spec)

	name, user, password := "db_"+ids.New(), "u_"+ids.New(), ids.New()+ids.New()
	request := &agentv1.CreateDatabaseRequest{SiteId: s.Id, Name: name, User: user, Password: password, WriteEnv: true, Actor: actor}

	created, err := databasesClient().CreateDatabase(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropDatabase(created.Engine, name, user) })

	wantEngine := map[bool]string{true: "mariadb", false: "postgres"}[strings.Contains(sh(t, "/", "cat", "/etc/os-release"), `VERSION_ID="24.04"`)]
	if created.Engine != wantEngine || created.Host != "127.0.0.1" {
		t.Errorf("created = %v, want engine %s", created, wantEngine)
	}

	if err := query(created.Engine, name, user, password, "CREATE TABLE visits (id integer)"); err != nil {
		t.Errorf("the site's user can't use its database: %v", err)
	}

	otherName, otherUser, otherPassword := "db_"+ids.New(), "u_"+ids.New(), ids.New()+ids.New()
	if _, err := databasesClient().CreateDatabase(ctx, &agentv1.CreateDatabaseRequest{Name: otherName, User: otherUser, Password: otherPassword, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropDatabase(created.Engine, otherName, otherUser) })

	if err := query(created.Engine, otherName, user, password, "SELECT 1"); err == nil {
		t.Error("the site's user can reach another database")
	}

	lookalike, lookalikeUser := strings.Replace(name, "db_", "dbx", 1), "u_"+ids.New()
	if _, err := databasesClient().CreateDatabase(ctx, &agentv1.CreateDatabaseRequest{Name: lookalike, User: lookalikeUser, Password: otherPassword, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropDatabase(created.Engine, lookalike, lookalikeUser) })

	if err := query(created.Engine, lookalike, user, password, "SELECT 1"); err == nil {
		t.Error("the site's user can reach a database whose name matches its own with _ as a wildcard")
	}

	env, err := configClient().GetEnv(ctx, &agentv1.GetEnvRequest{SiteId: s.Id})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"DB_HOST=127.0.0.1", "DB_DATABASE=" + name, "DB_USERNAME=" + user, "DB_PASSWORD=" + password} {
		if !strings.Contains(env.Content, line+"\n") {
			t.Errorf(".env lacks %s", line)
		}
	}

	again, err := databasesClient().CreateDatabase(ctx, request)
	if err != nil || again.Name != name || again.User != user {
		t.Errorf("creating it again with its password: %v %v", again, err)
	}
	activity, err := sitesClient().ListActivity(ctx, &agentv1.ListActivityRequest{SiteId: s.Id, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	confirmed := false
	for _, entry := range activity.Entries {
		confirmed = confirmed || (entry.Kind == "database.confirmed" && entry.Summary == "Confirmed the database "+name+" and its user "+user+".")
	}
	if !confirmed {
		t.Errorf("activity = %v", activity.Entries)
	}

	other := &agentv1.CreateDatabaseRequest{SiteId: s.Id, Name: name, User: user, Password: ids.New() + ids.New(), WriteEnv: true, Actor: actor}
	if _, err := databasesClient().CreateDatabase(ctx, other); status.Code(err) != codes.AlreadyExists {
		t.Errorf("creating it again with another password: %v", err)
	}

	journal := sh(t, "/", "journalctl", "-u", "serverdog-agent", "--no-pager")
	if strings.Contains(journal, password) || strings.Contains(journal, "PRIVATE KEY") {
		t.Error("the agent's journal holds a secret")
	}
}
