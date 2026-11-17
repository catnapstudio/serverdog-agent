package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/databases"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func putOrchard(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()

	_, err := agentv1.NewSiteServiceClient(conn).PutSite(context.Background(), &agentv1.PutSiteRequest{Actor: "Mac", Site: &agentv1.Site{
		Id: "abcdefghijkl", Preset: "laravel", Runtime: agentv1.Runtime_RUNTIME_PHP,
		Domains:       []*agentv1.Domain{{Name: "orchard.com", Redirect: agentv1.Redirect_REDIRECT_FROM_WWW, Primary: true}},
		RepositoryUrl: "git@github.com:morgan/orchard.git", Branch: "main", PhpVersion: "8.4", WebDirectory: "public",
		EnvironmentFile: ".env", DeployScript: "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n", ZeroDowntime: true, User: "serverdog",
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func selfSignedPEM(t *testing.T, names ...string) (certificatePEM, keyPEM string) {
	t.Helper()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
}

func TestCertificateServicesEndToEnd(t *testing.T) {
	conn, _ := startServices(t)
	putOrchard(t, conn)
	client := agentv1.NewCertificateServiceClient(conn)
	ctx := context.Background()

	list, err := client.ListCertificates(ctx, &agentv1.ListCertificatesRequest{SiteId: "abcdefghijkl"})
	if err != nil || len(list.Certificates) != 1 {
		t.Fatalf("ListCertificates = %v %v", list, err)
	}
	waiting := list.Certificates[0]
	if waiting.Source != agentv1.CertificateSource_CERTIFICATE_SOURCE_LETS_ENCRYPT || waiting.State != agentv1.CertificateState_CERTIFICATE_STATE_WAITING_FOR_DNS ||
		waiting.KeyType != agentv1.KeyType_KEY_TYPE_ECDSA_P256 || strings.Join(waiting.Names, " ") != "orchard.com www.orchard.com" || waiting.NextAttempt == "" {
		t.Errorf("waiting = %v", waiting)
	}

	request, err := client.CreateSigningRequest(ctx, &agentv1.CreateSigningRequestRequest{SiteId: "abcdefghijkl", Domain: "orchard.com", KeyType: agentv1.KeyType_KEY_TYPE_RSA_2048, Actor: "Mac"})
	if err != nil || !strings.HasPrefix(request.Csr, "-----BEGIN CERTIFICATE REQUEST-----") || request.Certificate.State != agentv1.CertificateState_CERTIFICATE_STATE_AWAITING_CERTIFICATE {
		t.Fatalf("CreateSigningRequest = %v %v", request, err)
	}

	certificatePEM, keyPEM := selfSignedPEM(t, "orchard.com", "www.orchard.com")
	installed, err := client.InstallCertificate(ctx, &agentv1.InstallCertificateRequest{SiteId: "abcdefghijkl", Domain: "orchard.com", Certificate: certificatePEM, PrivateKey: keyPEM, Actor: "Mac"})
	if err != nil {
		t.Fatal(err)
	}
	c := installed.Certificate
	if c.Source != agentv1.CertificateSource_CERTIFICATE_SOURCE_UPLOADED || c.State != agentv1.CertificateState_CERTIFICATE_STATE_ISSUED || !c.Active || c.NotAfter == "" || c.Issuer != "orchard.com" {
		t.Errorf("installed = %v", c)
	}

	if _, err := client.ActivateCertificate(ctx, &agentv1.ActivateCertificateRequest{CertificateId: "nonexistentx", Actor: "Mac"}); status.Code(err) != codes.NotFound {
		t.Errorf("Activate missing: %v", err)
	}
	if _, err := client.ActivateCertificate(ctx, &agentv1.ActivateCertificateRequest{CertificateId: waiting.Id, Actor: "Mac"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("Activate waiting: %v", err)
	}

	if _, err := client.DeleteCertificate(ctx, &agentv1.DeleteCertificateRequest{CertificateId: c.Id, Actor: "Mac"}); err != nil {
		t.Fatal(err)
	}
	list, _ = client.ListCertificates(ctx, &agentv1.ListCertificatesRequest{SiteId: "abcdefghijkl"})
	if len(list.Certificates) != 2 {
		t.Errorf("after delete: %v", list.Certificates)
	}
}

func TestInstallCertificateExplainsAMismatchedKey(t *testing.T) {
	conn, _ := startServices(t)
	putOrchard(t, conn)
	certificatePEM, _ := selfSignedPEM(t, "orchard.com", "www.orchard.com")
	_, otherKey := selfSignedPEM(t, "orchard.com")

	_, err := agentv1.NewCertificateServiceClient(conn).InstallCertificate(context.Background(), &agentv1.InstallCertificateRequest{
		SiteId: "abcdefghijkl", Domain: "orchard.com", Certificate: certificatePEM, PrivateKey: otherKey, Actor: "Mac",
	})

	if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "The private key doesn't match the certificate." {
		t.Errorf("err = %v", err)
	}
}

func TestCertificateRequestsCheckIDsAndKeyTypes(t *testing.T) {
	conn, _ := startServices(t)
	client := agentv1.NewCertificateServiceClient(conn)
	ctx := context.Background()

	if _, err := client.ListCertificates(ctx, &agentv1.ListCertificatesRequest{SiteId: "../../etc"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad id: %v", err)
	}
	if _, err := client.ListCertificates(ctx, &agentv1.ListCertificatesRequest{SiteId: "abcdefghijkl"}); status.Code(err) != codes.NotFound {
		t.Errorf("missing site: %v", err)
	}
	if _, err := client.RequestLetsEncrypt(ctx, &agentv1.RequestLetsEncryptRequest{SiteId: "abcdefghijkl", Domain: "orchard.com", KeyType: agentv1.KeyType(99)}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad key type: %v", err)
	}
}

func TestCheckDnsReportsRecordsAndAnswers(t *testing.T) {
	conn, _ := startServices(t)
	putOrchard(t, conn)
	client := agentv1.NewDomainServiceClient(conn)

	response, err := client.CheckDns(context.Background(), &agentv1.CheckDnsRequest{SiteId: "abcdefghijkl"})
	if err != nil || len(response.Domains) != 1 {
		t.Fatalf("CheckDns = %v %v", response, err)
	}

	d := response.Domains[0]
	if d.Domain != "orchard.com" || d.Reachable || len(d.Records) != 2 || d.Records[0].Type != "A" || d.Records[0].Value != "203.0.113.10" {
		t.Errorf("domain = %v", d)
	}
	if len(d.Names) != 2 || !d.Names[0].PointsHere || d.Names[1].PointsHere || strings.Join(d.Names[1].Answers, ",") != "198.51.100.7" {
		t.Errorf("names = %v", d.Names)
	}
	if !d.Names[0].ReachesHere || d.Names[1].ReachesHere {
		t.Errorf("reaches here = %v, %v", d.Names[0].ReachesHere, d.Names[1].ReachesHere)
	}

	if _, err := client.CheckDns(context.Background(), &agentv1.CheckDnsRequest{SiteId: "abcdefghijkl", Domain: "other.com"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown domain: %v", err)
	}
}

func TestCreateDatabaseWritesTheEnvironmentFile(t *testing.T) {
	conn, services := startServices(t)
	putOrchard(t, conn)

	counts := "0\n0\n"
	runner := &systemtest.Fake{}
	runner.Handle("mariadb", func(c system.Command) (system.Result, error) {
		script, _ := io.ReadAll(c.Stdin)
		if strings.Contains(string(script), "SELECT") {
			return system.Result{Output: []byte(counts)}, nil
		}
		return system.Result{}, nil
	})
	services.Databases = databases.Creator{Runner: runner, Engine: func(context.Context) string { return "mariadb" }}

	client := agentv1.NewDatabaseServiceClient(conn)
	ctx := context.Background()
	request := &agentv1.CreateDatabaseRequest{SiteId: "abcdefghijkl", Name: "orchard", User: "orchard", Password: "Zr8kQ2mVx7LpT4nWb9Ys", WriteEnv: true, Actor: "Mac"}

	response, err := client.CreateDatabase(ctx, request)
	if err != nil || response.Engine != "mariadb" || response.Port != 3306 || response.Host != "127.0.0.1" {
		t.Fatalf("CreateDatabase = %v %v", response, err)
	}

	env, _ := agentv1.NewConfigServiceClient(conn).GetEnv(ctx, &agentv1.GetEnvRequest{SiteId: "abcdefghijkl"})
	want := "DB_CONNECTION=mariadb\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=orchard\nDB_USERNAME=orchard\nDB_PASSWORD=Zr8kQ2mVx7LpT4nWb9Ys\n"
	if env.GetContent() != want {
		t.Errorf("env = %q", env.GetContent())
	}

	counts = "1\n0\n"
	if _, err := client.CreateDatabase(ctx, request); status.Code(err) != codes.AlreadyExists {
		t.Errorf("a database without its user: %v", err)
	}

	request.Password = "short"
	if _, err := client.CreateDatabase(ctx, request); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad password: %v", err)
	}
}

func TestCreateDatabaseConfirmsAnExistingDatabaseItsPasswordLogsInTo(t *testing.T) {
	conn, services := startServices(t)
	putOrchard(t, conn)

	const password = "Zr8kQ2mVx7LpT4nWb9Ys"
	runner := &systemtest.Fake{}
	runner.Handle("mariadb", func(c system.Command) (system.Result, error) {
		if c.Stdin != nil {
			return system.Result{Output: []byte("1\n2\n")}, nil
		}

		file := strings.TrimPrefix(c.Args[0], "--defaults-file=")
		if content, _ := os.ReadFile(file); !strings.Contains(string(content), "password="+password+"\n") {
			return system.Result{Output: []byte("ERROR 1045 (28000): Access denied for user 'orchard'@'localhost'"), ExitCode: 1}, &system.ExitError{Command: "mariadb", ExitCode: 1}
		}

		return system.Result{Output: []byte("1\n")}, nil
	})
	services.Databases = databases.Creator{Runner: runner, Engine: func(context.Context) string { return "mariadb" }, LoginDir: t.TempDir()}

	client := agentv1.NewDatabaseServiceClient(conn)
	ctx := context.Background()
	request := &agentv1.CreateDatabaseRequest{SiteId: "abcdefghijkl", Name: "orchard", User: "orchard", Password: password, WriteEnv: true, Actor: "Mac"}

	response, err := client.CreateDatabase(ctx, request)
	if err != nil || response.Engine != "mariadb" || response.Name != "orchard" || response.Port != 3306 {
		t.Fatalf("CreateDatabase = %v %v", response, err)
	}

	env, _ := agentv1.NewConfigServiceClient(conn).GetEnv(ctx, &agentv1.GetEnvRequest{SiteId: "abcdefghijkl"})
	if !strings.Contains(env.GetContent(), "DB_PASSWORD="+password+"\n") {
		t.Errorf("env = %q", env.GetContent())
	}

	activity, _ := services.Store.ListActivity("abcdefghijkl", 2)
	if len(activity) != 2 || activity[1].Kind != "database.confirmed" || activity[1].Summary != "Confirmed the database orchard and its user orchard." || activity[0].Kind != "env.changed" {
		t.Errorf("activity = %+v", activity)
	}

	request.Password = "Other7Password8Here9"
	if _, err := client.CreateDatabase(ctx, request); status.Code(err) != codes.AlreadyExists {
		t.Errorf("another password: %v", err)
	}
}

func TestCreateDatabaseChecksTheEnvironmentFileFirst(t *testing.T) {
	conn, services := startServices(t)
	putOrchard(t, conn)

	runner := &systemtest.Fake{}
	services.Databases = databases.Creator{Runner: runner, Engine: func(context.Context) string { return "mariadb" }}

	stored, err := services.Store.GetSite("abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(services.Paths.File(path.Join(stored.Directory, "shared", ".env"))); err != nil {
		t.Fatal(err)
	}

	request := &agentv1.CreateDatabaseRequest{SiteId: "abcdefghijkl", Name: "orchard", User: "orchard", Password: "Zr8kQ2mVx7LpT4nWb9Ys", WriteEnv: true, Actor: "Mac"}
	_, err = agentv1.NewDatabaseServiceClient(conn).CreateDatabase(context.Background(), request)

	if status.Code(err) != codes.InvalidArgument || !strings.Contains(status.Convert(err).Message(), ".env is missing") {
		t.Errorf("err = %v", err)
	}
	if calls := runner.Calls(); len(calls) != 0 {
		t.Errorf("ran %v before checking the environment file", runner.Commands())
	}
}
