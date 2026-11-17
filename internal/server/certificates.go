package server

import (
	"context"
	"fmt"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/certificates"
	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/databases"
	"github.com/catnapstudio/serverdog-agent/internal/domains"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type domainService struct {
	agentv1.UnimplementedDomainServiceServer
	*Services
}

func (s domainService) CheckDns(ctx context.Context, request *agentv1.CheckDnsRequest) (*agentv1.CheckDnsResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}

	stored, err := s.Store.GetSite(request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.CheckDnsResponse{}
	for _, domain := range stored.Domains {
		if request.Domain != "" && domain.Name != request.Domain {
			continue
		}
		response.Domains = append(response.Domains, toDomainDns(s.Domains.Check(ctx, domain)))
	}

	if request.Domain != "" && len(response.Domains) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "%s isn't one of this site's domains.", text(request.Domain))
	}

	return response, nil
}

func toDomainDns(checked domains.Status) *agentv1.DomainDns {
	d := &agentv1.DomainDns{Domain: checked.Domain, Reachable: checked.Reachable}

	for _, record := range checked.Records {
		d.Records = append(d.Records, &agentv1.DnsRecord{Type: record.Type, Name: record.Name, Value: record.Value})
	}
	for _, name := range checked.Names {
		d.Names = append(d.Names, &agentv1.DnsName{Name: name.Name, Answers: name.Answers, PointsHere: name.PointsHere, ReachesHere: name.ReachesHere})
	}

	return d
}

type certificateService struct {
	agentv1.UnimplementedCertificateServiceServer
	*Services
}

var (
	certificateSources = map[string]agentv1.CertificateSource{
		state.CertLetsEncrypt:    agentv1.CertificateSource_CERTIFICATE_SOURCE_LETS_ENCRYPT,
		state.CertSigningRequest: agentv1.CertificateSource_CERTIFICATE_SOURCE_SIGNING_REQUEST,
		state.CertUploaded:       agentv1.CertificateSource_CERTIFICATE_SOURCE_UPLOADED,
		state.CertCloned:         agentv1.CertificateSource_CERTIFICATE_SOURCE_CLONED,
	}
	certificateStates = map[string]agentv1.CertificateState{
		state.CertWaitingForDNS:       agentv1.CertificateState_CERTIFICATE_STATE_WAITING_FOR_DNS,
		state.CertIssuing:             agentv1.CertificateState_CERTIFICATE_STATE_ISSUING,
		state.CertIssued:              agentv1.CertificateState_CERTIFICATE_STATE_ISSUED,
		state.CertRenewalFailing:      agentv1.CertificateState_CERTIFICATE_STATE_RENEWAL_FAILING,
		state.CertFailed:              agentv1.CertificateState_CERTIFICATE_STATE_FAILED,
		state.CertAwaitingCertificate: agentv1.CertificateState_CERTIFICATE_STATE_AWAITING_CERTIFICATE,
	}
	keyTypes = map[string]agentv1.KeyType{
		string(certs.ECDSAP256): agentv1.KeyType_KEY_TYPE_ECDSA_P256,
		string(certs.RSA2048):   agentv1.KeyType_KEY_TYPE_RSA_2048,
	}
)

func toCertificate(c state.Certificate) *agentv1.Certificate {
	return &agentv1.Certificate{
		Id:           c.ID,
		SiteId:       c.SiteID,
		Domain:       c.Domain,
		Source:       certificateSources[c.Source],
		State:        certificateStates[c.Status],
		Active:       c.Active,
		Names:        c.Names,
		KeyType:      keyTypes[c.KeyType],
		Issuer:       text(c.Issuer),
		NotBefore:    timestamp(c.NotBefore),
		NotAfter:     timestamp(c.NotAfter),
		Error:        text(c.Error),
		NextAttempt:  timestamp(c.NextAttempt),
		WaitingSince: timestamp(c.WaitingSince),
	}
}

func keyTypeFrom(keyType agentv1.KeyType) (certs.KeyType, error) {
	switch keyType {
	case agentv1.KeyType_KEY_TYPE_UNSPECIFIED, agentv1.KeyType_KEY_TYPE_ECDSA_P256:
		return certs.ECDSAP256, nil
	case agentv1.KeyType_KEY_TYPE_RSA_2048:
		return certs.RSA2048, nil
	default:
		return "", status.Error(codes.InvalidArgument, "That key type isn't supported. Use ECDSA P-256 or RSA 2048.")
	}
}

func (s certificateService) ListCertificates(ctx context.Context, request *agentv1.ListCertificatesRequest) (*agentv1.ListCertificatesResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}
	if _, err := s.Store.GetSite(request.SiteId); err != nil {
		return nil, toStatus(err)
	}

	list, err := s.Store.ListCertificates(request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListCertificatesResponse{}
	for _, c := range list {
		response.Certificates = append(response.Certificates, toCertificate(c))
	}

	return response, nil
}

func (s certificateService) RequestLetsEncrypt(ctx context.Context, request *agentv1.RequestLetsEncryptRequest) (*agentv1.RequestLetsEncryptResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}
	keyType, err := keyTypeFrom(request.KeyType)
	if err != nil {
		return nil, err
	}

	c, err := s.Certificates.RequestLetsEncrypt(ctx, request.SiteId, request.Domain, keyType, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.RequestLetsEncryptResponse{Certificate: toCertificate(c)}, nil
}

func (s certificateService) CreateSigningRequest(ctx context.Context, request *agentv1.CreateSigningRequestRequest) (*agentv1.CreateSigningRequestResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}
	keyType, err := keyTypeFrom(request.KeyType)
	if err != nil {
		return nil, err
	}

	c, csr, err := s.Certificates.CreateSigningRequest(ctx, request.SiteId, request.Domain, keyType, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.CreateSigningRequestResponse{Certificate: toCertificate(c), Csr: string(csr)}, nil
}

func (s certificateService) InstallCertificate(ctx context.Context, request *agentv1.InstallCertificateRequest) (*agentv1.InstallCertificateResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}
	if request.CertificateId != "" {
		if err := checkID(request.CertificateId); err != nil {
			return nil, err
		}
	}

	upload := certificates.Upload{Certificate: []byte(request.Certificate), Chain: []byte(request.Chain), PrivateKey: []byte(request.PrivateKey)}
	c, err := s.Certificates.Install(ctx, request.SiteId, request.Domain, request.CertificateId, upload, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.InstallCertificateResponse{Certificate: toCertificate(c)}, nil
}

func (s certificateService) CloneCertificate(ctx context.Context, request *agentv1.CloneCertificateRequest) (*agentv1.CloneCertificateResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}
	if err := checkID(request.FromCertificateId); err != nil {
		return nil, err
	}

	c, err := s.Certificates.Clone(ctx, request.SiteId, request.Domain, request.FromCertificateId, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.CloneCertificateResponse{Certificate: toCertificate(c)}, nil
}

func (s certificateService) ActivateCertificate(ctx context.Context, request *agentv1.ActivateCertificateRequest) (*agentv1.ActivateCertificateResponse, error) {
	if err := checkID(request.CertificateId); err != nil {
		return nil, err
	}

	c, err := s.Certificates.Activate(ctx, request.CertificateId, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.ActivateCertificateResponse{Certificate: toCertificate(c)}, nil
}

func (s certificateService) DeleteCertificate(ctx context.Context, request *agentv1.DeleteCertificateRequest) (*agentv1.DeleteCertificateResponse, error) {
	if err := checkID(request.CertificateId); err != nil {
		return nil, err
	}

	if err := s.Certificates.Delete(ctx, request.CertificateId, request.Actor); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.DeleteCertificateResponse{}, nil
}

type databaseService struct {
	agentv1.UnimplementedDatabaseServiceServer
	*Services
}

func (s databaseService) CreateDatabase(ctx context.Context, request *agentv1.CreateDatabaseRequest) (*agentv1.CreateDatabaseResponse, error) {
	environmentFile := ""

	if request.SiteId != "" || request.WriteEnv {
		if err := checkID(request.SiteId); err != nil {
			return nil, err
		}

		stored, err := s.Store.GetSite(request.SiteId)
		if err != nil {
			return nil, toStatus(err)
		}
		if request.WriteEnv && stored.EnvironmentFile == "" {
			return nil, status.Error(codes.InvalidArgument, "This site has no environment file to write the database settings to.")
		}
		environmentFile = stored.EnvironmentFile
	}

	if request.WriteEnv {
		if err := s.Sites.CheckEnvWritable(ctx, request.SiteId); err != nil {
			return nil, toStatus(err)
		}
	}

	result, err := s.Databases.Create(ctx, databases.Request{Name: request.Name, User: request.User, Password: request.Password, From: request.AllowedFrom})
	if err != nil {
		return nil, toStatus(err)
	}

	if request.SiteId != "" {
		kind, summary := "database.created", fmt.Sprintf("Created the database %s and its user %s.", result.Name, result.User)
		if result.Existing {
			kind, summary = "database.confirmed", fmt.Sprintf("Confirmed the database %s and its user %s.", result.Name, result.User)
		}

		s.Store.AddActivity(request.SiteId, state.Activity{At: s.Sites.Now(), Kind: kind, Actor: request.Actor, Summary: summary})
	}

	if request.WriteEnv {
		summary := fmt.Sprintf("Set the database settings in %s.", environmentFile)
		if err := s.Sites.MergeEnv(ctx, request.SiteId, databases.EnvValues(result, request.Password), summary, request.Actor); err != nil {
			return nil, status.Error(codes.Internal, "The database was created, but writing the environment file failed.\n\n"+text(err.Error()))
		}
	}

	return &agentv1.CreateDatabaseResponse{Engine: result.Engine, Name: result.Name, User: result.User, Host: result.Host, Port: uint32(result.Port)}, nil
}
