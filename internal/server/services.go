package server

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/backups"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/certificates"
	"github.com/catnapstudio/serverdog-agent/internal/credentials"
	"github.com/catnapstudio/serverdog-agent/internal/daemons"
	"github.com/catnapstudio/serverdog-agent/internal/databases"
	"github.com/catnapstudio/serverdog-agent/internal/deploy"
	"github.com/catnapstudio/serverdog-agent/internal/domains"
	"github.com/catnapstudio/serverdog-agent/internal/firewall"
	"github.com/catnapstudio/serverdog-agent/internal/frankenphp"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/insights"
	"github.com/catnapstudio/serverdog-agent/internal/jobs"
	"github.com/catnapstudio/serverdog-agent/internal/logs"
	"github.com/catnapstudio/serverdog-agent/internal/meilisearch"
	"github.com/catnapstudio/serverdog-agent/internal/metrics"
	"github.com/catnapstudio/serverdog-agent/internal/network"
	"github.com/catnapstudio/serverdog-agent/internal/notify"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/phpsettings"
	"github.com/catnapstudio/serverdog-agent/internal/phpversions"
	"github.com/catnapstudio/serverdog-agent/internal/serversettings"
	"github.com/catnapstudio/serverdog-agent/internal/servicectl"
	"github.com/catnapstudio/serverdog-agent/internal/sites"
	"github.com/catnapstudio/serverdog-agent/internal/sshkeys"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/tools"
	"github.com/catnapstudio/serverdog-agent/internal/updates"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Services implements the protocol 2 services.
type Services struct {
	Store          *state.Store
	Paths          paths.Paths
	Sites          *sites.Manager
	Deploys        *deploy.Manager
	Watcher        deploy.Watcher
	Tester         gitsource.Tester
	Capabilities   func(context.Context) capabilities.Capabilities
	Domains        domains.Checker
	Certificates   *certificates.Manager
	Databases      databases.Creator
	Jobs           *jobs.Manager
	Daemons        *daemons.Manager
	PHPSettings    *phpsettings.Manager
	Credentials    *credentials.Manager
	Metrics        *metrics.Recorder
	Settings       *serversettings.Manager
	SystemServices *servicectl.Manager
	Notifications  *notify.Manager
	Logs           *logs.Reader
	Firewall       *firewall.Manager
	SSHKeys        *sshkeys.Manager
	PHP            *phpversions.Manager
	Backups        *backups.Manager
	BackupRunner   *backups.Runner
	Network        *network.Manager
	Updates        *updates.Manager
	FrankenPHP     *frankenphp.Installer
	Tools          *tools.Installer
	Insights       *insights.Scanner
	Meilisearch    *meilisearch.Manager
}

func (s *Services) Register(g *grpc.Server) {
	agentv1.RegisterServerServiceServer(g, serverService{Services: s})
	agentv1.RegisterSiteServiceServer(g, siteService{Services: s})
	agentv1.RegisterDeployServiceServer(g, deployService{Services: s})
	agentv1.RegisterConfigServiceServer(g, configService{Services: s})
	agentv1.RegisterDomainServiceServer(g, domainService{Services: s})
	agentv1.RegisterCertificateServiceServer(g, certificateService{Services: s})
	agentv1.RegisterDatabaseServiceServer(g, databaseService{Services: s})
	agentv1.RegisterBackupServiceServer(g, backupService{Services: s})
}

func checkID(id string) error {
	if !ids.Valid(id) {
		return status.Errorf(codes.InvalidArgument, "%q isn't a valid id.", id)
	}

	return nil
}

func invalidRepositoryURL(err error) error {
	return status.Error(codes.InvalidArgument, "That repository URL isn't valid.\n\n"+err.Error())
}

func limit(requested uint32, fallback, ceiling int) int {
	if requested == 0 {
		return fallback
	}

	return min(int(requested), ceiling)
}

type serverService struct {
	agentv1.UnimplementedServerServiceServer
	*Services
}

func (s serverService) GetCapabilities(ctx context.Context, _ *agentv1.GetCapabilitiesRequest) (*agentv1.GetCapabilitiesResponse, error) {
	c := s.Capabilities(ctx)

	return &agentv1.GetCapabilitiesResponse{
		PhpVersions:     c.PHPVersions,
		DatabaseEngine:  c.DatabaseEngine,
		DatabaseVersion: c.DatabaseVersion,
		NodeVersion:     c.NodeVersion,
		NginxVersion:    c.NginxVersion,
		PublicAddresses: c.PublicAddresses,
		PortGuard:       c.PortGuard,
		UvVersion:       c.UVVersion,
		BunVersion:      c.BunVersion,
	}, nil
}

func (s serverService) ListScheduledJobs(ctx context.Context, request *agentv1.ListScheduledJobsRequest) (*agentv1.ListScheduledJobsResponse, error) {
	list, revision, err := s.Jobs.List()
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListScheduledJobsResponse{Revision: revision}
	for _, job := range list {
		run := s.Jobs.LastRun(ctx, job.ID)
		log := ""
		if !request.GetWithoutLogs() {
			log = s.Jobs.Log(ctx, job.ID, 20)
		}
		response.Jobs = append(response.Jobs, &agentv1.ScheduledJob{
			Id: job.ID, Name: job.Name, Command: job.Command, User: job.User, Schedule: job.Schedule, Log: log,
			LastStartedAt: timestamp(run.Started), LastFinishedAt: timestamp(run.Finished), LastExitCode: int32(run.ExitCode), Running: run.Running,
		})
	}

	return response, nil
}

func (s serverService) ListBackgroundProcesses(ctx context.Context, request *agentv1.ListBackgroundProcessesRequest) (*agentv1.ListBackgroundProcessesResponse, error) {
	list, revision, err := s.Daemons.List()
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListBackgroundProcessesResponse{Revision: revision}
	for _, d := range list {
		lines := 100
		if request.GetWithoutLogs() {
			lines = 0
		}
		status := s.Daemons.Status(ctx, d, lines)
		response.Processes = append(response.Processes, &agentv1.BackgroundProcess{
			Id: d.ID, Name: d.Name, Command: d.Command, User: d.User, Directory: d.Directory, Count: uint32(d.Count),
			Running: uint32(status.Running), Log: status.Log, Stopped: d.Stopped, StopSeconds: uint32(d.StopSeconds),
		})
	}

	return response, nil
}

func (s serverService) PutBackgroundProcesses(ctx context.Context, request *agentv1.PutBackgroundProcessesRequest) (*agentv1.PutBackgroundProcessesResponse, error) {
	list := make([]daemons.Daemon, 0, len(request.Processes))
	for _, p := range request.Processes {
		list = append(list, daemons.Daemon{ID: p.Id, Name: p.Name, Command: p.Command, User: p.User, Directory: p.Directory, Count: int(p.Count), Stopped: p.Stopped, StopSeconds: int(p.StopSeconds)})
	}

	revision, err := s.Daemons.Put(ctx, list, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutBackgroundProcessesResponse{Revision: revision}, nil
}

func (s serverService) GetInsights(ctx context.Context, request *agentv1.GetInsightsRequest) (*agentv1.GetInsightsResponse, error) {
	found, scanned, partial := s.Insights.Insights(ctx, request.GetRefresh())

	response := &agentv1.GetInsightsResponse{ScannedAt: scanned.Unix(), Partial: partial}
	for _, insight := range found {
		response.Insights = append(response.Insights, &agentv1.Insight{Kind: insight.Kind, Subject: insight.Subject, Values: insight.Values, Fixable: insight.Fixable})
	}

	return response, nil
}

func (s serverService) FixInsight(ctx context.Context, request *agentv1.FixInsightRequest) (*agentv1.FixInsightResponse, error) {
	if err := s.Insights.Fix(ctx, request.GetKind(), request.GetSubject(), request.GetActor()); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.FixInsightResponse{}, nil
}

func (s serverService) InstallFrankenPHP(ctx context.Context, _ *agentv1.InstallFrankenPHPRequest) (*agentv1.InstallFrankenPHPResponse, error) {
	if err := s.FrankenPHP.Install(ctx); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.InstallFrankenPHPResponse{Version: frankenphp.Version}, nil
}

func (s serverService) InstallTool(ctx context.Context, request *agentv1.InstallToolRequest) (*agentv1.InstallToolResponse, error) {
	tool, known := map[agentv1.Tool]tools.Tool{agentv1.Tool_TOOL_UV: tools.UV, agentv1.Tool_TOOL_BUN: tools.Bun}[request.Tool]
	if !known {
		return nil, status.Errorf(codes.InvalidArgument, "Unknown tool %v.", request.Tool)
	}

	if err := s.Tools.Install(ctx, tool); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.InstallToolResponse{Version: tool.Version}, nil
}

func (s serverService) RestartBackgroundProcess(ctx context.Context, request *agentv1.RestartBackgroundProcessRequest) (*agentv1.RestartBackgroundProcessResponse, error) {
	if err := s.Daemons.Restart(ctx, request.Id); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.RestartBackgroundProcessResponse{}, nil
}

func (s serverService) GetServerSettings(context.Context, *agentv1.GetServerSettingsRequest) (*agentv1.GetServerSettingsResponse, error) {
	password, err := s.Settings.RedisPassword()
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.GetServerSettingsResponse{Timezone: s.Settings.Timezone(), RedisInstalled: s.Settings.RedisInstalled(), RedisPassword: password}, nil
}

func (s serverService) SetTimezone(ctx context.Context, request *agentv1.SetTimezoneRequest) (*agentv1.SetTimezoneResponse, error) {
	if err := s.Settings.SetTimezone(ctx, request.Timezone); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.SetTimezoneResponse{}, nil
}

func (s serverService) SetRedisPassword(ctx context.Context, request *agentv1.SetRedisPasswordRequest) (*agentv1.SetRedisPasswordResponse, error) {
	if err := s.Settings.SetRedisPassword(ctx, request.Password); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.SetRedisPasswordResponse{}, nil
}

func (s serverService) ListSystemServices(ctx context.Context, _ *agentv1.ListSystemServicesRequest) (*agentv1.ListSystemServicesResponse, error) {
	services, err := s.SystemServices.List(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListSystemServicesResponse{}
	for _, service := range services {
		response.Services = append(response.Services, &agentv1.SystemService{Unit: service.Unit, State: service.State, Reloadable: service.Reloadable})
	}

	return response, nil
}

var serviceActions = map[agentv1.ServiceAction]servicectl.Action{
	agentv1.ServiceAction_SERVICE_ACTION_START:   servicectl.Start,
	agentv1.ServiceAction_SERVICE_ACTION_STOP:    servicectl.Stop,
	agentv1.ServiceAction_SERVICE_ACTION_RESTART: servicectl.Restart,
	agentv1.ServiceAction_SERVICE_ACTION_RELOAD:  servicectl.Reload,
}

func (s serverService) ControlSystemService(ctx context.Context, request *agentv1.ControlSystemServiceRequest) (*agentv1.ControlSystemServiceResponse, error) {
	if err := s.SystemServices.Control(ctx, request.Unit, serviceActions[request.Action]); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.ControlSystemServiceResponse{}, nil
}

func (s serverService) RebootServer(context.Context, *agentv1.RebootServerRequest) (*agentv1.RebootServerResponse, error) {
	s.SystemServices.Reboot()
	return &agentv1.RebootServerResponse{}, nil
}

func (s serverService) GetMetricHistory(_ context.Context, request *agentv1.GetMetricHistoryRequest) (*agentv1.GetMetricHistoryResponse, error) {
	samples, step, err := s.Metrics.History(time.Duration(request.SpanSeconds) * time.Second)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetMetricHistoryResponse{StepSeconds: uint32(step / time.Second)}
	for _, sample := range samples {
		response.Samples = append(response.Samples, &agentv1.MetricSample{
			Time: sample.Time.Unix(), Load1: sample.Load1, MemUsed: sample.MemUsed, DiskUsed: sample.DiskUsed,
			RxBytesPerSecond: sample.RxRate, TxBytesPerSecond: sample.TxRate,
		})
	}

	return response, nil
}

func (s serverService) GetPHPSettings(_ context.Context, _ *agentv1.GetPHPSettingsRequest) (*agentv1.GetPHPSettingsResponse, error) {
	settings, revision, err := s.PHPSettings.Get()
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.GetPHPSettingsResponse{Revision: revision, Settings: &agentv1.PHPSettings{
		UploadMb: uint32(settings.UploadMB), MaxExecutionSeconds: uint32(settings.MaxExecutionSeconds),
		MemoryMb: uint32(settings.MemoryMB), OpcacheFrozen: settings.OPcacheFrozen,
	}}, nil
}

func (s serverService) PutPHPSettings(ctx context.Context, request *agentv1.PutPHPSettingsRequest) (*agentv1.PutPHPSettingsResponse, error) {
	in := request.GetSettings()
	settings := phpsettings.Settings{
		UploadMB: int(in.GetUploadMb()), MaxExecutionSeconds: int(in.GetMaxExecutionSeconds()),
		MemoryMB: int(in.GetMemoryMb()), OPcacheFrozen: in.GetOpcacheFrozen(),
	}

	revision, err := s.PHPSettings.Put(ctx, settings, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutPHPSettingsResponse{Revision: revision}, nil
}

func (s serverService) GetUpdates(ctx context.Context, _ *agentv1.GetUpdatesRequest) (*agentv1.GetUpdatesResponse, error) {
	settings, revision, err := s.Updates.Get()
	if err != nil {
		return nil, toStatus(err)
	}

	current, err := s.Updates.Status(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetUpdatesResponse{
		Settings: &agentv1.UpdateSettings{Databases: settings.Databases, AutomaticReboot: settings.AutomaticReboot, RebootTime: settings.RebootTime},
		Revision: revision, Pending: uint32(current.Pending), SecurityPending: uint32(current.SecurityPending),
		RebootPackages: current.RebootPackages,
	}
	if !current.LastRun.IsZero() {
		response.LastRun = current.LastRun.Unix()
	}
	if !current.RebootRequiredSince.IsZero() {
		response.RebootRequiredSince = current.RebootRequiredSince.Unix()
	}

	return response, nil
}

func (s serverService) PutUpdateSettings(ctx context.Context, request *agentv1.PutUpdateSettingsRequest) (*agentv1.PutUpdateSettingsResponse, error) {
	in := request.GetSettings()
	settings := updates.Settings{Databases: in.GetDatabases(), AutomaticReboot: in.GetAutomaticReboot(), RebootTime: in.GetRebootTime()}

	revision, err := s.Updates.Put(ctx, settings, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutUpdateSettingsResponse{Revision: revision}, nil
}

func (s serverService) GetComposerCredentials(ctx context.Context, request *agentv1.GetComposerCredentialsRequest) (*agentv1.GetComposerCredentialsResponse, error) {
	list, err := s.Credentials.Composer(ctx, request.User)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetComposerCredentialsResponse{}
	for _, c := range list {
		response.Credentials = append(response.Credentials, &agentv1.ComposerCredential{Host: c.Host, Username: c.Username, Password: c.Password})
	}

	return response, nil
}

func (s serverService) PutComposerCredentials(ctx context.Context, request *agentv1.PutComposerCredentialsRequest) (*agentv1.PutComposerCredentialsResponse, error) {
	list := make([]credentials.Composer, 0, len(request.Credentials))
	for _, c := range request.Credentials {
		list = append(list, credentials.Composer{Host: c.Host, Username: c.Username, Password: c.Password})
	}

	if err := s.Credentials.PutComposer(ctx, request.User, list); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutComposerCredentialsResponse{}, nil
}

func (s serverService) GetNPMCredentials(ctx context.Context, request *agentv1.GetNPMCredentialsRequest) (*agentv1.GetNPMCredentialsResponse, error) {
	list, err := s.Credentials.NPM(ctx, request.User)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetNPMCredentialsResponse{}
	for _, n := range list {
		response.Credentials = append(response.Credentials, &agentv1.NPMCredential{Registry: n.Registry, Token: n.Token})
	}

	return response, nil
}

func (s serverService) PutNPMCredentials(ctx context.Context, request *agentv1.PutNPMCredentialsRequest) (*agentv1.PutNPMCredentialsResponse, error) {
	list := make([]credentials.NPM, 0, len(request.Credentials))
	for _, n := range request.Credentials {
		list = append(list, credentials.NPM{Registry: n.Registry, Token: n.Token})
	}

	if err := s.Credentials.PutNPM(ctx, request.User, list); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutNPMCredentialsResponse{}, nil
}

func (s serverService) PutScheduledJobs(ctx context.Context, request *agentv1.PutScheduledJobsRequest) (*agentv1.PutScheduledJobsResponse, error) {
	list := make([]jobs.Job, 0, len(request.Jobs))
	for _, job := range request.Jobs {
		list = append(list, jobs.Job{ID: job.Id, Name: job.Name, Command: job.Command, User: job.User, Schedule: job.Schedule})
	}

	revision, err := s.Jobs.Put(ctx, list, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutScheduledJobsResponse{Revision: revision}, nil
}

func (s serverService) GetNotifications(context.Context, *agentv1.GetNotificationsRequest) (*agentv1.GetNotificationsResponse, error) {
	settings, revision, err := s.Notifications.Get()
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.GetNotificationsResponse{Notifications: &agentv1.Notifications{
		WebhookUrl: settings.WebhookURL, OnSuccess: settings.OnSuccess,
		DiskPercent: settings.DiskPercent, MemoryPercent: settings.MemoryPercent, LoadPercent: settings.LoadPercent,
	}, Revision: revision}, nil
}

func (s serverService) PutNotifications(_ context.Context, request *agentv1.PutNotificationsRequest) (*agentv1.PutNotificationsResponse, error) {
	n := request.GetNotifications()
	settings := notify.Settings{
		WebhookURL: n.GetWebhookUrl(), OnSuccess: n.GetOnSuccess(),
		DiskPercent: n.GetDiskPercent(), MemoryPercent: n.GetMemoryPercent(), LoadPercent: n.GetLoadPercent(),
	}

	revision, err := s.Notifications.Put(settings, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutNotificationsResponse{Revision: revision}, nil
}

func (s serverService) TestNotifications(ctx context.Context, request *agentv1.TestNotificationsRequest) (*agentv1.TestNotificationsResponse, error) {
	if err := s.Notifications.Test(ctx, strings.TrimSpace(request.WebhookUrl)); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.TestNotificationsResponse{}, nil
}

func (s serverService) ListLogs(context.Context, *agentv1.ListLogsRequest) (*agentv1.ListLogsResponse, error) {
	sources, err := s.Logs.List()
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListLogsResponse{}
	for _, source := range sources {
		response.Sources = append(response.Sources, &agentv1.LogSource{Id: source.ID, Title: source.Title, Group: source.Group})
	}

	return response, nil
}

func (s serverService) ReadLog(ctx context.Context, request *agentv1.ReadLogRequest) (*agentv1.ReadLogResponse, error) {
	text, err := s.Logs.Read(ctx, request.Id, int(request.Lines))
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.ReadLogResponse{Text: strings.ToValidUTF8(text, "\uFFFD")}, nil
}

type siteService struct {
	agentv1.UnimplementedSiteServiceServer
	*Services
}

func (s siteService) PutSite(ctx context.Context, request *agentv1.PutSiteRequest) (*agentv1.PutSiteResponse, error) {
	if request.Site == nil {
		return nil, status.Error(codes.InvalidArgument, "The request has no site.")
	}

	saved, created, err := s.Sites.Put(ctx, siteFromProto(request.Site), request.ExpectedRevision, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutSiteResponse{Site: siteToProto(saved), Created: created}, nil
}

func (s siteService) GetSite(_ context.Context, request *agentv1.GetSiteRequest) (*agentv1.GetSiteResponse, error) {
	found, err := s.Store.GetSite(request.Id)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.GetSiteResponse{Site: siteToProto(found)}, nil
}

func (s siteService) ListSites(context.Context, *agentv1.ListSitesRequest) (*agentv1.ListSitesResponse, error) {
	list, err := s.Store.ListSites()
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListSitesResponse{}
	for _, found := range list {
		response.Sites = append(response.Sites, siteToProto(found))
	}

	return response, nil
}

func (s siteService) DeleteSite(ctx context.Context, request *agentv1.DeleteSiteRequest) (*agentv1.DeleteSiteResponse, error) {
	if err := s.Sites.Delete(ctx, request.Id, request.RemoveFiles, request.Actor); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.DeleteSiteResponse{}, nil
}

func (s siteService) GetDeployKey(ctx context.Context, request *agentv1.GetDeployKeyRequest) (*agentv1.GetDeployKeyResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}

	key, err := s.Sites.DeployKey(ctx, request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.GetDeployKeyResponse{PublicKey: text(key.PublicKey), Fingerprint: key.Fingerprint}, nil
}

func (s siteService) TestRepository(ctx context.Context, request *agentv1.TestRepositoryRequest) (*agentv1.TestRepositoryResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}
	if _, err := gitsource.ParseURL(request.RepositoryUrl); err != nil {
		return nil, invalidRepositoryURL(err)
	}

	if err := s.Sites.RefreshKnownHosts(ctx, request.SiteId); err != nil {
		return nil, toStatus(err)
	}

	credentials, err := s.Sites.RepositoryCredentials(ctx, request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	trusted, err := s.trusted(request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	result := s.Tester.Test(ctx, request.RepositoryUrl, request.Branch, trusted, credentials)

	// Only a key the site trusts itself can be removed, so a provider's key leaves the fingerprint empty.
	var trustedFingerprint string
	if result.Access == gitsource.AccessHostKeyChanged {
		own, err := s.ownHostKeys(request.SiteId)
		if err != nil {
			return nil, toStatus(err)
		}
		trustedFingerprint = gitsource.Preferred(hostKeys(own, result.Host)).Fingerprint
	}

	return &agentv1.TestRepositoryResponse{
		Access:                    accessToProto[result.Access],
		Commit:                    result.Commit,
		Host:                      result.Host,
		HostKeyType:               result.HostKeyType,
		HostKeyFingerprint:        result.HostKeyFingerprint,
		Detail:                    text(result.Detail),
		TrustedHostKeyFingerprint: trustedFingerprint,
	}, nil
}

func (s siteService) TrustHostKey(ctx context.Context, request *agentv1.TrustHostKeyRequest) (*agentv1.TrustHostKeyResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}

	remote, err := gitsource.ParseURL(request.RepositoryUrl)
	if err != nil {
		return nil, invalidRepositoryURL(err)
	}

	// Trust on first use only: a host with trusted keys never gets another one this way, so a changed key can't be
	// accepted by confirming its fingerprint.
	trusted, err := s.trusted(request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}
	if known := hostKeys(trusted, remote.KnownHostsName()); len(known) > 0 {
		for _, key := range known {
			if key.Fingerprint == request.Fingerprint {
				return &agentv1.TrustHostKeyResponse{}, nil
			}
		}

		return nil, status.Error(codes.FailedPrecondition, "This host already has a different trusted key.\n\nIf the host changed its key on purpose, remove the old key first, then trust the new one.")
	}

	scanned, err := s.Tester.Scan(ctx, remote)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "The Git host didn't answer.\n\n"+err.Error())
	}

	for _, key := range scanned {
		if key.Fingerprint != request.Fingerprint {
			continue
		}

		if err := s.Store.AddHostKey(request.SiteId, key.Line); err != nil {
			return nil, toStatus(err)
		}
		if err := s.Sites.RefreshKnownHosts(ctx, request.SiteId); err != nil {
			return nil, toStatus(err)
		}

		return &agentv1.TrustHostKeyResponse{}, nil
	}

	return nil, status.Error(codes.FailedPrecondition, "The host's key changed since you checked it. Test access again before trusting it.")
}

func (s siteService) RemoveHostKeys(ctx context.Context, request *agentv1.RemoveHostKeysRequest) (*agentv1.RemoveHostKeysResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}

	remote, err := gitsource.ParseURL(request.RepositoryUrl)
	if err != nil {
		return nil, invalidRepositoryURL(err)
	}

	removed, err := s.Sites.RemoveHostKeys(ctx, request.SiteId, remote.KnownHostsName(), request.Fingerprint, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.RemoveHostKeysResponse{Host: remote.KnownHostsName(), Fingerprints: removed}, nil
}

func (s siteService) ListProcesses(ctx context.Context, request *agentv1.ListProcessesRequest) (*agentv1.ListProcessesResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}

	lines := limit(request.LogLines, 100, 500)
	if request.GetWithoutLogs() {
		lines = 0
	}
	statuses, err := s.Sites.Processes(ctx, request.SiteId, lines)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListProcessesResponse{}
	for _, found := range statuses {
		response.Processes = append(response.Processes, &agentv1.ProcessStatus{Id: found.ID, Running: uint32(found.Running), WaitingForRelease: found.WaitingForRelease, Log: text(found.Log)})
	}

	return response, nil
}

func (s siteService) RestartProcess(ctx context.Context, request *agentv1.RestartProcessRequest) (*agentv1.RestartProcessResponse, error) {
	if err := checkID(request.SiteId); err != nil {
		return nil, err
	}

	if err := s.Sites.RestartProcess(ctx, request.SiteId, request.ProcessId, request.Actor); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.RestartProcessResponse{}, nil
}

func (s siteService) ListActivity(_ context.Context, request *agentv1.ListActivityRequest) (*agentv1.ListActivityResponse, error) {
	entries, err := s.Store.ListActivity(request.SiteId, limit(request.Limit, 50, 200))
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListActivityResponse{}
	for _, entry := range entries {
		response.Entries = append(response.Entries, &agentv1.ActivityEntry{At: timestamp(entry.At), Kind: entry.Kind, Actor: entry.Actor, Summary: text(entry.Summary)})
	}

	return response, nil
}

// trusted is every host key the site may connect to: the providers' published keys plus those the user confirmed.
func (s siteService) trusted(siteID string) ([]gitsource.HostKey, error) {
	own, err := s.ownHostKeys(siteID)
	if err != nil {
		return nil, err
	}

	return append(gitsource.ParseKnownHosts(gitsource.ProviderKnownHosts), own...), nil
}

// ownHostKeys is the host keys the user confirmed for the site, without the providers' published keys.
func (s siteService) ownHostKeys(siteID string) ([]gitsource.HostKey, error) {
	lines, err := s.Store.HostKeys(siteID)
	if err != nil {
		return nil, err
	}

	return gitsource.ParseKnownHosts(strings.Join(lines, "\n")), nil
}

// hostKeys returns the keys that name host.
func hostKeys(keys []gitsource.HostKey, host string) []gitsource.HostKey {
	var named []gitsource.HostKey
	for _, key := range keys {
		if key.Names(host) {
			named = append(named, key)
		}
	}

	return named
}

var accessToProto = map[gitsource.Access]agentv1.RepositoryAccess{
	gitsource.AccessOK:                 agentv1.RepositoryAccess_REPOSITORY_ACCESS_OK,
	gitsource.AccessKeyNotAdded:        agentv1.RepositoryAccess_REPOSITORY_ACCESS_KEY_NOT_ADDED,
	gitsource.AccessRepositoryNotFound: agentv1.RepositoryAccess_REPOSITORY_ACCESS_REPOSITORY_NOT_FOUND,
	gitsource.AccessBranchNotFound:     agentv1.RepositoryAccess_REPOSITORY_ACCESS_BRANCH_NOT_FOUND,
	gitsource.AccessHostKeyChanged:     agentv1.RepositoryAccess_REPOSITORY_ACCESS_HOST_KEY_CHANGED,
	gitsource.AccessHostKeyUnknown:     agentv1.RepositoryAccess_REPOSITORY_ACCESS_HOST_KEY_UNKNOWN,
	gitsource.AccessHostUnreachable:    agentv1.RepositoryAccess_REPOSITORY_ACCESS_HOST_UNREACHABLE,
	gitsource.AccessFailed:             agentv1.RepositoryAccess_REPOSITORY_ACCESS_FAILED,
}

type deployService struct {
	agentv1.UnimplementedDeployServiceServer
	*Services
}

func (s deployService) Deploy(ctx context.Context, request *agentv1.DeployRequest) (*agentv1.DeployResponse, error) {
	d, running, err := s.Deploys.Deploy(ctx, request.SiteId, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.DeployResponse{Deployment: deploymentToProto(d), AlreadyRunning: running}, nil
}

func (s deployService) WatchDeployment(request *agentv1.WatchDeploymentRequest, stream grpc.ServerStreamingServer[agentv1.WatchDeploymentResponse]) error {
	err := s.Watcher.Watch(stream.Context(), request.Id, int64(request.FromOffset), func(update deploy.Update) error {
		response := &agentv1.WatchDeploymentResponse{}

		switch {
		case update.Deployment != nil:
			response.Event = &agentv1.WatchDeploymentResponse_Deployment{Deployment: deploymentToProto(*update.Deployment)}
		case update.Command != "":
			response.Event = &agentv1.WatchDeploymentResponse_Command{Command: &agentv1.CurrentCommand{Text: text(update.Command), NextOffset: uint64(update.NextOffset)}}
		default:
			response.Event = &agentv1.WatchDeploymentResponse_Log{Log: &agentv1.LogChunk{Text: text(update.Log), NextOffset: uint64(update.NextOffset)}}
		}

		return stream.Send(response)
	})

	return toStatus(err)
}

func (s deployService) ListDeployments(_ context.Context, request *agentv1.ListDeploymentsRequest) (*agentv1.ListDeploymentsResponse, error) {
	list, err := s.Store.ListDeployments(request.SiteId, limit(request.Limit, 50, 50))
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListDeploymentsResponse{}
	for _, d := range list {
		response.Deployments = append(response.Deployments, deploymentToProto(d))
	}

	return response, nil
}

func (s deployService) CancelDeployment(ctx context.Context, request *agentv1.CancelDeploymentRequest) (*agentv1.CancelDeploymentResponse, error) {
	d, err := s.Deploys.Cancel(ctx, request.Id, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.CancelDeploymentResponse{Deployment: deploymentToProto(d)}, nil
}

func (s deployService) Rollback(ctx context.Context, request *agentv1.RollbackRequest) (*agentv1.RollbackResponse, error) {
	d, err := s.Deploys.Rollback(ctx, request.SiteId, request.Release, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.RollbackResponse{Deployment: deploymentToProto(d)}, nil
}

func (s deployService) ListReleases(_ context.Context, request *agentv1.ListReleasesRequest) (*agentv1.ListReleasesResponse, error) {
	found, err := s.Store.GetSite(request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	dir := s.Paths.File(found.Directory)
	entries, err := os.ReadDir(filepath.Join(dir, "releases"))
	if err != nil && !os.IsNotExist(err) {
		return nil, toStatus(err)
	}

	live := ""
	if target, err := os.Readlink(filepath.Join(dir, "current")); err == nil {
		live = filepath.Base(target)
	}

	wentLive, err := s.Store.ReleasesThatWentLive(found.ID)
	if err != nil {
		return nil, toStatus(err)
	}

	// Only releases that went live can be rolled back to; the live one is listed whatever its record says.
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && (wentLive[entry.Name()] || entry.Name() == live) {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	response := &agentv1.ListReleasesResponse{}
	for _, name := range names {
		commit, message, _ := s.Store.ReleaseCommit(found.ID, name)
		response.Releases = append(response.Releases, &agentv1.Release{Name: name, Commit: commit, CommitMessage: text(message), Live: name == live})
	}

	return response, nil
}

type configService struct {
	agentv1.UnimplementedConfigServiceServer
	*Services
}

func (s configService) GetEnv(ctx context.Context, request *agentv1.GetEnvRequest) (*agentv1.GetEnvResponse, error) {
	content, sum, err := s.Sites.Env(ctx, request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	// Replacing bytes here would let a later PutEnv silently change them in the file.
	if !utf8.Valid(content) {
		return nil, status.Error(codes.FailedPrecondition, "The environment file isn't valid UTF-8, so ServerDog can't edit it safely.")
	}

	return &agentv1.GetEnvResponse{Content: string(content), Sha256: sum}, nil
}

func (s configService) PutEnv(ctx context.Context, request *agentv1.PutEnvRequest) (*agentv1.PutEnvResponse, error) {
	sum, err := s.Sites.PutEnv(ctx, request.SiteId, []byte(request.Content), request.ExpectedSha256, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutEnvResponse{Sha256: sum}, nil
}

func (s configService) GetNginxConfig(ctx context.Context, request *agentv1.GetNginxConfigRequest) (*agentv1.GetNginxConfigResponse, error) {
	content, sum, customised, err := s.Sites.NginxConfig(ctx, request.SiteId)
	if err != nil {
		return nil, toStatus(err)
	}

	// Replacing bytes here would let a later PutNginxConfig silently change them in the file.
	if !utf8.Valid(content) {
		return nil, status.Error(codes.FailedPrecondition, "The Nginx configuration isn't valid UTF-8, so ServerDog can't edit it safely.")
	}

	return &agentv1.GetNginxConfigResponse{Content: string(content), Sha256: sum, Customised: customised}, nil
}

func (s configService) PutNginxConfig(ctx context.Context, request *agentv1.PutNginxConfigRequest) (*agentv1.PutNginxConfigResponse, error) {
	sum, err := s.Sites.PutNginxConfig(ctx, request.SiteId, []byte(request.Content), request.ExpectedSha256, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutNginxConfigResponse{Sha256: sum}, nil
}

func (s configService) ResetNginxConfig(ctx context.Context, request *agentv1.ResetNginxConfigRequest) (*agentv1.ResetNginxConfigResponse, error) {
	content, sum, err := s.Sites.ResetNginxConfig(ctx, request.SiteId, request.Actor)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.ResetNginxConfigResponse{Content: string(content), Sha256: sum}, nil
}

func (s serverService) GetMeilisearchConfig(context.Context, *agentv1.GetMeilisearchConfigRequest) (*agentv1.GetMeilisearchConfigResponse, error) {
	if !s.Meilisearch.Installed() {
		return &agentv1.GetMeilisearchConfigResponse{}, nil
	}

	config, err := s.Meilisearch.Config()
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.GetMeilisearchConfigResponse{Installed: true, Config: config}, nil
}

func (s serverService) PutMeilisearchConfig(ctx context.Context, request *agentv1.PutMeilisearchConfigRequest) (*agentv1.PutMeilisearchConfigResponse, error) {
	if err := s.Meilisearch.PutConfig(ctx, request.Config); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutMeilisearchConfigResponse{}, nil
}

func (s serverService) ListMeilisearchKeys(ctx context.Context, _ *agentv1.ListMeilisearchKeysRequest) (*agentv1.ListMeilisearchKeysResponse, error) {
	keys, err := s.Meilisearch.Keys(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListMeilisearchKeysResponse{}
	for _, k := range keys {
		response.Keys = append(response.Keys, &agentv1.MeilisearchKey{Name: k.Name, Description: k.Description, Key: k.Key, Actions: k.Actions, Indexes: k.Indexes, ExpiresAt: k.ExpiresAt})
	}

	return response, nil
}
