package server

import (
	"context"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/firewall"
	"github.com/catnapstudio/serverdog-agent/internal/sshkeys"
)

// Firewall

func (s serverService) GetFirewall(ctx context.Context, _ *agentv1.GetFirewallRequest) (*agentv1.GetFirewallResponse, error) {
	status, err := s.Firewall.Status(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetFirewallResponse{Installed: status.Installed, Active: status.Active, Revision: status.Revision, OtherRules: status.Other}
	for _, rule := range status.Rules {
		response.Rules = append(response.Rules, &agentv1.FirewallRule{Id: rule.ID, Name: rule.Name, Action: rule.Action, Port: rule.Port, Protocol: rule.Protocol, From: rule.From})
	}

	return response, nil
}

func (s serverService) PutFirewall(ctx context.Context, request *agentv1.PutFirewallRequest) (*agentv1.PutFirewallResponse, error) {
	rules := make([]firewall.Rule, 0, len(request.Rules))
	for _, rule := range request.Rules {
		rules = append(rules, firewall.Rule{ID: rule.Id, Name: rule.Name, Action: rule.Action, Port: rule.Port, Protocol: rule.Protocol, From: rule.From})
	}

	revision, err := s.Firewall.Put(ctx, rules, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutFirewallResponse{Revision: revision}, nil
}

// SSH keys

func (s serverService) GetSSHKeys(ctx context.Context, _ *agentv1.GetSSHKeysRequest) (*agentv1.GetSSHKeysResponse, error) {
	status, err := s.SSHKeys.Status(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetSSHKeysResponse{Revision: status.Revision, Users: status.Users}
	for _, key := range status.Keys {
		response.Keys = append(response.Keys, &agentv1.SSHKey{Id: key.ID, Name: key.Name, User: key.User, PublicKey: key.PublicKey})
	}
	for _, other := range status.Other {
		response.OtherKeys = append(response.OtherKeys, &agentv1.OtherSSHKey{User: other.User, Fingerprint: other.Fingerprint, Comment: other.Comment})
	}

	return response, nil
}

func (s serverService) PutSSHKeys(ctx context.Context, request *agentv1.PutSSHKeysRequest) (*agentv1.PutSSHKeysResponse, error) {
	keys := make([]sshkeys.Key, 0, len(request.Keys))
	for _, key := range request.Keys {
		keys = append(keys, sshkeys.Key{ID: key.Id, Name: key.Name, User: key.User, PublicKey: key.PublicKey})
	}

	revision, err := s.SSHKeys.Put(ctx, keys, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutSSHKeysResponse{Revision: revision}, nil
}

// PHP versions

func (s serverService) GetPHPVersions(ctx context.Context, _ *agentv1.GetPHPVersionsRequest) (*agentv1.GetPHPVersionsResponse, error) {
	status, err := s.PHP.Status(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.GetPHPVersionsResponse{Installed: status.Installed, Available: status.Available, Cli: status.CLI}
	for _, version := range status.Installed {
		if sites := status.UsedBy[version]; len(sites) > 0 {
			response.UsedBy = append(response.UsedBy, &agentv1.PHPVersionUse{Version: version, Sites: sites})
		}
	}

	return response, nil
}

func (s serverService) InstallPHPVersion(ctx context.Context, request *agentv1.InstallPHPVersionRequest) (*agentv1.InstallPHPVersionResponse, error) {
	if err := s.PHP.Install(ctx, request.Version); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.InstallPHPVersionResponse{}, nil
}

func (s serverService) RemovePHPVersion(ctx context.Context, request *agentv1.RemovePHPVersionRequest) (*agentv1.RemovePHPVersionResponse, error) {
	if err := s.PHP.Remove(ctx, request.Version); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.RemovePHPVersionResponse{}, nil
}

func (s serverService) SetCLIPHPVersion(ctx context.Context, request *agentv1.SetCLIPHPVersionRequest) (*agentv1.SetCLIPHPVersionResponse, error) {
	if err := s.PHP.SetCLI(ctx, request.Version); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.SetCLIPHPVersionResponse{}, nil
}

// Databases

func (s databaseService) ListDatabases(ctx context.Context, _ *agentv1.ListDatabasesRequest) (*agentv1.ListDatabasesResponse, error) {
	listing, err := s.Databases.List(ctx)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.ListDatabasesResponse{Engine: listing.Engine, Databases: listing.Databases, Users: listing.Users}, nil
}

func (s databaseService) DeleteDatabase(ctx context.Context, request *agentv1.DeleteDatabaseRequest) (*agentv1.DeleteDatabaseResponse, error) {
	if err := s.Databases.DeleteDatabase(ctx, request.Name); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.DeleteDatabaseResponse{}, nil
}

func (s databaseService) DeleteDatabaseUser(ctx context.Context, request *agentv1.DeleteDatabaseUserRequest) (*agentv1.DeleteDatabaseUserResponse, error) {
	if err := s.Databases.DeleteUser(ctx, request.User); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.DeleteDatabaseUserResponse{}, nil
}

func (s databaseService) SetDatabaseUserPassword(ctx context.Context, request *agentv1.SetDatabaseUserPasswordRequest) (*agentv1.SetDatabaseUserPasswordResponse, error) {
	if err := s.Databases.SetPassword(ctx, request.User, request.Password); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.SetDatabaseUserPasswordResponse{}, nil
}

func (s databaseService) CreateReadOnlyDatabaseUser(ctx context.Context, request *agentv1.CreateReadOnlyDatabaseUserRequest) (*agentv1.CreateReadOnlyDatabaseUserResponse, error) {
	if err := s.Databases.CreateReadOnlyUser(ctx, request.Database, request.User, request.Password); err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.CreateReadOnlyDatabaseUserResponse{}, nil
}
