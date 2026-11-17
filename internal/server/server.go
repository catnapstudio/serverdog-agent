// Package server implements serverdog.agent.v1.AgentService.
package server

import (
	"context"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/sysinfo"
	"github.com/catnapstudio/serverdog-agent/internal/version"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server answers AgentService calls.
type Server struct {
	agentv1.UnimplementedAgentServiceServer

	root    string
	started time.Time
	now     func() time.Time
}

// New returns a Server that reads system information below root.
func New(root string, now func() time.Time) *Server {
	return &Server{root: root, started: now(), now: now}
}

func (s *Server) GetVersion(context.Context, *agentv1.GetVersionRequest) (*agentv1.GetVersionResponse, error) {
	return &agentv1.GetVersionResponse{
		Version:         version.Version,
		Commit:          version.Commit,
		BuiltAt:         version.BuiltAt,
		ProtocolVersion: version.ProtocolVersion,
	}, nil
}

func (s *Server) Health(context.Context, *agentv1.HealthRequest) (*agentv1.HealthResponse, error) {
	return &agentv1.HealthResponse{
		Ok:            true,
		UptimeSeconds: uint64(s.now().Sub(s.started).Seconds()),
	}, nil
}

func (s *Server) GetSystemInfo(context.Context, *agentv1.GetSystemInfoRequest) (*agentv1.GetSystemInfoResponse, error) {
	info, err := sysinfo.Collect(s.root)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "collect system info: %v", err)
	}

	return &agentv1.GetSystemInfoResponse{
		Os:            info.OS,
		OsVersion:     info.OSVersion,
		Kernel:        info.Kernel,
		Arch:          info.Arch,
		CpuCount:      info.CPUCount,
		CpuModel:      info.CPUModel,
		MemTotal:      info.MemTotal,
		MemUsed:       info.MemUsed,
		DiskTotal:     info.DiskTotal,
		DiskUsed:      info.DiskUsed,
		Load1:         info.Load1,
		Load5:         info.Load5,
		Load15:        info.Load15,
		UptimeSeconds: info.UptimeSeconds,
	}, nil
}
