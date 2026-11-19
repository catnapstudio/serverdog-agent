package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/listen"
	"github.com/catnapstudio/serverdog-agent/internal/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startServer(t *testing.T, now func() time.Time) agentv1.AgentServiceClient {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "ca")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	socket := filepath.Join(dir, "agent.sock")
	listener, err := listen.Unix(socket)
	if err != nil {
		t.Fatal(err)
	}

	grpcServer := grpc.NewServer()
	agentv1.RegisterAgentServiceServer(grpcServer, New("../sysinfo/testdata/root", now))
	go grpcServer.Serve(listener)
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	return agentv1.NewAgentServiceClient(conn)
}

func TestHealthReportsAgentUptime(t *testing.T) {
	start := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	current := start
	client := startServer(t, func() time.Time { return current })
	current = start.Add(90 * time.Second)

	response, err := client.Health(context.Background(), &agentv1.HealthRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if !response.Ok || response.UptimeSeconds != 90 {
		t.Errorf("health = %+v", response)
	}
}

func TestGetVersionReturnsBuildMetadata(t *testing.T) {
	client := startServer(t, time.Now)

	response, err := client.GetVersion(context.Background(), &agentv1.GetVersionRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if response.Version != version.Version || response.ProtocolVersion != version.ProtocolVersion {
		t.Errorf("version = %+v", response)
	}
}

func TestGetSystemInfoMapsCollectedValues(t *testing.T) {
	client := startServer(t, time.Now)

	response, err := client.GetSystemInfo(context.Background(), &agentv1.GetSystemInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if response.Os != "Ubuntu 24.04.3 LTS" || response.OsVersion != "24.04" || response.MemTotal != 8000000*1024 || response.Load1 != 0.42 {
		t.Errorf("system info = %+v", response)
	}
}

func TestGetVersionReportsProtocolSix(t *testing.T) {
	client := startServer(t, time.Now)

	response, err := client.GetVersion(context.Background(), &agentv1.GetVersionRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if response.ProtocolVersion != 24 {
		t.Errorf("protocol version = %d, want 24", response.ProtocolVersion)
	}
}
