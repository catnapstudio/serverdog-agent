package sysinfo

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCollectReadsFixtureRoot(t *testing.T) {
	info, err := Collect("testdata/root")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if info.OS != "Ubuntu 24.04.3 LTS" || info.OSVersion != "24.04" {
		t.Errorf("os = %q %q", info.OS, info.OSVersion)
	}
	if info.Kernel != "6.8.0-85-generic" {
		t.Errorf("kernel = %q", info.Kernel)
	}
	if info.CPUModel != "Intel(R) Xeon(R) Processor @ 2.40GHz" {
		t.Errorf("cpu model = %q", info.CPUModel)
	}
	if info.Arch != runtime.GOARCH || info.CPUCount != uint32(runtime.NumCPU()) {
		t.Errorf("arch/cpus = %q %d", info.Arch, info.CPUCount)
	}
	if info.MemTotal != 8000000*1024 || info.MemUsed != 3000000*1024 {
		t.Errorf("mem = %d used %d", info.MemTotal, info.MemUsed)
	}
	if info.Load1 != 0.42 || info.Load5 != 0.38 || info.Load15 != 0.31 {
		t.Errorf("load = %v %v %v", info.Load1, info.Load5, info.Load15)
	}
	if info.UptimeSeconds != 1987654 {
		t.Errorf("uptime = %d", info.UptimeSeconds)
	}
	if info.DiskTotal == 0 || info.DiskUsed > info.DiskTotal {
		t.Errorf("disk = %d used %d", info.DiskTotal, info.DiskUsed)
	}
}

func TestCollectWithoutCPUModelLeavesItEmpty(t *testing.T) {
	root := t.TempDir()
	copyTree(t, "testdata/root", root)
	if err := os.WriteFile(filepath.Join(root, "proc/cpuinfo"), []byte("processor\t: 0\nBogoMIPS\t: 50.00\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Collect(root)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if info.CPUModel != "" {
		t.Errorf("cpu model = %q, want empty", info.CPUModel)
	}
}

func TestCollectFailsWithoutOSRelease(t *testing.T) {
	if _, err := Collect(t.TempDir()); err == nil {
		t.Fatal("expected an error for a root without /etc/os-release")
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		target := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
