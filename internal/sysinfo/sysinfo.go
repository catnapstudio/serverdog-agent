// Package sysinfo reads system information from a Linux filesystem root.
package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Info describes the machine. Memory and disk values are in bytes.
type Info struct {
	OS            string
	OSVersion     string
	Kernel        string
	Arch          string
	CPUModel      string
	CPUCount      uint32
	MemTotal      uint64
	MemUsed       uint64
	DiskTotal     uint64
	DiskUsed      uint64
	Load1         float64
	Load5         float64
	Load15        float64
	UptimeSeconds uint64
}

// Collect reads system information from the filesystem rooted at root ("/" in production).
func Collect(root string) (Info, error) {
	info := Info{Arch: runtime.GOARCH, CPUCount: uint32(runtime.NumCPU())}

	osRelease, err := readKeyValues(filepath.Join(root, "etc/os-release"))
	if err != nil {
		return Info{}, fmt.Errorf("read os-release: %w", err)
	}

	info.OS = osRelease["PRETTY_NAME"]
	info.OSVersion = osRelease["VERSION_ID"]

	kernel, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/osrelease"))
	if err != nil {
		return Info{}, fmt.Errorf("read kernel release: %w", err)
	}

	info.Kernel = strings.TrimSpace(string(kernel))
	info.CPUModel = cpuModel(filepath.Join(root, "proc/cpuinfo"))

	mem, err := memInfo(filepath.Join(root, "proc/meminfo"))
	if err != nil {
		return Info{}, fmt.Errorf("read meminfo: %w", err)
	}

	info.MemTotal = mem["MemTotal"] * 1024
	info.MemUsed = (mem["MemTotal"] - mem["MemAvailable"]) * 1024

	loads, err := readFloats(filepath.Join(root, "proc/loadavg"), 3)
	if err != nil {
		return Info{}, fmt.Errorf("read loadavg: %w", err)
	}

	info.Load1, info.Load5, info.Load15 = loads[0], loads[1], loads[2]

	uptime, err := readFloats(filepath.Join(root, "proc/uptime"), 1)
	if err != nil {
		return Info{}, fmt.Errorf("read uptime: %w", err)
	}

	info.UptimeSeconds = uint64(uptime[0])

	var fs unix.Statfs_t
	if err := unix.Statfs(root, &fs); err != nil {
		return Info{}, fmt.Errorf("statfs %s: %w", root, err)
	}

	blockSize := uint64(fs.Bsize)
	info.DiskTotal = fs.Blocks * blockSize
	info.DiskUsed = (fs.Blocks - fs.Bfree) * blockSize

	return info, nil
}

func readKeyValues(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}

		values[key] = strings.Trim(value, `"'`)
	}

	return values, scanner.Err()
}

func cpuModel(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		if key == "model name" || key == "Model" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}

func memInfo(path string) (map[string]uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		number, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		values[strings.TrimSuffix(fields[0], ":")] = number
	}

	return values, scanner.Err()
}

func readFloats(path string, count int) ([]float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < count {
		return nil, fmt.Errorf("%s: expected %d values, got %d", path, count, len(fields))
	}

	values := make([]float64, count)
	for i := range count {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}

		values[i] = value
	}

	return values, nil
}
