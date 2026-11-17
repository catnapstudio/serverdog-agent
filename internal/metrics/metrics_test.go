package metrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/sysinfo"
)

const netDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9000      10    0    0    0     0          0         0     9000      10    0    0    0     0       0          0
  eth0: %d     100    0    0    0     0          0         0     %d     100    0    0    0     0       0          0
`

func TestParseNetDevSkipsLoopback(t *testing.T) {
	rx, tx, err := parseNetDev(strings.NewReader(strings.Replace(strings.Replace(netDev, "%d", "1000", 1), "%d", "500", 1)))
	if err != nil || rx != 1000 || tx != 500 {
		t.Fatalf("rx, tx = %d, %d, %v; want 1000, 500", rx, tx, err)
	}
}

func TestRecordsRatesAndAveragesLongRanges(t *testing.T) {
	dir := t.TempDir()
	devPath := filepath.Join(dir, "net_dev")
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	var load float64
	recorder := &Recorder{
		File:    filepath.Join(dir, "state", "metrics.bin"),
		NetDev:  devPath,
		Now:     func() time.Time { return now },
		Collect: func() (sysinfo.Info, error) { return sysinfo.Info{Load1: load, MemUsed: 100, DiskUsed: 7}, nil },
	}

	var received uint64
	for minute := 0; minute <= 120; minute++ {
		dev := strings.Replace(strings.Replace(netDev, "%d", strconv.FormatUint(received, 10), 1), "%d", "0", 1)
		if err := os.WriteFile(devPath, []byte(dev), 0o600); err != nil {
			t.Fatal(err)
		}
		load = float64(minute % 2)
		if err := recorder.Record(); err != nil {
			t.Fatal(err)
		}
		received += 6000
		now = now.Add(time.Minute)
	}

	hour, step, err := recorder.History(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if step != time.Minute || len(hour) != 60 {
		t.Fatalf("an hour has %d samples every %s; want 60 every minute", len(hour), step)
	}
	if hour[0].RxRate != 100 || hour[0].MemUsed != 100 {
		t.Errorf("first sample = %+v; want 100 B/s received and 100 bytes used", hour[0])
	}

	week, step, err := recorder.History(7 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if step != 28*time.Minute {
		t.Errorf("week step = %s; want 28m", step)
	}
	if len(week) == 0 || len(week) > MaxPoints {
		t.Fatalf("week has %d samples", len(week))
	}
	if load := week[1].Load1; load < 0.4 || load > 0.6 {
		t.Errorf("averaged load = %f; want about 0.5", load)
	}

	info, err := os.Stat(recorder.File)
	if err != nil || info.Size() > Slots*recordSize {
		t.Fatalf("file is %v bytes, %v", info, err)
	}
}

func TestOldSlotsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	recorder := &Recorder{File: filepath.Join(dir, "metrics.bin"), Now: func() time.Time { return now }}
	if err := recorder.write(Sample{Time: now.Add(-8 * 24 * time.Hour), Load1: 9}); err != nil {
		t.Fatal(err)
	}

	samples, _, err := recorder.History(7 * 24 * time.Hour)
	if err != nil || len(samples) != 0 {
		t.Fatalf("samples = %v, %v; want none", samples, err)
	}
}
