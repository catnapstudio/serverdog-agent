// Package metrics records the server's load, memory, disk and network traffic once a minute, for seven days.
//
// Samples live in a fixed-size file of one slot per minute of the week, written in place: the minute picks the slot,
// so the file never grows and needs no index, and a slot older than the week is ignored when read.
package metrics

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/sysinfo"
)

const (
	// Slots is a week of minutes.
	Slots = 7 * 24 * 60
	// MaxPoints is the most samples History returns; longer ranges are averaged down to it.
	MaxPoints  = 360
	recordSize = 8 + 8 + 8 + 8 + 8 + 8
)

// Sample is one minute, or the average of several. Rates are bytes per second over all interfaces but loopback.
type Sample struct {
	Time     time.Time
	Load1    float64
	MemUsed  uint64
	DiskUsed uint64
	RxRate   uint64
	TxRate   uint64
}

type Recorder struct {
	// File is the ring, created on the first write.
	File    string
	Collect func() (sysinfo.Info, error)
	// NetDev is /proc/net/dev under the managed root.
	NetDev string
	Now    func() time.Time

	mu       sync.Mutex
	lastRx   uint64
	lastTx   uint64
	lastRead time.Time
}

// Run records a sample at the start of every minute until ctx ends.
func (r *Recorder) Run(ctx context.Context, onError func(error)) {
	for {
		now := r.Now()
		wait := now.Truncate(time.Minute).Add(time.Minute).Sub(now)

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			if err := r.Record(); err != nil {
				onError(err)
			}
		}
	}
}

// Record reads the machine once and writes the minute's slot. The first call only primes the traffic counters.
func (r *Recorder) Record() error {
	info, err := r.Collect()
	if err != nil {
		return err
	}

	rx, tx, err := readNetDev(r.NetDev)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.Now()
	sample := Sample{Time: now.Truncate(time.Minute), Load1: info.Load1, MemUsed: info.MemUsed, DiskUsed: info.DiskUsed}
	if !r.lastRead.IsZero() {
		seconds := now.Sub(r.lastRead).Seconds()
		sample.RxRate = rate(r.lastRx, rx, seconds)
		sample.TxRate = rate(r.lastTx, tx, seconds)
	}
	primed := !r.lastRead.IsZero()
	r.lastRx, r.lastTx, r.lastRead = rx, tx, now

	if !primed {
		return nil
	}

	return r.write(sample)
}

// rate is zero when a counter went back, as after an interface came up again.
func rate(before, after uint64, seconds float64) uint64 {
	if after < before || seconds <= 0 {
		return 0
	}

	return uint64(float64(after-before) / seconds)
}

func (r *Recorder) write(sample Sample) error {
	if err := os.MkdirAll(filepath.Dir(r.File), 0o700); err != nil {
		return err
	}

	file, err := os.OpenFile(r.File, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	var record [recordSize]byte
	binary.LittleEndian.PutUint64(record[0:], uint64(sample.Time.Unix()))
	binary.LittleEndian.PutUint64(record[8:], math.Float64bits(sample.Load1))
	binary.LittleEndian.PutUint64(record[16:], sample.MemUsed)
	binary.LittleEndian.PutUint64(record[24:], sample.DiskUsed)
	binary.LittleEndian.PutUint64(record[32:], sample.RxRate)
	binary.LittleEndian.PutUint64(record[40:], sample.TxRate)

	slot := (sample.Time.Unix() / 60) % Slots
	if _, err := file.WriteAt(record[:], slot*recordSize); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}

	return nil
}

// History returns the samples of the last span, oldest first, averaged into steps so there are at most MaxPoints.
// It also returns the step.
func (r *Recorder) History(span time.Duration) ([]Sample, time.Duration, error) {
	span = min(max(span, time.Hour), Slots*time.Minute)
	step := max(time.Minute, (span / MaxPoints).Truncate(time.Minute))
	since := r.Now().Add(-span)

	r.mu.Lock()
	data, err := os.ReadFile(r.File)
	r.mu.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		return nil, step, nil
	}
	if err != nil {
		return nil, step, err
	}

	var minutes []Sample
	for offset := 0; offset+recordSize <= len(data); offset += recordSize {
		record := data[offset : offset+recordSize]
		seconds := int64(binary.LittleEndian.Uint64(record[0:]))
		if seconds == 0 {
			continue
		}

		at := time.Unix(seconds, 0)
		if at.Before(since) {
			continue
		}

		minutes = append(minutes, Sample{
			Time:     at,
			Load1:    math.Float64frombits(binary.LittleEndian.Uint64(record[8:])),
			MemUsed:  binary.LittleEndian.Uint64(record[16:]),
			DiskUsed: binary.LittleEndian.Uint64(record[24:]),
			RxRate:   binary.LittleEndian.Uint64(record[32:]),
			TxRate:   binary.LittleEndian.Uint64(record[40:]),
		})
	}

	sort.Slice(minutes, func(i, j int) bool { return minutes[i].Time.Before(minutes[j].Time) })

	return average(minutes, step), step, nil
}

// average folds the minutes into buckets of step, each stamped with its start.
func average(minutes []Sample, step time.Duration) []Sample {
	if step <= time.Minute {
		return minutes
	}

	var samples []Sample
	for start := 0; start < len(minutes); {
		bucket := minutes[start].Time.Truncate(step)
		end := start
		var sum Sample
		for end < len(minutes) && minutes[end].Time.Truncate(step).Equal(bucket) {
			sum.Load1 += minutes[end].Load1
			sum.MemUsed += minutes[end].MemUsed
			sum.RxRate += minutes[end].RxRate
			sum.TxRate += minutes[end].TxRate
			end++
		}

		count := uint64(end - start)
		samples = append(samples, Sample{
			Time:     bucket,
			Load1:    sum.Load1 / float64(count),
			MemUsed:  sum.MemUsed / count,
			DiskUsed: minutes[end-1].DiskUsed,
			RxRate:   sum.RxRate / count,
			TxRate:   sum.TxRate / count,
		})
		start = end
	}

	return samples
}

// readNetDev sums received and sent bytes over every interface but loopback.
func readNetDev(path string) (rx, tx uint64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	return parseNetDev(file)
}

func parseNetDev(reader io.Reader) (rx, tx uint64, err error) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		name, counters, found := strings.Cut(scanner.Text(), ":")
		if !found || strings.TrimSpace(name) == "lo" {
			continue
		}

		fields := strings.Fields(counters)
		if len(fields) < 9 {
			continue
		}

		received, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}

		sent, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}

		rx += received
		tx += sent
	}

	return rx, tx, scanner.Err()
}
