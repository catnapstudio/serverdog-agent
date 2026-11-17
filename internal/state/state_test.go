package state

import (
	"testing"
	"time"
)

func TestRecordStartKeepsInstallTimeAndVersionHistory(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	first := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	if err := store.RecordStart("v0.1.0", first); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordStart("v0.1.0", first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordStart("v0.2.0", first.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	installedAt, err := store.InstalledAt()
	if err != nil {
		t.Fatal(err)
	}
	if !installedAt.Equal(first) {
		t.Errorf("installedAt = %v, want %v", installedAt, first)
	}

	versions, err := store.Versions()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Version != "v0.1.0" || versions[1].Version != "v0.2.0" {
		t.Errorf("versions = %+v", versions)
	}
}

func TestOpenTwiceReusesTheDatabase(t *testing.T) {
	dir := t.TempDir()

	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordStart("v0.1.0", time.Now()); err != nil {
		t.Fatal(err)
	}
	store.Close()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	versions, err := reopened.Versions()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Errorf("versions = %+v", versions)
	}
}
