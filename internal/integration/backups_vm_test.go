//go:build vmtest

package integration

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

// A fake S3 on this server stands in for the bucket; plain http is allowed for storage on the server itself.
func TestBackupsDumpUploadAndKeepTheNewest(t *testing.T) {
	engine := serverEngine(t)
	name := "backup_" + strings.ToLower(ids.New()[:6])
	createByHand(t, engine, name, name, "secret-"+ids.New())
	insert := fmt.Sprintf("CREATE TABLE notes (body text); INSERT INTO notes VALUES ('remember %s');", name)
	if engine == "postgres" {
		sh(t, "/", "runuser", "-u", "postgres", "--", "psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", name, "-c", insert)
	} else {
		command := rootSQL(engine, insert)
		sh(t, "/", command[0], append(command[1:], name)...)
	}

	backend := s3mem.New()
	if err := backend.CreateBucket("backups"); err != nil {
		t.Fatal(err)
	}
	storage := httptest.NewServer(gofakes3.New(backend).Server())
	defer storage.Close()

	client := agentv1.NewBackupServiceClient(conn)
	listed, err := client.ListBackupPlans(timeout(t), &agentv1.ListBackupPlansRequest{})
	if err != nil {
		t.Fatal(err)
	}

	plan := &agentv1.BackupPlan{
		Id: ids.New(), Name: "Nightly", Databases: []string{name}, Schedule: "0 3 * * *", Keep: 1,
		Storage: &agentv1.BackupStorage{Endpoint: storage.URL, Region: "us-east-1", Bucket: "backups", Prefix: "servers/vm", AccessKey: "key", SecretKey: "secret"},
	}

	tested, err := client.TestBackupStorage(timeout(t), &agentv1.TestBackupStorageRequest{Storage: plan.Storage})
	if err != nil || !tested.Ok {
		t.Fatalf("TestBackupStorage = %v, %v", tested, err)
	}

	put, err := client.PutBackupPlans(timeout(t), &agentv1.PutBackupPlansRequest{Plans: append(listed.Plans, plan), ExpectedRevision: listed.Revision})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.PutBackupPlans(context.Background(), &agentv1.PutBackupPlansRequest{Plans: listed.Plans, ExpectedRevision: put.Revision})
	})

	if !strings.Contains(sh(t, "/", "cat", "/etc/cron.d/serverdog-backups"), "0 3 * * * root /usr/local/bin/serverdog-agent run-backup "+plan.Id) {
		t.Error("cron doesn't run the plan")
	}

	// The first run through the agent, the second as cron starts it. Keep 1 leaves only the second.
	first := runBackupNow(t, client, plan.Id)
	time.Sleep(time.Second) // run folders are named to the second
	if output, err := exec.Command("/usr/local/bin/serverdog-agent", "run-backup", plan.Id).CombinedOutput(); err != nil {
		t.Fatalf("run-backup: %v\n%s", err, output)
	}

	plans, err := client.ListBackupPlans(timeout(t), &agentv1.ListBackupPlansRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var second *agentv1.BackupRun
	for _, p := range plans.Plans {
		if p.Id == plan.Id {
			second = p.Runs[0]
			if p.Storage.SecretKey != "" || !p.Storage.HasSecretKey {
				t.Error("the secret key left the server, or was lost")
			}
		}
	}
	if second == nil || second.State != "succeeded" || second.Id == first.Id || second.Size == 0 {
		t.Fatalf("second run = %v", second)
	}

	listedObjects, err := backend.ListBucket("backups", &gofakes3.Prefix{}, gofakes3.ListBucketPage{})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, object := range listedObjects.Contents {
		keys = append(keys, object.Key)
	}
	want := "servers/vm/" + plan.Id + "/" + second.Folder + "/" + name + ".sql.gz"
	if len(keys) != 1 || keys[0] != want {
		t.Fatalf("bucket = %v, want only %s", keys, want)
	}

	object, err := backend.GetObject("backups", want, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Contents.Close()
	unzipped, err := gzip.NewReader(object.Contents)
	if err != nil {
		t.Fatal(err)
	}
	dump, _ := io.ReadAll(unzipped)
	if !strings.Contains(string(dump), "remember "+name) {
		t.Errorf("the dump lacks the row:\n%.400s", dump)
	}
}

func runBackupNow(t *testing.T, client agentv1.BackupServiceClient, planID string) *agentv1.BackupRun {
	t.Helper()

	started, err := client.RunBackup(timeout(t), &agentv1.RunBackupRequest{PlanId: planID})
	if err != nil {
		t.Fatal(err)
	}

	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		plans, err := client.ListBackupPlans(timeout(t), &agentv1.ListBackupPlansRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range plans.Plans {
			if p.Id == planID && p.Runs[0].Id == started.Run.Id && p.Runs[0].State != "running" {
				if p.Runs[0].State != "succeeded" {
					t.Fatalf("run failed: %s", p.Runs[0].Error)
				}
				return p.Runs[0]
			}
		}
	}

	t.Fatal("the backup didn't finish within a minute")
	return nil
}
