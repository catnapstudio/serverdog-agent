//go:build vmtest

package integration

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
)

func TestAScheduledJobRunsAndItsOutputIsListed(t *testing.T) {
	server := agentv1.NewServerServiceClient(conn)
	listed, err := server.ListScheduledJobs(timeout(t), &agentv1.ListScheduledJobsRequest{})
	if err != nil {
		t.Fatal(err)
	}

	job := &agentv1.ScheduledJob{Id: ids.New(), Name: "Hello", Command: `echo "hello from $(whoami) at $(date +%H:%M)"`, User: "serverdog", Schedule: "* * * * *"}
	put, err := server.PutScheduledJobs(timeout(t), &agentv1.PutScheduledJobsRequest{Jobs: append(listed.Jobs, job), ExpectedRevision: listed.Revision})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.PutScheduledJobs(timeout(t), &agentv1.PutScheduledJobsRequest{Jobs: listed.Jobs, ExpectedRevision: put.Revision})
	})

	// cron runs it at the start of the next minute.
	var log string
	for deadline := time.Now().Add(80 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		response, err := server.ListScheduledJobs(timeout(t), &agentv1.ListScheduledJobsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, j := range response.Jobs {
			if j.Id == job.Id {
				log = j.Log
			}
		}
		if strings.Contains(log, "hello from serverdog at ") {
			return
		}
	}

	t.Fatalf("the job didn't run within a minute; log = %q", log)
}
