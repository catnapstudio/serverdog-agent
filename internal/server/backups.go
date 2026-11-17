package server

import (
	"context"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/backups"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

type backupService struct {
	agentv1.UnimplementedBackupServiceServer
	*Services
}

func (s backupService) ListBackupPlans(_ context.Context, request *agentv1.ListBackupPlansRequest) (*agentv1.ListBackupPlansResponse, error) {
	plans, revision, err := s.Backups.List()
	if err != nil {
		return nil, toStatus(err)
	}

	response := &agentv1.ListBackupPlansResponse{Revision: revision}
	for _, plan := range plans {
		runs, err := s.Store.ListBackupRuns(plan.ID, limit(request.RunLimit, 10, 100))
		if err != nil {
			return nil, toStatus(err)
		}

		p := toBackupPlan(plan)
		for _, run := range runs {
			p.Runs = append(p.Runs, toBackupRun(run))
		}
		response.Plans = append(response.Plans, p)
	}

	return response, nil
}

func (s backupService) PutBackupPlans(ctx context.Context, request *agentv1.PutBackupPlansRequest) (*agentv1.PutBackupPlansResponse, error) {
	plans := make([]backups.Plan, 0, len(request.Plans))
	for _, p := range request.Plans {
		plans = append(plans, backups.Plan{ID: p.Id, Name: p.Name, Databases: p.Databases, Schedule: p.Schedule, Keep: int(p.Keep), Storage: fromBackupStorage(p.Storage)})
	}

	revision, err := s.Backups.Put(ctx, plans, request.ExpectedRevision)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.PutBackupPlansResponse{Revision: revision}, nil
}

func (s backupService) TestBackupStorage(ctx context.Context, request *agentv1.TestBackupStorageRequest) (*agentv1.TestBackupStorageResponse, error) {
	storage := fromBackupStorage(request.Storage)
	if storage.SecretKey == "" && request.PlanId != "" {
		if plan, err := s.Backups.Get(request.PlanId); err == nil {
			storage.SecretKey = plan.Storage.SecretKey
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := backups.Test(ctx, storage); err != nil {
		return &agentv1.TestBackupStorageResponse{Error: err.Error()}, nil
	}

	return &agentv1.TestBackupStorageResponse{Ok: true}, nil
}

func (s backupService) RunBackup(_ context.Context, request *agentv1.RunBackupRequest) (*agentv1.RunBackupResponse, error) {
	if err := checkID(request.PlanId); err != nil {
		return nil, err
	}

	run, err := s.BackupRunner.Start(request.PlanId)
	if err != nil {
		return nil, toStatus(err)
	}

	return &agentv1.RunBackupResponse{Run: toBackupRun(run)}, nil
}

// toBackupPlan leaves the secret key out: it never leaves the server.
func toBackupPlan(plan backups.Plan) *agentv1.BackupPlan {
	return &agentv1.BackupPlan{
		Id: plan.ID, Name: plan.Name, Databases: plan.Databases, Schedule: plan.Schedule, Keep: uint32(plan.Keep),
		Storage: &agentv1.BackupStorage{
			Endpoint: plan.Storage.Endpoint, Region: plan.Storage.Region, Bucket: plan.Storage.Bucket, Prefix: plan.Storage.Prefix,
			AccessKey: plan.Storage.AccessKey, HasSecretKey: plan.Storage.SecretKey != "",
		},
	}
}

func fromBackupStorage(s *agentv1.BackupStorage) backups.Storage {
	if s == nil {
		return backups.Storage{}
	}

	return backups.Storage{Endpoint: s.Endpoint, Region: s.Region, Bucket: s.Bucket, Prefix: s.Prefix, AccessKey: s.AccessKey, SecretKey: s.SecretKey}
}

func toBackupRun(run state.BackupRun) *agentv1.BackupRun {
	r := &agentv1.BackupRun{Id: run.ID, State: run.State, StartedAt: run.StartedAt.UTC().Format(time.RFC3339), Folder: run.Folder, Size: run.Size, Error: run.Error}
	if !run.FinishedAt.IsZero() {
		r.FinishedAt = run.FinishedAt.UTC().Format(time.RFC3339)
	}

	return r
}
