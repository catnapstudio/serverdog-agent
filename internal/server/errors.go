package server

import (
	"context"
	"errors"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/daemons"
	"github.com/catnapstudio/serverdog-agent/internal/databases"
	"github.com/catnapstudio/serverdog-agent/internal/deploy"
	"github.com/catnapstudio/serverdog-agent/internal/deployscript"
	"github.com/catnapstudio/serverdog-agent/internal/frankenphp"
	"github.com/catnapstudio/serverdog-agent/internal/insights"
	"github.com/catnapstudio/serverdog-agent/internal/logs"
	"github.com/catnapstudio/serverdog-agent/internal/network"
	"github.com/catnapstudio/serverdog-agent/internal/phpversions"
	"github.com/catnapstudio/serverdog-agent/internal/servicectl"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/sites"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// toStatus maps errors to gRPC statuses. Messages follow the protocol convention: a one-sentence summary,
// then a blank line and the detail (a tool's output) when there is one.
func toStatus(err error) error {
	if err == nil {
		return nil
	}

	var invalid *site.InvalidError
	var scriptErr *deployscript.Error
	var taken *state.DomainTakenError
	var applyErr *apply.Error
	var exists *databases.ExistsError
	var databaseErr *databases.Error
	var phpErr *phpversions.Error
	var networkErr *network.Error
	var serviceErr *servicectl.Error

	switch {
	case errors.As(err, &invalid):
		return status.Error(codes.InvalidArgument, text(invalid.Reason))
	case errors.As(err, &scriptErr):
		return status.Error(codes.InvalidArgument, scriptErr.Error())
	case errors.As(err, &taken):
		return status.Errorf(codes.AlreadyExists, "%s already belongs to another site on this server.", taken.Name)
	// A cancel is checked before the database errors: a client killed by the cancel failed, but not on its own.
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "The request was cancelled.")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "The request took too long.")
	case errors.As(err, &exists):
		return status.Error(codes.AlreadyExists, exists.Error())
	case errors.As(err, &databaseErr):
		return status.Error(codes.Internal, text(databaseErr.Error()))
	case errors.As(err, &phpErr):
		return status.Error(codes.Internal, text(phpErr.Error()))
	case errors.As(err, &networkErr):
		return status.Error(codes.Internal, text(networkErr.Error()))
	case errors.As(err, &serviceErr):
		return status.Error(codes.Internal, text(serviceErr.Error()))
	case errors.Is(err, state.ErrNotFound):
		return status.Error(codes.NotFound, "That site, deployment or certificate doesn't exist on this server.")
	case errors.Is(err, state.ErrStaleRevision):
		return status.Error(codes.FailedPrecondition, "The site changed on the server since you opened it. Reload it and try again.")
	case errors.Is(err, logs.ErrUnknownSource):
		return status.Error(codes.NotFound, "That log isn't on this server.")
	case errors.Is(err, state.ErrStaleDocument):
		return status.Error(codes.FailedPrecondition, "The list changed on the server since you opened it. Reload it and try again.")
	case errors.Is(err, sites.ErrStaleContent):
		return status.Error(codes.FailedPrecondition, "The file changed on the server since you opened it. Reload it and try again.")
	case errors.Is(err, state.ErrDeployRunning):
		return status.Error(codes.FailedPrecondition, "A deploy is running for this site. Wait for it to finish or cancel it.")
	case errors.Is(err, deploy.ErrNoRepository):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, insights.ErrGone):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, new(*insights.Error)):
		return status.Error(codes.Internal, text(err.Error()))
	case errors.As(err, new(*frankenphp.DownloadError)):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, sites.ErrNoHostKey), errors.Is(err, sites.ErrHostKeyMoved), errors.Is(err, sites.ErrProcessStopped), errors.Is(err, daemons.ErrStopped):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &applyErr):
		return status.Error(codes.FailedPrecondition, applyErr.Error())
	default:
		return status.Error(codes.Internal, "Something went wrong on the server.\n\n"+text(err.Error()))
	}
}
