package acmeclient

import (
	"strings"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

// Failure is an ACME error turned into what the person needs: a message (summary, blank line, detail) and when to retry.
type Failure struct {
	Message     string
	RateLimited bool
	// RetryAfter is the server's wait for rate limits; zero means the caller's backoff decides.
	RetryAfter time.Duration
}

const validation = "Let's Encrypt couldn't verify the domain. Check that port 80 is open and that the domain points at this server."

var summaries = map[string]string{
	acme.CaaErrorType:                "A CAA record on the domain doesn't allow Let's Encrypt. Add one that does, for example: CAA 0 issue \"letsencrypt.org\".",
	acme.ConnectionErrorType:         validation,
	acme.IncorrectResponseErrorType:  validation,
	acme.DNSErrorType:                validation,
	acme.UnauthorizedErrorType:       validation,
	acme.RejectedIdentifierErrorType: "Let's Encrypt won't issue certificates for this name.",
}

// priority orders the problem types that win when several names fail differently: the most actionable first.
var priority = []string{
	acme.CaaErrorType,
	acme.RejectedIdentifierErrorType,
	acme.ConnectionErrorType,
	acme.IncorrectResponseErrorType,
	acme.DNSErrorType,
	acme.UnauthorizedErrorType,
}

const rateLimitSummary = "Let's Encrypt's rate limit for this domain was reached.\n\n"

func Classify(err error) Failure {
	limits, problems := collect(err)

	if len(limits) > 0 {
		longest := limits[0]
		for _, limited := range limits[1:] {
			if limited.RetryAfter > longest.RetryAfter {
				longest = limited
			}
		}

		return Failure{RateLimited: true, RetryAfter: retryAfter(longest.RetryAfter), Message: rateLimitSummary + detail(longest.ProblemDetails, err)}
	}

	if len(problems) > 0 {
		best, kind := mostActionable(problems)

		return Failure{Message: summary(kind) + "\n\n" + detail(best, err)}
	}

	// Errors that were flattened into text still carry the problem types.
	text := err.Error()
	if strings.Contains(text, acme.RateLimitedErrorType) {
		return Failure{RateLimited: true, RetryAfter: time.Hour, Message: rateLimitSummary + text}
	}

	for _, kind := range priority {
		if strings.Contains(text, kind) {
			return Failure{Message: summaries[kind] + "\n\n" + text}
		}
	}

	return Failure{Message: "Couldn't reach Let's Encrypt.\n\n" + text}
}

// collect walks the whole error tree, including the per-domain errors lego joins into one.
func collect(err error) (limits []*acme.RateLimitedError, problems []*acme.ProblemDetails) {
	if err == nil {
		return nil, nil
	}

	switch typed := err.(type) {
	case *acme.RateLimitedError:
		limits = append(limits, typed)
	case *acme.ProblemDetails:
		problems = append(problems, typed)
	}

	var children []error
	switch wrapper := err.(type) {
	case interface{ Unwrap() error }:
		children = []error{wrapper.Unwrap()}
	case interface{ Unwrap() []error }:
		children = wrapper.Unwrap()
	}

	for _, child := range children {
		childLimits, childProblems := collect(child)
		limits = append(limits, childLimits...)
		problems = append(problems, childProblems...)
	}

	return limits, problems
}

// mostActionable picks the problem and problem type to report, the same way on every run.
func mostActionable(problems []*acme.ProblemDetails) (*acme.ProblemDetails, string) {
	var best *acme.ProblemDetails
	bestKind := ""
	bestRank := len(priority) + 1

	for _, problem := range problems {
		kinds := []string{problem.Type}
		for _, sub := range problem.SubProblems {
			kinds = append(kinds, sub.Type)
		}

		for _, kind := range kinds {
			rank := rankOf(kind)
			if best != nil && rank > bestRank {
				continue
			}
			if best != nil && rank == bestRank && (kind > bestKind || (kind == bestKind && problem.Detail >= best.Detail)) {
				continue
			}

			best, bestKind, bestRank = problem, kind, rank
		}
	}

	return best, bestKind
}

func rankOf(kind string) int {
	for rank, known := range priority {
		if known == kind {
			return rank
		}
	}

	return len(priority)
}

func retryAfter(wait time.Duration) time.Duration {
	if wait <= 0 {
		return time.Hour
	}

	return wait
}

func summary(kind string) string {
	if text, ok := summaries[kind]; ok {
		return text
	}

	return "Let's Encrypt refused the certificate."
}

func detail(problem *acme.ProblemDetails, err error) string {
	if problem != nil && problem.Detail != "" {
		return problem.Detail
	}

	return err.Error()
}
