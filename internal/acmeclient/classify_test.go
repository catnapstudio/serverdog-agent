package acmeclient

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
)

func TestClassifyRateLimits(t *testing.T) {
	limited := &acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, Detail: "too many certificates (50) already issued"}, RetryAfter: 2 * time.Hour}

	var wrapped error = limited

	failure := Classify(fmt.Errorf("obtain: %w", wrapped))
	if !failure.RateLimited || failure.RetryAfter != 2*time.Hour || !strings.HasPrefix(failure.Message, "Let's Encrypt's rate limit") || !strings.Contains(failure.Message, "\n\ntoo many certificates") {
		t.Errorf("failure = %+v", failure)
	}

	limited.RetryAfter = 0
	if failure := Classify(limited); failure.RetryAfter != time.Hour {
		t.Errorf("missing Retry-After became %v, want 1h", failure.RetryAfter)
	}
}

func TestClassifyProblems(t *testing.T) {
	cases := map[string]string{
		acme.CaaErrorType:                "CAA record",
		acme.ConnectionErrorType:         "port 80",
		acme.IncorrectResponseErrorType:  "port 80",
		acme.DNSErrorType:                "port 80",
		acme.RejectedIdentifierErrorType: "won't issue",
		acme.MalformedErrorType:          "refused the certificate",
	}

	for kind, want := range cases {
		failure := Classify(fmt.Errorf("wrapped: %w", &acme.ProblemDetails{Type: kind, Detail: "detail text"}))
		if !strings.Contains(failure.Message, want) || !strings.HasSuffix(failure.Message, "\n\ndetail text") || failure.RateLimited {
			t.Errorf("%s: %+v", kind, failure)
		}
	}
}

func TestClassifyReadsProblemTypesFromText(t *testing.T) {
	// Per-domain validation errors may reach us only as text.
	err := errors.New("error: one or more domains had a problem:\n[a.test] invalid authorization: acme: error: 400 :: urn:ietf:params:acme:error:connection :: Connection refused")

	if failure := Classify(err); !strings.Contains(failure.Message, "port 80") {
		t.Errorf("failure = %+v", failure)
	}
}

func TestClassifyAnythingElse(t *testing.T) {
	failure := Classify(errors.New("dial tcp: lookup acme-v02.api.letsencrypt.org: no such host"))
	if !strings.HasPrefix(failure.Message, "Couldn't reach Let's Encrypt.") || failure.RetryAfter != 0 {
		t.Errorf("failure = %+v", failure)
	}
}

func TestFallbackRenewsWithAThirdLeft(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * 24 * time.Hour)}

	if got := Fallback(leaf); !got.Equal(start.Add(60 * 24 * time.Hour)) {
		t.Errorf("fallback = %v", got)
	}
}

type domainsError map[string]error

func (d domainsError) Error() string { return "one or more domains had a problem" }

func (d domainsError) Unwrap() []error {
	errs := make([]error, 0, len(d))
	for _, err := range d {
		errs = append(errs, err)
	}

	return errs
}

func TestClassifyPicksTheMostActionableDomainProblem(t *testing.T) {
	for i := 0; i < 50; i++ {
		err := fmt.Errorf("obtain: %w", domainsError{
			"a.test":     &acme.ProblemDetails{Type: acme.ConnectionErrorType, Detail: "connection refused"},
			"www.a.test": &acme.ProblemDetails{Type: acme.CaaErrorType, Detail: "CAA forbids"},
			"b.test":     &acme.ProblemDetails{Type: acme.DNSErrorType, Detail: "no such host"},
		})

		failure := Classify(err)
		if !strings.Contains(failure.Message, "CAA record") || !strings.HasSuffix(failure.Message, "\n\nCAA forbids") {
			t.Fatalf("run %d: %+v", i, failure)
		}
	}
}

func TestClassifyUsesSubProblemTypes(t *testing.T) {
	problem := &acme.ProblemDetails{
		Type:   acme.CompoundErrorType,
		Detail: "multiple problems",
		SubProblems: []acme.SubProblem{
			{Type: acme.ConnectionErrorType},
			{Type: acme.CaaErrorType},
		},
	}

	if failure := Classify(problem); !strings.Contains(failure.Message, "CAA record") {
		t.Errorf("failure = %+v", failure)
	}
}

func TestClassifyFindsRateLimitsAmongDomainProblems(t *testing.T) {
	err := domainsError{
		"a.test": &acme.ProblemDetails{Type: acme.CaaErrorType, Detail: "CAA forbids"},
		"b.test": &acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, Detail: "slow down"}, RetryAfter: 3 * time.Hour},
	}

	if failure := Classify(err); !failure.RateLimited || failure.RetryAfter != 3*time.Hour {
		t.Errorf("failure = %+v", failure)
	}
}

func TestClassifyReadsRateLimitsFromText(t *testing.T) {
	err := errors.New("error: one or more domains had a problem:\n[a.test] acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many certificates")

	failure := Classify(err)
	if !failure.RateLimited || failure.RetryAfter != time.Hour || !strings.HasPrefix(failure.Message, "Let's Encrypt's rate limit") {
		t.Errorf("failure = %+v", failure)
	}
}

func TestClassifyTextPrefersCaa(t *testing.T) {
	text := "[a.test] urn:ietf:params:acme:error:connection :: refused\n[www.a.test] urn:ietf:params:acme:error:caa :: forbidden"

	for i := 0; i < 50; i++ {
		if failure := Classify(errors.New(text)); !strings.Contains(failure.Message, "CAA record") {
			t.Fatalf("run %d: %+v", i, failure)
		}
	}
}
