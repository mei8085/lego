package challenge

import (
	"context"
	"time"
)

// Provider enables implementing a custom challenge
// provider. Present presents the solution to a challenge available to
// be solved. CleanUp will be called by the challenge if Present ends
// in a non-error state.
//
// For DNS-01, Present and CleanUp identify this authorization by the
// (domain, token, keyAuth) tuple. Several authorizations can share the same
// validation name, so CleanUp must remove only the TXT value derived from
// keyAuth and leave other TXT values on that name untouched.
type Provider interface {
	Present(ctx context.Context, domain, token, keyAuth string) error
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
}

// ProviderTimeout allows for implementing a
// Provider where an unusually long timeout is required when
// waiting for an ACME challenge to be satisfied, such as when
// checking for DNS record propagation. If an implementor of a
// Provider provides a Timeout method, then the return values
// of the Timeout method will be used when appropriate by the acme
// package. The interval value is the time between checks.
//
// The default values used for timeout and interval are 60 seconds and
// 2 seconds respectively. These are used when no Timeout method is
// defined for the Provider.
type ProviderTimeout interface {
	Provider
	Timeout() (timeout, interval time.Duration)
}

// PersistentProvider enables implementing a custom challenge provider of DNS-PERSISTENT-01.
// IMPORTANT: this interface is experimental and may change without notice.
type PersistentProvider interface {
	Persist(ctx context.Context, fqdn, value string) error
	Timeout() (timeout, interval time.Duration)
}
