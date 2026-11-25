package http01

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These integration tests pin the HTTP-01 challenge contract to the boundaries of a
// live ProviderServer. A presented challenge only exposes its (short-lived) key
// authorization on an exact token path + matching domain (RFC 8555, section 8.3);
// every other request must receive an ordinary HTTP error/body that contains no
// authorization material.
const (
	integrationTokenA = "integration-token-a"
	integrationTokenB = "integration-token-b"

	integrationKeyAuthA = "integration-token-a.very-secret-key-authorization-A"
	integrationKeyAuthB = "integration-token-b.very-secret-key-authorization-B"

	integrationDomainA = "challenge-a.example"
	integrationDomainB = "challenge-b.example"
)

// challengeServer bundles a presented ProviderServer with the arguments used to
// present it, so tests can drive both the HTTP surface and Present/CleanUp directly.
type challengeServer struct {
	server  *ProviderServer
	domain  string
	token   string
	keyAuth string

	// cleanup is idempotent: explicit test cleanups and the t.Cleanup hook share
	// the same sync.Once so a second call is a safe no-op instead of hanging.
	cleanup func() error
}

func newPresentedServer(t *testing.T, opts Options, domain, token, keyAuth string) *challengeServer {
	t.Helper()

	// Port 0 lets the kernel pick a free ephemeral port so parallel servers never
	// collide on a hard-coded port.
	if opts.Address == "" {
		opts.Address = "127.0.0.1:0"
	}

	srv := NewProviderServerWithOptions(opts)

	require.NoError(t, srv.Present(t.Context(), domain, token, keyAuth))

	instance := &challengeServer{
		server:  srv,
		domain:  domain,
		token:   token,
		keyAuth: keyAuth,
	}

	var cleanOnce sync.Once

	runCleanup := func() error {
		return srv.CleanUp(context.Background(), domain, token, keyAuth)
	}

	t.Cleanup(func() {
		cleanOnce.Do(func() { _ = runCleanup() })
	})

	instance.cleanup = func() error {
		var err error

		cleanOnce.Do(func() { err = runCleanup() })

		return err
	}

	return instance
}

func (s *challengeServer) baseURL(t *testing.T) string {
	t.Helper()

	require.NotNil(t, s.server.listener)

	return "http://" + s.server.listener.Addr().String()
}

func (s *challengeServer) challengeURL(t *testing.T) string {
	t.Helper()

	return s.baseURL(t) + ChallengePath(s.token)
}

// doChallengeRequest issues a request against the running challenge server.
// host overrides the HTTP Host header (empty keeps the dial address), while
// headers simulates proxy-forwarding headers such as X-Forwarded-Host.
func (s *challengeServer) doChallengeRequest(t *testing.T, method, requestPath, host string, headers map[string]string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, s.baseURL(t)+requestPath, nil)
	require.NoError(t, err)

	if host != "" {
		req.Host = host
	}

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return string(body)
}

// assertDoesNotLeakKeyAuth ensures a response never carries any presented key
// authorization, neither for this server's challenge nor for another one.
func assertDoesNotLeakKeyAuth(t *testing.T, body string, knownKeyAuths ...string) {
	t.Helper()

	for _, keyAuth := range knownKeyAuths {
		assert.NotContains(t, body, keyAuth)
	}
}

// TestHTTP01Challenge_ResponseBoundaries verifies that only the exact
// (domain, token) registration is served the key authorization, and that every
// unregistered or non-conforming request is answered without exposing it.
func TestHTTP01Challenge_ResponseBoundaries(t *testing.T) {
	t.Parallel()

	instance := newPresentedServer(t, Options{}, integrationDomainA, integrationTokenA, integrationKeyAuthA)

	t.Run("registered domain and token returns the key authorization", func(t *testing.T) {
		resp := instance.doChallengeRequest(t, http.MethodGet, ChallengePath(integrationTokenA), integrationDomainA, nil)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
		assert.Equal(t, integrationKeyAuthA, readResponseBody(t, resp))
	})

	t.Run("registered token but mismatched domain does not expose the key authorization", func(t *testing.T) {
		resp := instance.doChallengeRequest(t, http.MethodGet, ChallengePath(integrationTokenA), "unregistered.example", nil)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotEqual(t, "text/plain", resp.Header.Get("Content-Type"))

		body := readResponseBody(t, resp)
		assert.Equal(t, "TEST", body)
		assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
	})

	t.Run("unregistered token on the registered domain returns 404 without key authorization", func(t *testing.T) {
		resp := instance.doChallengeRequest(t, http.MethodGet, ChallengePath(integrationTokenB), integrationDomainA, nil)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		body := readResponseBody(t, resp)
		assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
	})

	t.Run("request outside the challenge path prefix returns 404 without key authorization", func(t *testing.T) {
		resp := instance.doChallengeRequest(t, http.MethodGet, "/admin/"+integrationTokenA, integrationDomainA, nil)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		body := readResponseBody(t, resp)
		assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
	})

	t.Run("non-GET method on the registered challenge does not expose the key authorization", func(t *testing.T) {
		resp := instance.doChallengeRequest(t, http.MethodPost, ChallengePath(integrationTokenA), integrationDomainA, nil)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotEqual(t, "text/plain", resp.Header.Get("Content-Type"))

		body := readResponseBody(t, resp)
		assert.Equal(t, "TEST", body)
		assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
	})

	t.Run("HEAD on the registered challenge has an empty body and no key authorization", func(t *testing.T) {
		resp := instance.doChallengeRequest(t, http.MethodHead, ChallengePath(integrationTokenA), integrationDomainA, nil)

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := readResponseBody(t, resp)
		assert.Empty(t, body)
		assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
	})

	t.Run("after cleanup the challenge endpoint stops serving the key authorization", func(t *testing.T) {
		require.NoError(t, instance.cleanup())

		_, err := http.Get(instance.challengeURL(t))
		require.Error(t, err)

		// The listener must be fully closed, i.e. nothing is listening anymore.
		_, dialErr := net.Dial("tcp", instance.server.listener.Addr().String())
		require.Error(t, dialErr)
	})
}

// TestHTTP01Challenge_ParallelPresentAndCleanup presents several challenges on
// independent servers at the same time and proves they are isolated: each server
// only answers for its own (domain, token), cross-talk is rejected, and cleaning
// one challenge up leaves the others untouched.
func TestHTTP01Challenge_ParallelPresentAndCleanup(t *testing.T) {
	t.Parallel()

	servers := []struct {
		domain  string
		token   string
		keyAuth string
	}{
		{domain: integrationDomainA, token: integrationTokenA, keyAuth: integrationKeyAuthA},
		{domain: integrationDomainB, token: integrationTokenB, keyAuth: integrationKeyAuthB},
	}

	instances := make([]*challengeServer, len(servers))

	var wg sync.WaitGroup

	for i, cfg := range servers {
		wg.Go(func() {
			instances[i] = newPresentedServer(t, Options{}, cfg.domain, cfg.token, cfg.keyAuth)
		})
	}

	wg.Wait()

	for i, instance := range instances {
		require.NotNil(t, instance)
		require.NotNil(t, instance.server.listener)

		cfg := servers[i]

		t.Run(cfg.domain+" serves its own key authorization", func(t *testing.T) {
			resp := instance.doChallengeRequest(t, http.MethodGet, ChallengePath(cfg.token), cfg.domain, nil)

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
			assert.Equal(t, cfg.keyAuth, readResponseBody(t, resp))
		})
	}

	t.Run("a registered token served with another domain is rejected by the matcher", func(t *testing.T) {
		// Server A's own token path, but presented with domain B's identity:
		// the path is registered so the handler runs, but the domain matcher
		// refuses to hand over A's key authorization.
		resp := instances[0].doChallengeRequest(t, http.MethodGet,
			ChallengePath(servers[0].token), servers[1].domain, nil)

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body := readResponseBody(t, resp)
		assert.Equal(t, "TEST", body)
		assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA, integrationKeyAuthB)
	})

	t.Run("a token presented on one server is unknown to the other server", func(t *testing.T) {
		resp := instances[1].doChallengeRequest(t, http.MethodGet, ChallengePath(servers[0].token), servers[0].domain, nil)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		body := readResponseBody(t, resp)
		assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA, integrationKeyAuthB)
	})

	t.Run("cleaning one challenge up leaves the other one serving", func(t *testing.T) {
		require.NoError(t, instances[0].cleanup())

		// The cleaned-up server refuses new connections.
		_, err := net.Dial("tcp", instances[0].server.listener.Addr().String())
		require.Error(t, err)

		// The second server still serves its own challenge.
		resp := instances[1].doChallengeRequest(t, http.MethodGet, ChallengePath(servers[1].token), servers[1].domain, nil)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, servers[1].keyAuth, readResponseBody(t, resp))
	})

	t.Run("parallel cleanup of the remaining challenge does not interfere", func(t *testing.T) {
		var cleanWG sync.WaitGroup

		for _, instance := range instances {
			cleanWG.Go(func() {
				_ = instance.cleanup()
			})
		}

		cleanWG.Wait()

		for _, instance := range instances {
			_, err := net.Dial("tcp", instance.server.listener.Addr().String())
			require.Error(t, err)
		}
	})
}

// TestHTTP01Challenge_ProxyForwardingIsolation verifies that, when the server
// runs behind a proxy and trusts a forwarding header, the same domain/token
// isolation holds: a matching forwarded identity is served, while a mismatched
// identity or an unregistered token reveals no key authorization.
func TestHTTP01Challenge_ProxyForwardingIsolation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		proxyName  string
		okHeader   map[string]string
		nookHeader map[string]string
	}{
		{
			name:      "X-Forwarded-Host",
			proxyName: "X-Forwarded-Host",
			okHeader: map[string]string{
				"X-Forwarded-Host": integrationDomainA,
			},
			nookHeader: map[string]string{
				"X-Forwarded-Host": "unregistered.example",
			},
		},
		{
			name:      "Forwarded",
			proxyName: "Forwarded",
			okHeader: map[string]string{
				"Forwarded": `for=192.0.2.10;host=` + integrationDomainA + `;proto=http`,
			},
			nookHeader: map[string]string{
				"Forwarded": `for=192.0.2.10;host=unregistered.example;proto=http`,
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			instance := newPresentedServer(t,
				Options{ProxyHeaderName: test.proxyName},
				integrationDomainA, integrationTokenA, integrationKeyAuthA)

			t.Run("matching forwarded identity returns the key authorization", func(t *testing.T) {
				resp := instance.doChallengeRequest(t, http.MethodGet,
					ChallengePath(integrationTokenA), "proxy.internal", test.okHeader)

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
				assert.Equal(t, integrationKeyAuthA, readResponseBody(t, resp))
			})

			t.Run("mismatched forwarded identity does not expose the key authorization", func(t *testing.T) {
				resp := instance.doChallengeRequest(t, http.MethodGet,
					ChallengePath(integrationTokenA), "proxy.internal", test.nookHeader)

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.NotEqual(t, "text/plain", resp.Header.Get("Content-Type"))

				body := readResponseBody(t, resp)
				assert.Equal(t, "TEST", body)
				assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
			})

			t.Run("unregistered token behind the proxy returns 404 without key authorization", func(t *testing.T) {
				resp := instance.doChallengeRequest(t, http.MethodGet,
					ChallengePath(integrationTokenB), "proxy.internal", test.okHeader)

				assert.Equal(t, http.StatusNotFound, resp.StatusCode)

				body := readResponseBody(t, resp)
				assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
			})

			t.Run("missing forwarding header does not expose the key authorization", func(t *testing.T) {
				resp := instance.doChallengeRequest(t, http.MethodGet,
					ChallengePath(integrationTokenA), "proxy.internal", nil)

				assert.Equal(t, http.StatusOK, resp.StatusCode)

				body := readResponseBody(t, resp)
				assertDoesNotLeakKeyAuth(t, body, integrationKeyAuthA)
			})
		})
	}
}
