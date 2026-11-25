package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/internal/tester/servermock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestCSR creates a parsed certificate request for the given domains.
func buildTestCSR(t *testing.T, key *rsa.PrivateKey, domains []string) *x509.CertificateRequest {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)

	return csr
}

// buildPEMLeaf builds a self-signed leaf certificate PEM for the given key and domains.
func buildPEMLeaf(t *testing.T, leafKey, issuerKey *rsa.PrivateKey, domains []string) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     domains,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, leafKey.Public(), issuerKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestCertifier_getForCSR_rejectsTamperedOrder verifies that an order whose
// identifiers are changed by the server during finalization is rejected:
// the updated order must stay bound to the original application.
func TestCertifier_getForCSR_rejectsTamperedOrder(t *testing.T) {
	server := tester.MockACMEServer().
		Route("POST /finalize",
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// The server answers with a different set of identifiers
				// than the ones of the original order.
				servermock.JSONEncode(acme.Order{
					Status:      acme.StatusReady,
					Identifiers: []acme.Identifier{{Type: "dns", Value: "evil.example.org"}},
				}).ServeHTTP(rw, req)
			}),
		).
		BuildHTTPS(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{Timeout: time.Second})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Finalize:    server.URL + "/finalize",
			Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		},
		Location: server.URL + "/order",
	}

	csr := buildTestCSR(t, key, []string{"example.com"})

	cert, err := certifier.getForCSR(t.Context(), &Resource{}, order, csr, false, "")

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "identifiers have been modified")
}

// TestCertifier_getForCSR_rejectsMismatchedCertificate verifies that a
// certificate whose public key does not match the submitted CSR is rejected,
// and that no reusable certificate resource is returned.
func TestCertifier_getForCSR_rejectsMismatchedCertificate(t *testing.T) {
	requestKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// The server "issues" a certificate bound to a foreign key pair.
	foreignCertPEM := buildPEMLeaf(t, foreignKey, foreignKey, []string{"example.com"})

	server := tester.MockACMEServer().
		Route("POST /finalize",
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				servermock.JSONEncode(acme.Order{
					Status:      acme.StatusProcessing,
					Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
				}).ServeHTTP(rw, req)
			}),
		).
		Route("POST /order", http.HandlerFunc(
			func(rw http.ResponseWriter, req *http.Request) {
				order := acme.Order{
					Status:      acme.StatusValid,
					Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
					Certificate: fmt.Sprintf("https://%s/certificate", req.Host),
				}

				servermock.JSONEncode(order).ServeHTTP(rw, req)
			}),
		).
		Route("POST /certificate", servermock.RawStringResponse(string(foreignCertPEM))).
		BuildHTTPS(t)

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", requestKey)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{Timeout: 5 * time.Second})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Finalize:    server.URL + "/finalize",
			Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		},
		Location: server.URL + "/order",
	}

	csr := buildTestCSR(t, requestKey, []string{"example.com"})

	certRes := &Resource{}

	cert, err := certifier.getForCSR(t.Context(), certRes, order, csr, false, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not bound to the original certificate request")
	assert.Nil(t, cert)
	// The half-finished resource must not carry any reusable certificate.
	assert.Empty(t, certRes.Certificate)
	assert.Empty(t, certRes.CertURL)
}

// TestCertifier_getForCSR_acceptsMatchingCertificate verifies the happy path:
// when the issued certificate matches the CSR key and identifiers,
// a valid resource with the expected certificate chain is returned.
func TestCertifier_getForCSR_acceptsMatchingCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	matchingCertPEM := buildPEMLeaf(t, key, key, []string{"example.com"})

	server := tester.MockACMEServer().
		Route("POST /finalize",
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				servermock.JSONEncode(acme.Order{
					Status:      acme.StatusValid,
					Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
					Certificate: fmt.Sprintf("https://%s/certificate", req.Host),
				}).ServeHTTP(rw, req)
			}),
		).
		Route("POST /certificate", servermock.RawStringResponse(string(matchingCertPEM))).
		BuildHTTPS(t)

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{Timeout: 5 * time.Second})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Finalize:    server.URL + "/finalize",
			Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		},
		Location: server.URL + "/order",
	}

	csr := buildTestCSR(t, key, []string{"example.com"})

	cert, err := certifier.getForCSR(t.Context(), &Resource{}, order, csr, false, "")

	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, matchingCertPEM, cert.Certificate)
	assert.Contains(t, cert.CertURL, "/certificate")
}

// TestCertifier_getForCSR_retryAfterCannotExceedCallerDeadline verifies that a
// large server-suggested Retry-After can never make the call exceed the
// caller-supplied context deadline: the function must return promptly with a
// deadline error rather than sleeping for the suggested duration.
func TestCertifier_getForCSR_retryAfterCannotExceedCallerDeadline(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := tester.MockACMEServer().
		Route("POST /finalize",
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				// The server asks to wait one hour, which the client must not honor
				// beyond the caller's much shorter deadline.
				rw.Header().Set("Retry-After", "3600")

				servermock.JSONEncode(acme.Order{
					Status:      acme.StatusProcessing,
					Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
				}).ServeHTTP(rw, req)
			}),
		).
		BuildHTTPS(t)

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{Timeout: time.Hour})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Finalize:    server.URL + "/finalize",
			Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		},
		Location: server.URL + "/order",
	}

	csr := buildTestCSR(t, key, []string{"example.com"})

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()

	_, err = certifier.getForCSR(ctx, &Resource{}, order, csr, false, "")

	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	// The one-hour Retry-After must never be applied: the call returns close
	// to the caller's 100ms deadline, well under the suggested hour.
	assert.Less(t, elapsed, time.Second)
}
