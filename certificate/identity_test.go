package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckCertificateIdentity_matches(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com", "www.example.com"},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	leaf := generateLeafCertificate(t, key, key, []string{"example.com", "www.example.com"}, nil)

	require.NoError(t, checkCertificateIdentity(leaf, csr))
}

func TestCheckCertificateIdentity_rejectsForeignPublicKey(t *testing.T) {
	t.Parallel()

	csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}, csrKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// The leaf carries a different key pair: it cannot belong to this request.
	leaf := generateLeafCertificate(t, otherKey, otherKey, []string{"example.com"}, nil)

	err = checkCertificateIdentity(leaf, csr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key")
}

func TestCheckCertificateIdentity_rejectsDifferentIdentifiers(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// Same key, but the server issued the certificate for a different domain.
	leaf := generateLeafCertificate(t, key, key, []string{"evil.example.org"}, nil)

	err = checkCertificateIdentity(leaf, csr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identifiers")
}

func TestCheckCertificateIdentity_rejectsAdditionalIdentifier(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// The certificate contains every requested name plus an extra, unauthorized one.
	leaf := generateLeafCertificate(t, key, key, []string{"example.com", "extra.example.net"}, nil)

	err = checkCertificateIdentity(leaf, csr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identifiers")
}

func TestCheckCertificateIdentity_ipAddresses(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	leaf := generateLeafCertificate(t, key, key, nil, []net.IP{net.ParseIP("10.0.0.1")})

	require.NoError(t, checkCertificateIdentity(leaf, csr))
}

// generateLeafCertificate builds a self-signed leaf certificate usable in tests.
// The leaf public key comes from leafKey; issuerKey signs the certificate.
func generateLeafCertificate(t *testing.T, leafKey, issuerKey *rsa.PrivateKey, dnsNames []string, ipAddresses []net.IP) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, leafKey.Public(), issuerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}
