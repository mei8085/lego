package certificate

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
)

// checkCertificateIdentity verifies that the issued leaf certificate is bound
// to the original certificate application:
//   - its public key MUST be the public key of the submitted CSR, so a certificate
//     issued for another order/key pair cannot be substituted;
//   - its identifiers (DNS names and IP addresses) MUST be exactly the identifiers
//     contained in the CSR, so a server cannot return a certificate for a different
//     set of domains than the ones that were authorized and requested.
//
// A mismatch makes the whole obtain flow fail: no certificate resource is
// returned, so a half-finished or mismatched certificate can never be reused
// by the caller.
func checkCertificateIdentity(leaf *x509.Certificate, csr *x509.CertificateRequest) error {
	if !publicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		return fmt.Errorf("the public key of the issued certificate does not match the certificate request")
	}

	expected := certificateRequestIdentifiers(csr)
	actual := certificateIdentifiers(leaf)

	if len(expected) != len(actual) {
		return fmt.Errorf("the identifiers of the issued certificate do not match the certificate request: %v != %v",
			actual, expected)
	}

	for _, identifier := range expected {
		if !slices.Contains(actual, identifier) {
			return fmt.Errorf("the identifiers of the issued certificate do not match the certificate request: %v != %v",
				actual, expected)
		}
	}

	return nil
}

// certificateRequestIdentifiers returns the DNS and IP identifiers carried by
// the SAN extension of a certificate request.
// The Subject CommonName is not used on its own: Go's x509 parsing mirrors a
// DNS/IP CommonName into DNSNames/IPAddresses, which is also what the CA signs.
func certificateRequestIdentifiers(csr *x509.CertificateRequest) []string {
	return collectIdentifiers(csr.DNSNames, csr.IPAddresses)
}

// certificateIdentifiers returns the DNS and IP identifiers carried by the SAN
// extension of an issued certificate.
func certificateIdentifiers(cert *x509.Certificate) []string {
	return collectIdentifiers(cert.DNSNames, cert.IPAddresses)
}

func collectIdentifiers(dnsNames []string, ipAddresses []net.IP) []string {
	identifiers := make([]string, 0, len(dnsNames)+len(ipAddresses))

	for _, dnsName := range dnsNames {
		if !slices.Contains(identifiers, dnsName) {
			identifiers = append(identifiers, dnsName)
		}
	}

	for _, ip := range ipAddresses {
		value := ip.String()
		if !slices.Contains(identifiers, value) {
			identifiers = append(identifiers, value)
		}
	}

	slices.Sort(identifiers)

	return identifiers
}

// publicKeysEqual reports whether two public keys are identical.
// The canonical PKIX (SPKI) DER encoding is compared, which gives a
// type-agnostic, deterministic comparison for every key type supported
// by x509 (RSA, ECDSA, Ed25519, ML-DSA, ...).
func publicKeysEqual(a, b any) bool {
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}

	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}

	return bytes.Equal(aDER, bDER)
}
