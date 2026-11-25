package api

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/internal/tester/servermock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrderService_UpdateForCSR_preservesIdentifiers(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	expected := []acme.Identifier{{Type: "dns", Value: "example.com"}}

	server := tester.MockACMEServer().
		Route("POST /finalize",
			servermock.JSONEncode(acme.Order{
				Status:      acme.StatusProcessing,
				Identifiers: expected,
			})).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	order, err := core.Orders.UpdateForCSR(t.Context(), server.URL+"/finalize", []byte("csr"), expected)
	require.NoError(t, err)

	assert.Equal(t, expected, order.Identifiers)
	// The location must be retained so later polls always target this order.
	assert.Equal(t, server.URL+"/finalize", order.Location)
}

func TestOrderService_UpdateForCSR_rejectsModifiedIdentifiers(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	original := []acme.Identifier{{Type: "dns", Value: "example.com"}}

	server := tester.MockACMEServer().
		Route("POST /finalize",
			servermock.JSONEncode(acme.Order{
				Status:      acme.StatusProcessing,
				Identifiers: []acme.Identifier{{Type: "dns", Value: "evil.example.org"}},
			})).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	_, err = core.Orders.UpdateForCSR(t.Context(), server.URL+"/finalize", []byte("csr"), original)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identifiers have been modified")
}

func TestOrderService_UpdateForCSR_invalidStatus(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	identifiers := []acme.Identifier{{Type: "dns", Value: "example.com"}}

	server := tester.MockACMEServer().
		Route("POST /finalize",
			servermock.JSONEncode(acme.Order{
				Status:      acme.StatusInvalid,
				Identifiers: identifiers,
				Error:       &acme.ProblemDetails{Detail: "boom"},
			})).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	_, err = core.Orders.UpdateForCSR(t.Context(), server.URL+"/finalize", []byte("csr"), identifiers)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid order")
}
