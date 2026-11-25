package nonces

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/go-acme/lego/v5/acme/api/internal/sender"
	"github.com/go-jose/go-jose/v4"
)

// Manager Manages nonces.
type Manager struct {
	sync.Mutex

	do       *sender.Doer
	nonceURL string
	nonces   []string
}

// NewManager Creates a new Manager.
func NewManager(do *sender.Doer, nonceURL string) *Manager {
	return &Manager{
		do:       do,
		nonceURL: nonceURL,
	}
}

// Push Pushes nonce.
func (n *Manager) Push(nonce string) {
	n.Lock()
	defer n.Unlock()

	n.nonces = append(n.nonces, nonce)
}

// Pop Pops a nonce.
func (n *Manager) Pop() (string, bool) {
	n.Lock()
	defer n.Unlock()

	if len(n.nonces) == 0 {
		return "", false
	}

	nonce := n.nonces[len(n.nonces)-1]
	n.nonces = n.nonces[:len(n.nonces)-1]

	return nonce, true
}

// Nonce returns a nonce from the shared pool or requests a new one from the
// ACME server.
func (n *Manager) Nonce() (string, error) {
	return n.getNonce(context.Background())
}

func (n *Manager) getNonce(ctx context.Context) (string, error) {
	if nonce, ok := n.Pop(); ok {
		return nonce, nil
	}

	resp, err := n.do.Head(ctx, n.nonceURL)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce from HTTP HEAD: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	return GetFromResponse(resp)
}

// GetFromResponse Extracts nonce from an HTTP response.
func GetFromResponse(resp *http.Response) (string, error) {
	if resp == nil {
		return "", errors.New("nil response")
	}

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", errors.New("server did not respond with a proper nonce header")
	}

	return nonce, nil
}

func (n *Manager) NewNonceSource(ctx context.Context) *NonceSource {
	return NewNonceSource(ctx, n)
}

var (
	_ jose.NonceSource = (*NonceSource)(nil)
	_ io.Closer        = (*NonceSource)(nil)
)

// NonceSource implements [jose.NonceSource].
//
// A source can be scoped to a single logical POST and reused by that request's
// retries. Nonces pushed to the source stay with that request until they are
// consumed or flushed back to the shared [Manager]. This prevents concurrent
// requests from taking a nonce issued for another request's retry.
//
//nolint:containedctx // This is the only way to use the context in this case.
type NonceSource struct {
	ctx context.Context
	m   *Manager

	mu     sync.Mutex
	nonces []string
}

// NewNonceSource Creates a new NonceSource.
func NewNonceSource(ctx context.Context, manager *Manager) *NonceSource {
	return &NonceSource{ctx: ctx, m: manager}
}

// Push stores a nonce in this source.
//
// The nonce is consumed at most once by a later call to [NonceSource.Nonce].
// Unconsumed nonces can be returned to the shared manager with
// [NonceSource.Flush].
func (n *NonceSource) Push(nonce string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.nonces = append(n.nonces, nonce)
}

// Pop removes and returns the most recently stored source-local nonce.
func (n *NonceSource) Pop() (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(n.nonces) == 0 {
		return "", false
	}

	nonce := n.nonces[len(n.nonces)-1]
	n.nonces = n.nonces[:len(n.nonces)-1]

	return nonce, true
}

// Flush returns all unconsumed source-local nonces to the shared manager pool.
func (n *NonceSource) Flush() {
	n.mu.Lock()
	nonces := n.nonces
	n.nonces = nil
	n.mu.Unlock()

	for _, nonce := range nonces {
		n.m.Push(nonce)
	}
}

// Release is an alias for [NonceSource.Flush].
func (n *NonceSource) Release() {
	n.Flush()
}

// Close implements [io.Closer] and returns unconsumed nonces to the manager.
func (n *NonceSource) Close() error {
	n.Flush()
	return nil
}

func (n *NonceSource) Nonce() (string, error) {
	if nonce, ok := n.Pop(); ok {
		return nonce, nil
	}

	return n.m.getNonce(n.ctx)
}
