package api

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api/internal/nonces"
	"github.com/go-acme/lego/v5/acme/api/internal/secure"
	"github.com/go-acme/lego/v5/acme/api/internal/sender"
	"github.com/go-acme/lego/v5/internal/wait"
)

type service struct {
	core *Core
}

// Core ACME/LE core API.
type Core struct {
	doer         *sender.Doer
	nonceManager *nonces.Manager
	directory    acme.Directory

	HTTPClient *http.Client

	privateKey crypto.Signer
	kid        string
	mu         sync.RWMutex

	common         service // Reuse a single struct instead of allocating one for each service on the heap.
	Accounts       *AccountService
	Authorizations *AuthorizationService
	Certificates   *CertificateService
	Challenges     *ChallengeService
	Orders         *OrderService
}

// New Creates a new Core.
func New(httpClient *http.Client, userAgent, caDirURL, kid string, privateKey crypto.Signer) (*Core, error) {
	doer := sender.NewDoer(httpClient, userAgent)

	// NOTE(ldez) add context as a parameter of the constructor?
	dir, err := getDirectory(context.Background(), doer, caDirURL)
	if err != nil {
		return nil, err
	}

	return newCore(httpClient, doer, dir, kid, privateKey)
}

func newCore(httpClient *http.Client, doer *sender.Doer, dir acme.Directory, kid string, privateKey crypto.Signer) (*Core, error) {
	nonceManager := nonces.NewManager(doer, dir.NewNonceURL)

	c := &Core{
		doer:         doer,
		nonceManager: nonceManager,
		directory:    dir,

		privateKey: privateKey,
		kid:        kid,

		// NOTE(ldez): use the doer instead of the HTTP client? (only related to OCSP)
		HTTPClient: httpClient,
	}

	c.common.core = c
	c.Accounts = (*AccountService)(&c.common)
	c.Authorizations = (*AuthorizationService)(&c.common)
	c.Certificates = (*CertificateService)(&c.common)
	c.Challenges = (*ChallengeService)(&c.common)
	c.Orders = (*OrderService)(&c.common)

	return c, nil
}

// GetKeyAuthorization Gets the key authorization.
func (a *Core) GetKeyAuthorization(token string) (string, error) {
	return a.signer().GetKeyAuthorization(token)
}

// GetKID gets Key identifier (account URI).
func (a *Core) GetKID() string {
	return a.kid
}

// GetDirectory gets the ACME server directory.
func (a *Core) GetDirectory() acme.Directory {
	return a.directory
}

func (a *Core) signer() *secure.Signer {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return secure.NewSigner(a.privateKey, a.kid)
}

// setKid Sets the key identifier (account URI).
func (a *Core) setKid(kid string) {
	if kid == "" {
		return
	}

	a.mu.Lock()
	a.kid = kid
	a.mu.Unlock()
}

func (a *Core) setPrivateKey(privateKey crypto.Signer) {
	a.mu.Lock()
	a.privateKey = privateKey
	a.mu.Unlock()
}

// post performs an HTTP POST request and parses the response body as JSON,
// into the provided respBody object.
func (a *Core) post(ctx context.Context, uri string, reqBody, response any) (*http.Response, error) {
	content, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.New("failed to marshal message")
	}

	return a.retrievablePost(ctx, uri, content, response)
}

// postAsGet performs an HTTP POST ("POST-as-GET") request.
// https://www.rfc-editor.org/rfc/rfc8555.html#section-6.3
func (a *Core) postAsGet(ctx context.Context, uri string, response any) (*http.Response, error) {
	return a.retrievablePost(ctx, uri, []byte{}, response)
}

func (a *Core) retrievablePost(ctx context.Context, uri string, content []byte, response any) (*http.Response, error) {
	// Keep one nonce source and signer for the whole logical request. A nonce
	// returned in a response is therefore offered first to that request's
	// retry, while concurrent requests keep their own independent state.
	nonceSource := nonces.NewNonceSource(ctx, a.nonceManager)
	defer nonceSource.Flush()

	signer := a.signer()

	// during tests, allow to support ~90% of bad nonce with a minimum of attempts.
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 200 * time.Millisecond
	bo.MaxInterval = 5 * time.Second

	operation := func() (*http.Response, error) {
		resp, err := a.sendSignedPost(ctx, signer, nonceSource, uri, content, response)

		_, isNonceError := errors.AsType[*acme.NonceError](err)

		if !isNonceError {
			// The nonce from a terminal response goes back to the shared pool
			// immediately. For a badNonce response, keep it in this source so
			// the retry for this logical request consumes it first.
			nonceSource.Flush()
		}

		if err != nil {
			// Retry if the nonce was invalidated.
			if isNonceError {
				return resp, err
			}

			return resp, backoff.Permanent(err)
		}

		return resp, nil
	}

	return backoff.Retry(ctx, operation,
		backoff.WithBackOff(bo),
		backoff.WithMaxElapsedTime(0),
		backoff.WithMaxTries(6),
		backoff.WithNotify(wait.SimpleNotify("Retry.")))
}

func (a *Core) signedPost(ctx context.Context, uri string, content []byte, response any) (*http.Response, error) {
	nonceSource := nonces.NewNonceSource(ctx, a.nonceManager)
	defer nonceSource.Flush()

	return a.sendSignedPost(ctx, a.signer(), nonceSource, uri, content, response)
}

func (a *Core) sendSignedPost(
	ctx context.Context,
	signer *secure.Signer,
	nonceSource *nonces.NonceSource,
	uri string,
	content []byte,
	response any,
) (*http.Response, error) {
	signedContent, err := signer.SignContent(nonceSource, uri, content)
	if err != nil {
		return nil, fmt.Errorf("failed to post JWS message: failed to sign content: %w", err)
	}

	signedBody := bytes.NewBufferString(signedContent.FullSerialize())

	resp, err := a.doer.Post(ctx, uri, signedBody, "application/jose+json", response)

	// Keep the nonce with the source that signed this attempt. If this is a
	// one-off signedPost call, its deferred Flush returns the nonce to the
	// shared manager. For a retrievable POST, a badNonce retry consumes it
	// before the logical request's final Flush runs.
	nonce, nonceErr := nonces.GetFromResponse(resp)
	if nonceErr == nil {
		nonceSource.Push(nonce)
	}

	return resp, err
}

func getDirectory(ctx context.Context, do *sender.Doer, caDirURL string) (acme.Directory, error) {
	var dir acme.Directory

	_, err := do.Get(ctx, caDirURL, &dir)
	if err != nil {
		return dir, fmt.Errorf("get directory at '%s': %w", caDirURL, err)
	}

	if dir.NewAccountURL == "" {
		return dir, errors.New("directory missing new registration URL")
	}

	if dir.NewOrderURL == "" {
		return dir, errors.New("directory missing new order URL")
	}

	return dir, nil
}
