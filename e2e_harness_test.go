package main

// End-to-end harness (F-006a). Unlike the per-package tests — which exercise
// idp, auth, proxy, keys and cimd in isolation — this assembles the whole
// gateway the way Run() mounts it (session store + auth + idp + proxy on one
// gin engine, real signing keys, a real KVS repository) in front of a mock
// upstream, and drives it over HTTP through httptest. It is the only test that
// verifies a token minted by /.idp/token is accepted by the proxy and
// forwarded upstream, that the real password login gates the authorize flow,
// and that revocation / key rotation are honoured through the full stack.
//
// Coverage note: CIMD's HTTP fetch layer (SSRF guards, size/time limits,
// caching) can only be reached in-package because the private-host bypass is
// deliberately unexported — it stays covered by pkg/cimd. Here the CIMD happy
// path runs through an injected resolver stub, exactly as the gateway treats a
// resolved CIMD client. The real CIMD network path against a public
// deployment is verified live in F-006c.

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/idp"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/proxy"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// The issuer is fixed (as the per-package tests do) while httptest binds a
// random port: metadata, token iss/aud and the RFC 9207 iss all use this
// value, and the client redirect_uri is a loopback literal, so nothing depends
// on the ephemeral port.
const (
	e2eIssuer      = "http://localhost:8080"
	e2ePassword    = "correct-horse-battery-staple"
	e2eRedirectURI = "http://localhost:8080/callback"
	upstreamSecret = "upstream-bearer-secret"
)

// upstreamRecorder is the mock MCP upstream: it records what the proxy
// forwarded so tests can assert credential injection (FR-6) and returns 200.
type upstreamRecorder struct {
	mu       sync.Mutex
	hits     int
	lastAuth string
	lastPath string
}

func (u *upstreamRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits++
		u.lastAuth = r.Header.Get("Authorization")
		u.lastPath = r.URL.Path
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

func (u *upstreamRecorder) snapshot() (hits int, auth, path string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits, u.lastAuth, u.lastPath
}

// stubCIMDResolver satisfies idp.CIMDResolver without network access; the real
// HTTP resolution (SSRF guards, limits, caching) is covered in pkg/cimd.
type stubCIMDResolver struct {
	doc *cimd.Client
}

func (s *stubCIMDResolver) Resolve(_ context.Context, clientID string) (*cimd.Client, error) {
	if s.doc != nil && s.doc.ClientID == clientID {
		return s.doc, nil
	}
	return nil, cimd.ErrInvalidClientID
}

// e2eGateway is a fully assembled gateway wrapped in an httptest server.
type e2eGateway struct {
	server   *httptest.Server
	issuer   string
	repo     repository.Repository
	keys     *keys.Manager
	upstream *upstreamRecorder
}

type e2eOpts struct {
	oidcMirror    bool
	cimd          idp.CIMDResolver
	registerLimit string // e.g. "1/m"; empty disables
	tokenLimit    string
}

// newE2EGateway builds the gateway exactly as Run() mounts it and starts an
// httptest server for it.
func newE2EGateway(t *testing.T, opts e2eOpts) *e2eGateway {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	repo, err := repository.NewKVSRepository(filepath.Join(dir, "db"), "e2e")
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Close() })

	keyManager, err := keys.NewManager(keys.Config{
		Dir:          filepath.Join(dir, "keys"),
		Alg:          keys.AlgRS256,
		RetireWindow: time.Hour,
	})
	require.NoError(t, err)

	secret := sha256.Sum256([]byte("e2e-secret"))
	logger := zap.NewNop()

	hash, err := bcrypt.GenerateFromPassword([]byte(e2ePassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	authRouter, err := auth.NewAuthRouter(auth.Config{
		PasswordHashes: []string{string(hash)},
		Users:          repo,
		ExternalURL:    e2eIssuer,
		Logger:         logger,
		Lockout:        ratelimit.NewLockout(0, 0), // disabled but nil-safe
	})
	require.NoError(t, err)

	idpRouter, err := idp.NewIDPRouter(idp.Config{
		Repo:                repo,
		Keys:                keyManager,
		Logger:              logger,
		ExternalURL:         e2eIssuer,
		Secret:              secret[:],
		AuthRouter:          authRouter,
		OIDCDiscoveryMirror: opts.oidcMirror,
		AccessTokenTTL:      time.Hour,
		AuthCodeTTL:         10 * time.Minute,
		RefreshTokenTTL:     30 * 24 * time.Hour,
		CIMDResolver:        opts.cimd,
		DCREnabled:          true,
		DCRClientTTL:        30 * 24 * time.Hour,
		TokenRateLimit:      limiterMiddleware(t, opts.tokenLimit, "token", logger),
		RegisterRateLimit:   limiterMiddleware(t, opts.registerLimit, "register", logger),
	})
	require.NoError(t, err)

	upstream := &upstreamRecorder{}
	proxyHeaders := http.Header{}
	proxyHeaders.Set("Authorization", "Bearer "+upstreamSecret)

	proxyRouter, err := proxy.NewProxyRouter(proxy.Config{
		ExternalURL:     e2eIssuer,
		Proxy:           upstream.handler(),
		VerificationKey: keyManager.VerificationKey,
		ProxyHeaders:    proxyHeaders,
		TokenActive:     tokenActiveChecker(repo),
	})
	require.NoError(t, err)

	router := gin.New()
	store := cookie.NewStore(secret[:])
	router.Use(sessions.Sessions("session", store))
	authRouter.SetupRoutes(router)
	idpRouter.SetupRoutes(router)
	proxyRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return &e2eGateway{server: server, issuer: e2eIssuer, repo: repo, keys: keyManager, upstream: upstream}
}

// limiterMiddleware mirrors Run's construction; an empty expression yields a
// nil (disabled) middleware, which idp tolerates.
func limiterMiddleware(t *testing.T, expr, endpoint string, logger *zap.Logger) gin.HandlerFunc {
	t.Helper()
	if expr == "" {
		return ratelimit.Middleware(nil, endpoint, logger)
	}
	limit, err := ratelimit.ParseLimit(expr)
	require.NoError(t, err)
	return ratelimit.Middleware(ratelimit.NewLimiter(limit), endpoint, logger)
}

// tokenActiveChecker is the proxy's revocation hook (SPEC §2.4), copied from
// Run: a token is active while its fosite record (keyed by JWT signature)
// exists; a store failure fails closed.
func tokenActiveChecker(repo repository.Repository) func(context.Context, string) error {
	return func(ctx context.Context, rawToken string) error {
		parts := strings.Split(rawToken, ".")
		if len(parts) != 3 {
			return proxy.ErrTokenInactive
		}
		if _, err := repo.GetAccessTokenSession(ctx, parts[2], nil); err != nil {
			if errors.Is(err, fosite.ErrNotFound) {
				return proxy.ErrTokenInactive
			}
			return err
		}
		return nil
	}
}

// -- HTTP helpers ------------------------------------------------------------

// newFlowClient returns a cookie-jar client that does not auto-follow
// redirects, so each hop's Location can be inspected.
func newFlowClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (g *e2eGateway) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(g.server.URL + path)
	require.NoError(t, err)
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// pkcePair returns a PKCE verifier and its S256 challenge; seed lets callers
// derive distinct verifiers.
func pkcePair(seed string) (verifier, challenge string) {
	verifier = strings.Repeat("v", 43) + seed // >= 43 chars per RFC 7636
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// registerClient performs DCR (POST /.idp/register) and returns the client_id
// and (for confidential clients) the secret.
func (g *e2eGateway) registerClient(t *testing.T, authMethod string) (clientID, clientSecret string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"client_name":                "E2E Client",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
		"redirect_uris":              []string{e2eRedirectURI},
	})
	require.NoError(t, err)

	resp, err := http.Post(g.server.URL+idp.RegistrationEndpoint, "application/json", strings.NewReader(string(body)))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	out := decodeJSON(t, resp)

	clientID, _ = out["client_id"].(string)
	clientSecret, _ = out["client_secret"].(string)
	require.NotEmpty(t, clientID)
	return clientID, clientSecret
}

// driveAuthCode runs the full authorize flow with a real password login and
// consent, returning the callback URL (which carries the code + iss). It
// asserts each hop so a broken login surfaces where it breaks.
func (g *e2eGateway) driveAuthCode(t *testing.T, client *http.Client, authURL string) *url.URL {
	t.Helper()

	// 1. GET /.idp/auth -> 302 to the login-gated return endpoint.
	returnPath := requireRedirect(t, mustGet(t, client, authURL))
	require.Contains(t, returnPath, strings.ReplaceAll(idp.AuthorizationReturnEndpoint, ":ar_id", ""))

	// 2. GET the return endpoint unauthenticated -> 302 to the login page.
	loginPath := requireRedirect(t, mustGet(t, client, g.server.URL+returnPath))
	require.Contains(t, loginPath, auth.LoginEndpoint)

	// 3. POST the password -> 302 back to the return endpoint.
	form := url.Values{"password": {e2ePassword}}
	loginResp, err := client.PostForm(g.server.URL+auth.LoginEndpoint, form)
	require.NoError(t, err)
	afterLogin := requireRedirect(t, loginResp)
	require.Contains(t, afterLogin, returnPath)

	// 4. GET the consent form -> 200.
	formResp := mustGet(t, client, g.server.URL+returnPath)
	require.Equal(t, http.StatusOK, formResp.StatusCode)
	formResp.Body.Close()

	// 5. POST consent -> 302 to redirect_uri with code + iss.
	consentResp, err := client.Post(g.server.URL+returnPath, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	callback := requireRedirect(t, consentResp)
	parsed, err := url.Parse(callback)
	require.NoError(t, err)
	return parsed
}

func mustGet(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err)
	return resp
}

// requireRedirect asserts a 3xx with a Location and returns it, closing the body.
func requireRedirect(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode,
		"expected a redirect, got %d", resp.StatusCode)
	location := resp.Header.Get("Location")
	require.NotEmpty(t, location)
	return location
}

// exchangeCode posts the authorization code to /.idp/token and returns the
// decoded token response. extra carries client auth / code_verifier.
func (g *e2eGateway) exchangeCode(t *testing.T, code string, extra url.Values) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {e2eRedirectURI},
	}
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	resp, err := http.PostForm(g.server.URL+idp.TokenEndpoint, form)
	require.NoError(t, err)
	return resp
}

// proxyGet issues an authenticated (or, with an empty token, unauthenticated)
// request to the protected proxy surface.
func (g *e2eGateway) proxyGet(t *testing.T, path, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, g.server.URL+path, nil)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// verifyAgainstJWKS fetches the published JWKS and verifies the token against
// the key its kid selects — proving the advertised key set validates issued
// tokens (FR-7). Returns the token's claims.
func (g *e2eGateway) verifyAgainstJWKS(t *testing.T, rawToken string) jwt.MapClaims {
	t.Helper()
	resp := g.get(t, idp.JWKSEndpoint)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var set struct {
		Keys []keys.JWK `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &set))
	require.NotEmpty(t, set.Keys, "JWKS must publish at least one key")

	byKid := map[string]*rsa.PublicKey{}
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" {
			continue
		}
		byKid[jwk.Kid] = rsaPublicKeyFromJWK(t, jwk)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(rawToken, claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		pub, ok := byKid[kid]
		if !ok {
			return nil, fmt.Errorf("kid %q not in JWKS", kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	require.True(t, token.Valid)
	return claims
}

func rsaPublicKeyFromJWK(t *testing.T, jwk keys.JWK) *rsa.PublicKey {
	t.Helper()
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	require.NoError(t, err)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	require.NoError(t, err)
	// Left-pad the exponent to 8 bytes so it can be read as a big-endian uint.
	padded := make([]byte, 8)
	copy(padded[8-len(eBytes):], eBytes)
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(binary.BigEndian.Uint64(padded)),
	}
}
