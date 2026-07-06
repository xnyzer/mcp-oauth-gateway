package idp

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type IDPRouter struct {
	repo                repository.Repository
	privKey             *rsa.PrivateKey
	logger              *zap.Logger
	externalURL         string
	hasher              fosite.Hasher
	provider            fosite.OAuth2Provider
	signer              *jwt.DefaultSigner
	authRouter          *auth.AuthRouter
	oidcDiscoveryMirror bool
	refreshEnabled      bool
	dcrEnabled          bool
	dcrClientTTL        time.Duration
	dcrMaxClients       int
}

// CIMDResolver resolves a Client ID Metadata Document for an https://
// client ID (implemented by *cimd.Resolver; an interface for testability).
type CIMDResolver interface {
	Resolve(ctx context.Context, clientID string) (*cimd.Client, error)
}

// clientSource resolves CIMD client IDs first and falls back to the DCR
// store (SPEC §1.3); fosite uses it for every client lookup, so CIMD works
// at the authorize and token endpoints alike.
type clientSource struct {
	repository.Repository
	resolver    CIMDResolver
	externalURL string
	logger      *zap.Logger
}

func (s *clientSource) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if s.resolver == nil || !strings.HasPrefix(id, "https://") {
		return s.Repository.GetClient(ctx, id)
	}
	doc, err := s.resolver.Resolve(ctx, id)
	if err != nil {
		// Resolution detail stays in the logs (SR-8); the client only
		// sees invalid_client (SPEC §1.3.6, fail-closed).
		s.logger.Warn("CIMD resolution failed", zap.String("client_id", id), zap.Error(err))
		return nil, fosite.ErrNotFound
	}
	return &fosite.DefaultClient{
		ID:            doc.ClientID,
		RedirectURIs:  doc.RedirectURIs,
		GrantTypes:    doc.GrantTypes,
		ResponseTypes: doc.ResponseTypes,
		Scopes:        strings.Fields(doc.Scope),
		Audience:      []string{s.externalURL},
		Public:        true, // CIMD clients are public; PKCE is enforced
	}, nil
}

// Config carries all options for the OAuth authorization-server surface
// (SPEC §1.2–§1.10).
type Config struct {
	Repo    repository.Repository
	PrivKey *rsa.PrivateKey
	Logger  *zap.Logger
	// ExternalURL is the normalized issuer (no trailing slash, SPEC §0).
	ExternalURL string
	Secret      []byte
	AuthRouter  *auth.AuthRouter
	// OIDCDiscoveryMirror additionally serves the AS metadata under
	// /.well-known/openid-configuration (SPEC §1.2, off by default).
	OIDCDiscoveryMirror bool
	// AccessTokenTTL and AuthCodeTTL default to 1h / 10m when zero.
	// RefreshTokenTTL of 0 disables the refresh grant (SPEC §3.2).
	AccessTokenTTL  time.Duration
	AuthCodeTTL     time.Duration
	RefreshTokenTTL time.Duration
	// CIMDResolver resolves https:// client IDs (SPEC §1.3). nil disables
	// CIMD; only stored DCR registrations are accepted then.
	CIMDResolver CIMDResolver
	// DCREnabled serves POST /.idp/register and advertises it in the AS
	// metadata (SPEC §1.4). CIMD is unaffected.
	DCREnabled bool
	// DCRClientTTL expires DCR registrations (refreshed on token issuance);
	// 0 disables expiry. DCRMaxClients caps stored registrations; 0 means
	// unlimited (SR-5).
	DCRClientTTL  time.Duration
	DCRMaxClients int
}

const (
	defaultAccessTokenTTL = time.Hour
	defaultAuthCodeTTL    = 10 * time.Minute
)

func NewIDPRouter(cfg Config) (*IDPRouter, error) {
	hasher := &fosite.BCrypt{
		Config: &fosite.Config{
			HashCost: bcrypt.DefaultCost,
		},
	}
	accessTokenTTL := cfg.AccessTokenTTL
	if accessTokenTTL == 0 {
		accessTokenTTL = defaultAccessTokenTTL
	}
	authCodeTTL := cfg.AuthCodeTTL
	if authCodeTTL == 0 {
		authCodeTTL = defaultAuthCodeTTL
	}
	refreshEnabled := cfg.RefreshTokenTTL > 0
	fositeConfig := &fosite.Config{
		GlobalSecret:                   cfg.Secret,
		AccessTokenLifespan:            accessTokenTTL,
		AuthorizeCodeLifespan:          authCodeTTL,
		RefreshTokenLifespan:           cfg.RefreshTokenTTL,
		RefreshTokenScopes:             []string{},
		AccessTokenIssuer:              cfg.ExternalURL,
		EnforcePKCE:                    false,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy:                  fosite.HierarchicScopeStrategy,
		MinParameterEntropy:            fosite.MinParameterEntropy,
		ClientSecretsHasher:            hasher,
		// Space-separated scope claim (SPEC §1.7).
		JWTScopeClaimKey: jwt.JWTScopeFieldString,
	}
	storage := &clientSource{
		Repository:  cfg.Repo,
		resolver:    cfg.CIMDResolver,
		externalURL: cfg.ExternalURL,
		logger:      cfg.Logger,
	}
	provider, signer := customCompose(fositeConfig, storage, cfg.PrivKey, refreshEnabled)

	return &IDPRouter{
		repo:                cfg.Repo,
		privKey:             cfg.PrivKey,
		logger:              cfg.Logger,
		externalURL:         cfg.ExternalURL,
		hasher:              hasher,
		provider:            provider,
		signer:              signer,
		authRouter:          cfg.AuthRouter,
		oidcDiscoveryMirror: cfg.OIDCDiscoveryMirror,
		refreshEnabled:      refreshEnabled,
		dcrEnabled:          cfg.DCREnabled,
		dcrClientTTL:        cfg.DCRClientTTL,
		dcrMaxClients:       cfg.DCRMaxClients,
	}, nil
}

func customCompose(config *fosite.Config, storage any, key any, refreshEnabled bool) (fosite.OAuth2Provider, *jwt.DefaultSigner) {
	keyGetter := func(context.Context) (any, error) { return key, nil }
	signer := &jwt.DefaultSigner{GetPrivateKey: keyGetter}

	factories := []compose.Factory{
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenRevocationFactory,
	}
	if refreshEnabled {
		factories = append(factories, compose.OAuth2RefreshTokenGrantFactory)
	}

	provider := compose.Compose(
		config,
		storage,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, compose.NewOAuth2HMACStrategy(config), config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     signer,
		},
		factories...,
	)
	return provider, signer
}

const (
	AuthorizationEndpoint            = "/.idp/auth"
	AuthorizationReturnEndpoint      = "/.idp/auth/:ar_id"
	TokenEndpoint                    = "/.idp/token"
	IntrospectionEndpoint            = "/.idp/introspect"
	RevocationEndpoint               = "/.idp/revoke"
	RegistrationEndpoint             = "/.idp/register"
	OauthAuthorizationServerEndpoint = "/.well-known/oauth-authorization-server"
	OIDCDiscoveryEndpoint            = "/.well-known/openid-configuration"
	JWKSEndpoint                     = "/.well-known/jwks.json"
	sessionKeyAuthorizeRequestIDs    = "idp_authorize_request_ids"
)

func (a *IDPRouter) SetupRoutes(router gin.IRouter) {
	router.GET(AuthorizationEndpoint, a.handleAuth)
	router.GET(AuthorizationReturnEndpoint, a.authRouter.RequireAuth(), a.handleAuthorizationReturnForm)
	router.POST(AuthorizationReturnEndpoint, a.authRouter.RequireAuth(), a.handleAuthorizationReturn)
	router.POST(TokenEndpoint, a.handleToken)
	router.POST(IntrospectionEndpoint, a.handleIntrospect)
	router.POST(RevocationEndpoint, a.handleRevoke)
	if a.dcrEnabled {
		router.POST(RegistrationEndpoint, a.handleRegister)
	}
	router.GET(OauthAuthorizationServerEndpoint, a.handleOauthAuthorizationServer)
	if a.oidcDiscoveryMirror {
		router.GET(OIDCDiscoveryEndpoint, a.handleOauthAuthorizationServer)
	}
	router.GET(JWKSEndpoint, a.handleJWKS)
}

// errInvalidTarget is the RFC 8707 error for resource values the gateway
// does not serve.
var errInvalidTarget = &fosite.RFC6749Error{
	ErrorField:       "invalid_target",
	DescriptionField: "The requested resource is not served by this authorization server.",
	CodeField:        http.StatusBadRequest,
}

// validateResource enforces SPEC §1.5/§1.6: the gateway fronts exactly one
// resource — itself. Absent values default to the issuer; anything else is
// rejected with invalid_target (RFC 8707).
func (a *IDPRouter) validateResource(resources []string) error {
	for _, resource := range resources {
		if resource != "" && strings.TrimSuffix(resource, "/") != a.externalURL {
			return errInvalidTarget
		}
	}
	return nil
}

// issRedirectWriter appends the RFC 9207 `iss` parameter to redirect
// responses written by fosite's WriteAuthorizeError, which has no built-in
// RFC 9207 support in v0.49. Non-redirect responses pass through untouched.
type issRedirectWriter struct {
	http.ResponseWriter
	issuer string
}

func (w *issRedirectWriter) WriteHeader(statusCode int) {
	if statusCode >= 300 && statusCode < 400 {
		if location := w.Header().Get("Location"); location != "" {
			if u, err := url.Parse(location); err == nil {
				q := u.Query()
				if q.Get("iss") == "" {
					q.Set("iss", w.issuer)
					u.RawQuery = q.Encode()
					w.Header().Set("Location", u.String())
				}
			}
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// writeAuthorizeError delegates to fosite while ensuring redirected errors
// carry the RFC 9207 `iss` parameter (SPEC §1.5).
func (a *IDPRouter) writeAuthorizeError(ctx context.Context, w http.ResponseWriter, ar fosite.AuthorizeRequester, err error) {
	a.provider.WriteAuthorizeError(ctx, &issRedirectWriter{ResponseWriter: w, issuer: a.externalURL}, ar, err)
}

func (a *IDPRouter) handleAuth(c *gin.Context) {
	ctx := c.Request.Context()

	// RFC 6749 makes state RECOMMENDED, not REQUIRED, but fosite enforces
	// minimum entropy (8 chars). Generate a server-side state for clients
	// that omit it (e.g., MCP Inspector, Cursor CLI) so they can complete
	// the OAuth flow. The generated state is echoed back in the redirect;
	// clients that didn't send state will simply ignore it.
	if c.Request.URL.Query().Get("state") == "" {
		state, err := utils.GenerateState()
		if err != nil {
			a.writeAuthorizeError(ctx, c.Writer, nil, fosite.ErrServerError.WithWrap(err))
			return
		}
		q := c.Request.URL.Query()
		q.Set("state", state)
		c.Request.URL.RawQuery = q.Encode()
	}

	ar, err := a.provider.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// RFC 8707: the only valid resource is the gateway itself (SPEC §1.5).
	if err := a.validateResource(c.Request.URL.Query()["resource"]); err != nil {
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	if err := a.repo.CreateAuthorizeRequest(ctx, ar); err != nil {
		a.logger.Error("Failed to create authorize requester", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	session := sessions.Default(c)
	addAuthorizeRequestID(session, ar.GetID())
	if err := session.Save(); err != nil {
		a.logger.Error("Failed to save authorize request in session", zap.Error(err))
		_ = a.repo.DeleteAuthorizeRequest(ctx, ar.GetID())
		a.writeAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	c.Redirect(302, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ar.GetID()))
}

func (a *IDPRouter) handleAuthorizationReturnForm(c *gin.Context) {
	arID := c.Param("ar_id")
	if !hasAuthorizeRequestID(sessions.Default(c), arID) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid authorization session"})
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`<!doctype html><html><body><form method="post"><button type="submit">Authorize</button></form></body></html>`))
}

func (a *IDPRouter) handleAuthorizationReturn(c *gin.Context) {
	ctx := c.Request.Context()
	arID := c.Param("ar_id")
	session := sessions.Default(c)
	if !hasAuthorizeRequestID(session, arID) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid authorization session"})
		return
	}

	ar, err := a.repo.GetAuthorizeRequest(ctx, arID)
	if err != nil {
		a.logger.Error("Failed to get authorize requester", zap.Error(err))
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	defer func() {
		if err := a.repo.DeleteAuthorizeRequest(ctx, arID); err != nil {
			a.logger.Error("Failed to delete authorize requester", zap.Error(err))
		}
	}()

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	ar.GrantAudience(a.externalURL)

	subject := "user"
	if userID, ok := session.Get(auth.SessionKeyUserID).(string); ok && userID != "" {
		subject = userID
	}
	var userInfo map[string]any
	if userInfoJSON, ok := session.Get(auth.SessionKeyUserInfo).(string); ok && userInfoJSON != "" {
		json.Unmarshal([]byte(userInfoJSON), &userInfo)
	}

	jwtSession, err := NewJWTSessionWithKey(a.externalURL, subject, ar.GetClient().GetID(), a.privKey, userInfo)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	response, err := a.provider.NewAuthorizeResponse(ctx, ar, jwtSession)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to generate authorization response", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}
	// RFC 9207: identify the issuer in the authorization response (SPEC §1.5).
	response.AddParameter("iss", a.externalURL)

	removeAuthorizeRequestID(session, arID)
	if err := session.Save(); err != nil {
		a.logger.Error("Failed to remove authorize request from session", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}

	a.provider.WriteAuthorizeResponse(ctx, c.Writer, ar, response)
}

func authorizeRequestIDs(session sessions.Session) []string {
	value, ok := session.Get(sessionKeyAuthorizeRequestIDs).(string)
	if !ok || value == "" {
		return nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(value), &ids); err != nil {
		return nil
	}
	return ids
}

func addAuthorizeRequestID(session sessions.Session, arID string) {
	ids := authorizeRequestIDs(session)
	if hasAuthorizeRequestID(session, arID) {
		return
	}
	ids = append(ids, arID)
	data, _ := json.Marshal(ids)
	session.Set(sessionKeyAuthorizeRequestIDs, string(data))
}

func hasAuthorizeRequestID(session sessions.Session, arID string) bool {
	for _, id := range authorizeRequestIDs(session) {
		if id == arID {
			return true
		}
	}
	return false
}

func removeAuthorizeRequestID(session sessions.Session, arID string) {
	ids := authorizeRequestIDs(session)
	remaining := ids[:0]
	for _, id := range ids {
		if id != arID {
			remaining = append(remaining, id)
		}
	}
	if len(remaining) == 0 {
		session.Delete(sessionKeyAuthorizeRequestIDs)
		return
	}
	data, _ := json.Marshal(remaining)
	session.Set(sessionKeyAuthorizeRequestIDs, string(data))
}

func (a *IDPRouter) handleToken(c *gin.Context) {
	ctx := c.Request.Context()

	session, err := NewJWTSessionWithKey("", "", "", a.privKey, nil)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session for token", zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, nil, fosite.ErrServerError.WithWrap(err))
		return
	}

	// RFC 8707: the only valid resource is the gateway itself (SPEC §1.6).
	if err := c.Request.ParseForm(); err != nil {
		a.provider.WriteAccessError(ctx, c.Writer, nil, fosite.ErrInvalidRequest.WithWrap(err))
		return
	}
	if err := a.validateResource(c.Request.PostForm["resource"]); err != nil {
		a.provider.WriteAccessError(ctx, c.Writer, nil, err)
		return
	}

	accessRequest, err := a.provider.NewAccessRequest(ctx, c.Request, session)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access request", zap.String("grant_type", c.PostForm("grant_type")))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	response, err := a.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access response", zap.String("grant_type", c.PostForm("grant_type")), zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	// Active DCR clients never expire mid-use: refresh the registration
	// TTL on successful issuance (SR-5). CIMD clients are not persisted.
	if a.dcrClientTTL > 0 {
		clientID := accessRequest.GetClient().GetID()
		if !strings.HasPrefix(clientID, "https://") {
			if err := a.repo.TouchClient(ctx, clientID, time.Now().UTC().Add(a.dcrClientTTL)); err != nil {
				a.logger.Warn("Failed to refresh client registration TTL", zap.String("client_id", clientID), zap.Error(err))
			}
		}
	}

	a.provider.WriteAccessResponse(ctx, c.Writer, accessRequest, response)
}

func (a *IDPRouter) handleIntrospect(c *gin.Context) {
	ctx := c.Request.Context()
	session, err := NewJWTSessionWithKey("", "", "", a.privKey, nil)
	if err != nil {
		a.provider.WriteIntrospectionError(ctx, c.Writer, fosite.ErrServerError.WithWrap(err))
		return
	}

	ir, err := a.provider.NewIntrospectionRequest(ctx, c.Request, session)
	if err != nil {
		a.provider.WriteIntrospectionError(ctx, c.Writer, err)
		return
	}

	a.provider.WriteIntrospectionResponse(ctx, c.Writer, ir)
}

// handleRevoke implements RFC 7009 (SPEC §1.9). fosite authenticates the
// client, resolves the token (access or refresh), and revokes the grant via
// the repository; unknown tokens still yield 200 (no token-existence oracle).
func (a *IDPRouter) handleRevoke(c *gin.Context) {
	ctx := c.Request.Context()
	err := a.provider.NewRevocationRequest(ctx, c.Request)
	if err != nil {
		a.logger.With(utils.Err(err)...).Warn("Token revocation failed")
	}
	a.provider.WriteRevocationResponse(ctx, c.Writer, err)
}

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	RedirectURIs            []string `json:"redirect_uris"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	// ClientSecretExpiresAt is 0 when the registration never expires
	// (RFC 7591 §3.2.1); otherwise the SR-5 registration TTL.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at"`
}

var (
	supportedGrantTypes    = map[string]bool{"authorization_code": true, "refresh_token": true}
	supportedResponseTypes = map[string]bool{"code": true}
	supportedAuthMethods   = map[string]bool{"none": true, "client_secret_basic": true, "client_secret_post": true}
)

// validateRegistration enforces the SPEC §1.4 metadata rules. It returns an
// RFC 7591 error code and description, or empty strings when valid.
func validateRegistration(req *registrationRequest) (string, string) {
	if len(req.RedirectURIs) == 0 {
		return "invalid_redirect_uri", "redirect_uris must not be empty"
	}
	for _, redirectURI := range req.RedirectURIs {
		if err := cimd.ValidateRedirectURI(redirectURI); err != nil {
			return "invalid_redirect_uri", err.Error()
		}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic" // RFC 7591 default
	}
	if !supportedAuthMethods[req.TokenEndpointAuthMethod] {
		return "invalid_client_metadata", "unsupported token_endpoint_auth_method"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	for _, grantType := range req.GrantTypes {
		if !supportedGrantTypes[grantType] {
			return "invalid_client_metadata", "unsupported grant_type: " + grantType
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	for _, responseType := range req.ResponseTypes {
		if !supportedResponseTypes[responseType] {
			return "invalid_client_metadata", "unsupported response_type: " + responseType
		}
	}
	return "", ""
}

func (a *IDPRouter) handleRegister(c *gin.Context) {
	ctx := c.Request.Context()

	var req registrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if errCode, errDesc := validateRegistration(&req); errCode != "" {
		c.JSON(400, gin.H{"error": errCode, "error_description": errDesc})
		return
	}

	// Registration cap (SR-5): never silently evict active clients.
	if a.dcrMaxClients > 0 {
		count, err := a.repo.CountClients(ctx)
		if err != nil {
			a.logger.Error("Failed to count registered clients", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
		if count >= a.dcrMaxClients {
			a.logger.Warn("DCR client cap reached", zap.Int("cap", a.dcrMaxClients))
			c.JSON(503, gin.H{"error": "temporarily_unavailable", "error_description": "client registration is temporarily unavailable"})
			return
		}
	}

	clientID, err := utils.GenerateClientID()
	if err != nil {
		a.logger.Error("Failed to generate client ID", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	var clientSecret string
	var hashedSecret []byte
	isPublic := req.TokenEndpointAuthMethod == "none"

	if !isPublic {
		// Generate client secret for confidential clients
		clientSecret, err = utils.GenerateClientSecret()
		if err != nil {
			a.logger.Error("Failed to generate client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
			return
		}

		hashedSecret, err = a.hasher.Hash(ctx, []byte(clientSecret))
		if err != nil {
			a.logger.Error("Failed to hash client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
			return
		}
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
		Scopes:        strings.Fields(req.Scope),
		Audience:      []string{a.externalURL},
		Public:        isPublic,
	}
	// Registration TTL (SR-5): refreshed on token issuance (handleToken).
	var expiresAt time.Time
	if a.dcrClientTTL > 0 {
		expiresAt = time.Now().UTC().Add(a.dcrClientTTL)
	}
	if err := a.repo.RegisterClient(ctx, client, expiresAt); err != nil {
		a.logger.Error("Failed to register client", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	registrationClientURI, err := url.JoinPath(RegistrationEndpoint, clientID)
	if err != nil {
		a.logger.Error("Failed to create registration client URI", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	response := registrationResponse{
		ClientID:                clientID,
		RedirectURIs:            req.RedirectURIs,
		ClientName:              req.ClientName,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RegistrationClientURI:   registrationClientURI,
		ClientIDIssuedAt:        time.Now().Unix(),
	}

	if !isPublic {
		response.ClientSecret = clientSecret
		// 0 = never expires (RFC 7591 §3.2.1).
		if !expiresAt.IsZero() {
			response.ClientSecretExpiresAt = expiresAt.Unix()
		}
	}

	c.JSON(201, response)
}

type authorizationServerResponse struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	JWKSURI                                    string   `json:"jwks_uri"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

func (a *IDPRouter) handleOauthAuthorizationServer(c *gin.Context) {
	authorizationEndpoint, err := url.JoinPath(a.externalURL, AuthorizationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create authorization endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	tokenEndpoint, err := url.JoinPath(a.externalURL, TokenEndpoint)
	if err != nil {
		a.logger.Error("Failed to create token endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	// Advertised only while the deprecated DCR fallback is enabled
	// (SPEC §1.4); CIMD needs no registration endpoint.
	var registrationEndpoint string
	if a.dcrEnabled {
		registrationEndpoint, err = url.JoinPath(a.externalURL, RegistrationEndpoint)
		if err != nil {
			a.logger.Error("Failed to create registration endpoint URL", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
			return
		}
	}
	jwksURI, err := url.JoinPath(a.externalURL, JWKSEndpoint)
	if err != nil {
		a.logger.Error("Failed to create JWKS URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	introspectionEndpoint, err := url.JoinPath(a.externalURL, IntrospectionEndpoint)
	if err != nil {
		a.logger.Error("Failed to create introspection endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	revocationEndpoint, err := url.JoinPath(a.externalURL, RevocationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create revocation endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	grantTypes := []string{"authorization_code"}
	if a.refreshEnabled {
		grantTypes = append(grantTypes, "refresh_token")
	}

	res := &authorizationServerResponse{
		Issuer:                                     a.externalURL,
		AuthorizationEndpoint:                      authorizationEndpoint,
		TokenEndpoint:                              tokenEndpoint,
		RegistrationEndpoint:                       registrationEndpoint,
		JWKSURI:                                    jwksURI,
		IntrospectionEndpoint:                      introspectionEndpoint,
		RevocationEndpoint:                         revocationEndpoint,
		ScopesSupported:                            []string{},
		ResponseTypesSupported:                     []string{"code"},
		ResponseModesSupported:                     []string{"query"},
		GrantTypesSupported:                        grantTypes,
		TokenEndpointAuthMethodsSupported:          []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		AuthorizationResponseIssParameterSupported: true,
	}
	c.JSON(200, res)
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (a *IDPRouter) handleJWKS(c *gin.Context) {
	publicKey := &a.privKey.PublicKey

	// Convert RSA public key components to base64url
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	n := base64.RawURLEncoding.EncodeToString(nBytes)
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	keyID, err := utils.GenerateKeyID(&a.privKey.PublicKey)
	if err != nil {
		a.logger.Error("Failed to generate key ID for JWKS", zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to generate key ID"})
		return
	}

	k := jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: keyID,
		Alg: "RS256",
		N:   n,
		E:   e,
	}

	ks := jwks{Keys: []jwk{k}}
	c.JSON(200, ks)
}

func NewJWTSessionWithKey(iss string, subject string, clientID string, privateKey *rsa.PrivateKey, userInfo map[string]any) (*Session, error) {
	keyID, err := utils.GenerateKeyID(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	jti, err := utils.GenerateJTI()
	if err != nil {
		return nil, err
	}
	extra := map[string]any{}
	if userInfo != nil {
		extra["userinfo"] = userInfo
	}
	if clientID != "" {
		extra["client_id"] = clientID
	}
	// exp, aud, and scope are set by fosite at issuance time from the
	// session expiry and the granted audience/scopes (SPEC §1.7).
	return &Session{
		DefaultSession: &fosite.DefaultSession{
			Username: subject,
			Subject:  subject,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    iss,
			Subject:   subject,
			JTI:       jti,
			IssuedAt:  time.Now(),
			NotBefore: time.Now(),
			Extra:     extra,
		},
		JWTHeader: &jwt.Headers{
			Extra: map[string]any{
				"kid": keyID,
			},
		},
	}, nil
}

type Session struct {
	*fosite.DefaultSession
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
}

func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	return s.JWTClaims
}

func (s *Session) GetJWTHeader() *jwt.Headers {
	return s.JWTHeader
}

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	clone := &Session{
		DefaultSession: &fosite.DefaultSession{
			Username:  s.DefaultSession.Username,
			Subject:   s.DefaultSession.Subject,
			ExpiresAt: s.DefaultSession.ExpiresAt,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    s.JWTClaims.Issuer,
			Subject:   s.JWTClaims.Subject,
			JTI:       s.JWTClaims.JTI,
			Audience:  s.JWTClaims.Audience,
			ExpiresAt: s.JWTClaims.ExpiresAt,
			IssuedAt:  s.JWTClaims.IssuedAt,
			NotBefore: s.JWTClaims.NotBefore,
			Extra:     s.JWTClaims.Extra,
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]any),
		},
	}

	// Refresh grants clone the stored session; each issued token gets a
	// fresh jti so token identifiers stay unique (SPEC §1.7).
	if jti, err := utils.GenerateJTI(); err == nil {
		clone.JWTClaims.JTI = jti
	}

	for k, v := range s.JWTHeader.Extra {
		clone.JWTHeader.Extra[k] = v
	}

	return clone
}
