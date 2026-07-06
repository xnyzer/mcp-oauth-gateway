package proxy

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mattn/go-jsonpointer"
)

// Config carries all options for the authenticated proxy surface (SPEC §1.11).
type Config struct {
	// ExternalURL is the normalized issuer (no trailing slash, SPEC §0);
	// it is compared against the token's iss and aud claims.
	ExternalURL string
	Proxy       http.Handler
	PublicKey   *rsa.PublicKey
	// ProxyHeaders are static headers added to every upstream request (FR-6).
	ProxyHeaders http.Header
	// HTTPStreamingOnly rejects GET-SSE requests with 405 (SPEC §1.11.3).
	HTTPStreamingOnly bool
	// ForwardAuthorizationHeader forwards the validated client bearer upstream.
	ForwardAuthorizationHeader bool
	HeaderMapping              map[string]string
	HeaderMappingBase          string
	// ClockSkew is the leeway applied to exp/nbf/iat validation (SPEC §1.11.1).
	ClockSkew time.Duration
}

type ProxyRouter struct {
	cfg Config
}

func NewProxyRouter(cfg Config) (*ProxyRouter, error) {
	// Defensive re-normalization (SPEC §0): iss/aud comparison and the PRM
	// document must always use the no-trailing-slash issuer form.
	cfg.ExternalURL = strings.TrimSuffix(cfg.ExternalURL, "/")
	return &ProxyRouter{cfg: cfg}, nil
}

const (
	OauthProtectedResourceEndpoint = "/.well-known/oauth-protected-resource"
	// jwksPath is fixed by SPEC §1.8; kept in sync with pkg/idp.JWKSEndpoint.
	jwksPath = "/.well-known/jwks.json"
)

func (p *ProxyRouter) SetupRoutes(router gin.IRouter) {
	router.GET(OauthProtectedResourceEndpoint, p.handleProtectedResource)
	router.Use(p.handleProxy)
}

type protectedResourceResponse struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	JWKSURI                string   `json:"jwks_uri"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResourceName           string   `json:"resource_name"`
}

func (p *ProxyRouter) handleProtectedResource(c *gin.Context) {
	c.JSON(http.StatusOK, protectedResourceResponse{
		Resource:               p.cfg.ExternalURL,
		AuthorizationServers:   []string{p.cfg.ExternalURL},
		JWKSURI:                p.cfg.ExternalURL + jwksPath,
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{},
		ResourceName:           "mcp-oauth-gateway",
	})
}

// abortUnauthorized writes the RFC 6750 challenge pointing clients at the PRM
// document (RFC 9728 §5, SPEC §1.11.2). errorCode is empty when no token was
// presented (RFC 6750 §3: no error attribute in that case).
func (p *ProxyRouter) abortUnauthorized(c *gin.Context, errorCode string, description string) {
	challenge := fmt.Sprintf("Bearer resource_metadata=%q", p.cfg.ExternalURL+OauthProtectedResourceEndpoint)
	if errorCode != "" {
		challenge += fmt.Sprintf(", error=%q, error_description=%q", errorCode, description)
	}
	c.Header("WWW-Authenticate", challenge)
	body := gin.H{"error": "unauthorized"}
	if errorCode != "" {
		body = gin.H{"error": errorCode, "error_description": description}
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, body)
}

func (p *ProxyRouter) handleProxy(c *gin.Context) {
	authHeader := c.Request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		p.abortUnauthorized(c, "", "")
		return
	}
	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.cfg.PublicKey, nil
	},
		jwt.WithIssuer(p.cfg.ExternalURL),
		jwt.WithAudience(p.cfg.ExternalURL),
		jwt.WithLeeway(p.cfg.ClockSkew),
	)

	if err != nil || !token.Valid {
		p.abortUnauthorized(c, "invalid_token", "the access token is invalid or expired")
		return
	}

	if p.cfg.HTTPStreamingOnly && isSSEGetRequest(c.Request) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{"error": "SSE (GET) streaming is not supported by this backend; use POST-based HTTP streaming instead"})
		return
	}

	if !p.cfg.ForwardAuthorizationHeader {
		c.Request.Header.Del("Authorization")
	}
	for _, headerName := range p.cfg.HeaderMapping {
		c.Request.Header.Del(headerName)
	}
	for key, values := range p.cfg.ProxyHeaders {
		if strings.EqualFold(key, "Authorization") {
			c.Request.Header.Del("Authorization")
		}
		for _, value := range values {
			c.Request.Header.Add(key, value)
		}
	}

	if len(p.cfg.HeaderMapping) > 0 {
		var source any = map[string]any(claims)
		if p.cfg.HeaderMappingBase != "/" {
			val, err := jsonpointer.Get(source, p.cfg.HeaderMappingBase)
			if err != nil {
				source = nil
			} else {
				source = val
			}
		}
		if source != nil {
			for pointer, headerName := range p.cfg.HeaderMapping {
				val, err := jsonpointer.Get(source, pointer)
				if err != nil {
					continue
				}
				switch v := val.(type) {
				case string:
					c.Request.Header.Set(headerName, v)
				case []any:
					var parts []string
					for _, item := range v {
						if s, ok := item.(string); ok {
							parts = append(parts, s)
						}
					}
					c.Request.Header.Set(headerName, strings.Join(parts, ","))
				default:
					c.Request.Header.Set(headerName, fmt.Sprintf("%v", v))
				}
			}
		}
	}

	p.cfg.Proxy.ServeHTTP(c.Writer, c.Request)
}

func isSSEGetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, value := range strings.Split(accept, ",") {
		mediaType := strings.TrimSpace(strings.ToLower(value))
		if idx := strings.Index(mediaType, ";"); idx != -1 {
			mediaType = strings.TrimSpace(mediaType[:idx])
		}
		if mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}
