package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
)

// withRateLimit prepends the login rate-limit middleware when configured.
func (a *AuthRouter) withRateLimit(handlers ...gin.HandlerFunc) []gin.HandlerFunc {
	if a.loginRateLimit == nil {
		return handlers
	}
	return append([]gin.HandlerFunc{a.loginRateLimit}, handlers...)
}

func (a *AuthRouter) SetupRoutes(router gin.IRouter) {
	router.GET(LoginEndpoint, a.handleLogin)
	router.POST(LoginEndpoint, a.withRateLimit(a.RequireCSRF(), a.handleLoginPost)...)
	router.GET(LogoutEndpoint, a.handleLogout)
	if a.webAuthn != nil {
		router.POST(WebAuthnLoginBeginEndpoint, a.withRateLimit(a.RequireCSRF(), a.handleWebAuthnLoginBegin)...)
		router.POST(WebAuthnLoginFinishEndpoint, a.withRateLimit(a.RequireCSRF(), a.handleWebAuthnLoginFinish)...)
		router.POST(WebAuthnRegisterBeginEndpoint, a.RequireAuth(), a.RequireCSRF(), a.handleWebAuthnRegisterBegin)
		router.POST(WebAuthnRegisterFinishEndpoint, a.RequireAuth(), a.RequireCSRF(), a.handleWebAuthnRegisterFinish)
		router.GET(SettingsEndpoint, a.RequireAuth(), a.handleSettings)
		router.POST(SettingsPasswordEndpoint, a.RequireAuth(), a.RequireCSRF(), a.handleSettingsPassword)
		router.POST(SettingsCredentialDeleteEndpoint, a.RequireAuth(), a.RequireCSRF(), a.handleSettingsCredentialDelete)
		router.POST(SettingsClientRevokeEndpoint, a.RequireAuth(), a.RequireCSRF(), a.handleSettingsClientRevoke)
		router.POST(SettingsGrantRevokeEndpoint, a.RequireAuth(), a.RequireCSRF(), a.handleSettingsGrantRevoke)
		router.POST(SettingsRevokeAllEndpoint, a.RequireAuth(), a.RequireCSRF(), a.handleSettingsRevokeAll)
	}
	for _, provider := range a.providers {
		router.GET(provider.RedirectURL(), func(c *gin.Context) {
			session := sessions.Default(c)
			state := session.Get(SessionKeyOAuthState)
			if state == nil {
				a.renderError(c, errors.New("OAuth state is missing"))
				return
			}
			token, err := provider.Exchange(c, state.(string))
			if err != nil {
				a.renderError(c, err)
				return
			}
			ok, user, userInfo, err := provider.Authorization(c, token)
			if err != nil {
				a.renderError(c, err)
				return
			}
			if !ok {
				a.renderUnauthorized(c, user, provider.Name())
				return
			}
			session.Set(SessionKeyAuthorized, true)
			session.Set(SessionKeyUserID, user)
			if userInfo != nil {
				if len(a.userInfoFields) > 0 {
					userInfo = filterUserInfo(userInfo, a.userInfoFields)
				}
				if userInfoJSON, err := json.Marshal(userInfo); err == nil {
					session.Set(SessionKeyUserInfo, string(userInfoJSON))
				}
			}
			redirectTarget := takeRedirectTarget(session)
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, redirectTarget)
		})

		router.GET(provider.AuthURL(), func(c *gin.Context) {
			session := sessions.Default(c)

			state, err := utils.GenerateState()
			if err != nil {
				a.renderError(c, err)
				return
			}
			url, err := provider.AuthCodeURL(state)
			if err != nil {
				a.renderError(c, err)
				return
			}
			session.Set(SessionKeyOAuthState, state)
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, url)
		})
	}
}
