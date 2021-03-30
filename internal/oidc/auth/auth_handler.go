// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a handler for the OIDC authorization endpoint.
package auth

import (
	"fmt"
	"net/http"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/httputil/httperr"
	"go.pinniped.dev/internal/httputil/securityheader"
	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/csrftoken"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/pkce"
)

func NewHandler(
	downstreamIssuer string,
	idpListGetter oidc.IDPListGetter,
	oauthHelperWithNullStorage fosite.OAuth2Provider,
	oauthHelperWithRealStorage fosite.OAuth2Provider,
	generateCSRF func() (csrftoken.CSRFToken, error),
	generatePKCE func() (pkce.Code, error),
	generateNonce func() (nonce.Nonce, error),
	upstreamStateEncoder oidc.Encoder,
	cookieCodec oidc.Codec,
) http.Handler {
	return securityheader.Wrap(httperr.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// Authorization Servers MUST support the use of the HTTP GET and POST methods defined in
			// RFC 2616 [RFC2616] at the Authorization Endpoint.
			return httperr.Newf(http.StatusMethodNotAllowed, "%s (try GET or POST)", r.Method)
		}

		csrfFromCookie := readCSRFCookie(r, cookieCodec)

		authorizeRequester, err := oauthHelperWithNullStorage.NewAuthorizeRequest(r.Context(), r)
		if err != nil {
			plog.Info("authorize request error", oidc.FositeErrorForLog(err)...)
			oauthHelperWithNullStorage.WriteAuthorizeError(w, authorizeRequester, err)
			return nil
		}

		var upstreamIDP provider.UpstreamOIDCIdentityProviderI
		// TODO this would need to look up the IDP and either return an OIDC or LDAP IDP
		//upstreamIDP, err := chooseUpstreamIDP(idpListGetter)
		//if err != nil {
		//	plog.WarningErr("authorize upstream config", err)
		//	return err
		//}

		// Grant the openid scope (for now) if they asked for it so that `NewAuthorizeResponse` will perform its OIDC validations.
		oidc.GrantScopeIfRequested(authorizeRequester, coreosoidc.ScopeOpenID)
		// There don't seem to be any validations inside `NewAuthorizeResponse` related to the offline_access scope
		// at this time, however we will temporarily grant the scope just in case that changes in a future release of fosite.
		oidc.GrantScopeIfRequested(authorizeRequester, coreosoidc.ScopeOfflineAccess)

		// Grant the pinniped:request-audience scope if requested.
		oidc.GrantScopeIfRequested(authorizeRequester, "pinniped:request-audience")

		// TODO We would check here if the upstreamIDP variable is of type LDAP.
		//  For our spike, we will just force ourselves into the LDAP IDP branch.
		if true { // if this was a request to log in to an LDAP IDP...
			// "authenticate" basic auth creds by checking that they match username/password
			username, password, basicAuthExists := r.BasicAuth()
			if !basicAuthExists {
				// in the future, if we wanted to, this could redirect to a web-based login page. for now,
				// we will simply return an error and therefore require basic auth for all LDAP IDP logins.
				//
				// TODO for a real implementation, according to the OIDC spec 3.1.2.6 (second paragraph), we should
				//  be returning this error via a redirect to the client's redirect uri. we can get fosite's
				//  help here.
				return httperr.New(http.StatusUnauthorized, "expected basic auth")
			}

			// if they don't match, then return some failure as the authorize response
			if !(username == "fake-username" && password == "password123") {
				// TODO as above, for a real implementation, we will want to return an error according to OIDC spec
				//  3.1.2.6 (second paragraph).
				return httperr.New(http.StatusUnauthorized, "username/password does not match")
			}

			// make up fake downstream username and downstream groups and create downstream session (see callback_handler.go:94)
			now := time.Now().UTC()
			openIDSession := &openid.DefaultSession{
				Claims: &jwt.IDTokenClaims{
					Subject:     "some-ldap-subject", // TODO: pull this from actual LDAP IDP
					RequestedAt: now,
					AuthTime:    now,
				},
			}
			openIDSession.Claims.Extra = map[string]interface{}{
				oidc.DownstreamUsernameClaim: "some-ldap-username",                               // TODO: pull this from actual LDAP IDP
				oidc.DownstreamGroupsClaim:   []string{"some-ldap-group-1", "some-ldap-group-2"}, // TODO: pull this from actual LDAP IDP
			}

			// create authorize response (see callback_handler.go:95)
			authorizeResponder, err := oauthHelperWithRealStorage.NewAuthorizeResponse(r.Context(), authorizeRequester, openIDSession)
			if err != nil {
				plog.WarningErr("error while generating and saving authcode", err, "upstreamName", "ldap")
				return httperr.Wrap(http.StatusInternalServerError, "error while generating and saving authcode", err)
			}

			// write authorize response (see callback_handler.go:101)
			oauthHelperWithRealStorage.WriteAuthorizeResponse(w, authorizeRequester, authorizeResponder)

			return nil
		}

		now := time.Now()
		_, err = oauthHelperWithNullStorage.NewAuthorizeResponse(r.Context(), authorizeRequester, &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				// Temporary claim values to allow `NewAuthorizeResponse` to perform other OIDC validations.
				Subject:     "none",
				AuthTime:    now,
				RequestedAt: now,
			},
		})
		if err != nil {
			plog.Info("authorize response error", oidc.FositeErrorForLog(err)...)
			oauthHelperWithNullStorage.WriteAuthorizeError(w, authorizeRequester, err)
			return nil
		}

		csrfValue, nonceValue, pkceValue, err := generateValues(generateCSRF, generateNonce, generatePKCE)
		if err != nil {
			plog.Error("authorize generate error", err)
			return err
		}
		if csrfFromCookie != "" {
			csrfValue = csrfFromCookie
		}

		upstreamOAuthConfig := oauth2.Config{
			ClientID: upstreamIDP.GetClientID(),
			Endpoint: oauth2.Endpoint{
				AuthURL: upstreamIDP.GetAuthorizationURL().String(),
			},
			RedirectURL: fmt.Sprintf("%s/callback", downstreamIssuer),
			Scopes:      upstreamIDP.GetScopes(),
		}

		encodedStateParamValue, err := upstreamStateParam(
			authorizeRequester,
			upstreamIDP.GetName(),
			nonceValue,
			csrfValue,
			pkceValue,
			upstreamStateEncoder,
		)
		if err != nil {
			plog.Error("authorize upstream state param error", err)
			return err
		}

		if csrfFromCookie == "" {
			// We did not receive an incoming CSRF cookie, so write a new one.
			err := addCSRFSetCookieHeader(w, csrfValue, cookieCodec)
			if err != nil {
				plog.Error("error setting CSRF cookie", err)
				return err
			}
		}

		authCodeOptions := []oauth2.AuthCodeOption{
			oauth2.AccessTypeOffline,
			nonceValue.Param(),
			pkceValue.Challenge(),
			pkceValue.Method(),
		}

		promptParam := r.Form.Get("prompt")
		if promptParam != "" && oidc.ScopeWasRequested(authorizeRequester, coreosoidc.ScopeOpenID) {
			authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("prompt", promptParam))
		}

		http.Redirect(w, r,
			upstreamOAuthConfig.AuthCodeURL(
				encodedStateParamValue,
				authCodeOptions...,
			),
			302,
		)

		return nil
	}))
}

func readCSRFCookie(r *http.Request, codec oidc.Decoder) csrftoken.CSRFToken {
	receivedCSRFCookie, err := r.Cookie(oidc.CSRFCookieName)
	if err != nil {
		// Error means that the cookie was not found
		return ""
	}

	var csrfFromCookie csrftoken.CSRFToken
	err = codec.Decode(oidc.CSRFCookieEncodingName, receivedCSRFCookie.Value, &csrfFromCookie)
	if err != nil {
		// We can ignore any errors and just make a new cookie. Hopefully this will
		// make the user experience better if, for example, the server rotated
		// cookie signing keys and then a user submitted a very old cookie.
		return ""
	}

	return csrfFromCookie
}

func chooseUpstreamIDP(idpListGetter oidc.IDPListGetter) (provider.UpstreamOIDCIdentityProviderI, error) {
	allUpstreamIDPs := idpListGetter.GetIDPList()
	if len(allUpstreamIDPs) == 0 {
		return nil, httperr.New(
			http.StatusUnprocessableEntity,
			"No upstream providers are configured",
		)
	} else if len(allUpstreamIDPs) > 1 {
		var upstreamIDPNames []string
		for _, idp := range allUpstreamIDPs {
			upstreamIDPNames = append(upstreamIDPNames, idp.GetName())
		}

		plog.Warning("Too many upstream providers are configured (found: %s)", upstreamIDPNames)

		return nil, httperr.New(
			http.StatusUnprocessableEntity,
			"Too many upstream providers are configured (support for multiple upstreams is not yet implemented)",
		)
	}
	return allUpstreamIDPs[0], nil
}

func generateValues(
	generateCSRF func() (csrftoken.CSRFToken, error),
	generateNonce func() (nonce.Nonce, error),
	generatePKCE func() (pkce.Code, error),
) (csrftoken.CSRFToken, nonce.Nonce, pkce.Code, error) {
	csrfValue, err := generateCSRF()
	if err != nil {
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating CSRF token", err)
	}
	nonceValue, err := generateNonce()
	if err != nil {
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating nonce param", err)
	}
	pkceValue, err := generatePKCE()
	if err != nil {
		return "", "", "", httperr.Wrap(http.StatusInternalServerError, "error generating PKCE param", err)
	}
	return csrfValue, nonceValue, pkceValue, nil
}

func upstreamStateParam(
	authorizeRequester fosite.AuthorizeRequester,
	upstreamName string,
	nonceValue nonce.Nonce,
	csrfValue csrftoken.CSRFToken,
	pkceValue pkce.Code,
	encoder oidc.Encoder,
) (string, error) {
	stateParamData := oidc.UpstreamStateParamData{
		AuthParams:    authorizeRequester.GetRequestForm().Encode(),
		UpstreamName:  upstreamName,
		Nonce:         nonceValue,
		CSRFToken:     csrfValue,
		PKCECode:      pkceValue,
		FormatVersion: oidc.UpstreamStateParamFormatVersion,
	}
	encodedStateParamValue, err := encoder.Encode(oidc.UpstreamStateParamEncodingName, stateParamData)
	if err != nil {
		return "", httperr.Wrap(http.StatusInternalServerError, "error encoding upstream state param", err)
	}
	return encodedStateParamValue, nil
}

func addCSRFSetCookieHeader(w http.ResponseWriter, csrfValue csrftoken.CSRFToken, codec oidc.Encoder) error {
	encodedCSRFValue, err := codec.Encode(oidc.CSRFCookieEncodingName, csrfValue)
	if err != nil {
		return httperr.Wrap(http.StatusInternalServerError, "error encoding CSRF cookie", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oidc.CSRFCookieName,
		Value:    encodedCSRFValue,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Path:     "/",
	})

	return nil
}
