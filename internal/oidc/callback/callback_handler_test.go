// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/internal/oidc"
	"go.pinniped.dev/internal/oidc/jwks"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/pkg/oidcclient/nonce"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
	oidcpkce "go.pinniped.dev/pkg/oidcclient/pkce"
)

const (
	happyUpstreamIDPName = "upstream-idp-name"

	upstreamIssuer              = "https://my-upstream-issuer.com"
	upstreamSubject             = "abc123-some guid" // has a space character which should get escaped in URL
	queryEscapedUpstreamSubject = "abc123-some+guid"
	upstreamUsername            = "test-pinniped-username"

	upstreamUsernameClaim = "the-user-claim"
	upstreamGroupsClaim   = "the-groups-claim"

	happyUpstreamAuthcode    = "upstream-auth-code"
	happyUpstreamRedirectURI = "https://example.com/callback"

	happyDownstreamState        = "8b-state"
	happyDownstreamCSRF         = "test-csrf"
	happyDownstreamPKCE         = "test-pkce"
	happyDownstreamNonce        = "test-nonce"
	happyDownstreamStateVersion = "1"

	downstreamIssuer              = "https://my-downstream-issuer.com/path"
	downstreamRedirectURI         = "http://127.0.0.1/callback"
	downstreamClientID            = "pinniped-cli"
	downstreamNonce               = "some-nonce-value"
	downstreamPKCEChallenge       = "some-challenge"
	downstreamPKCEChallengeMethod = "S256"

	htmlContentType = "text/html; charset=utf-8"
)

var (
	upstreamGroupMembership        = []string{"test-pinniped-group-0", "test-pinniped-group-1"}
	happyDownstreamScopesRequested = []string{"openid"}
	happyDownstreamScopesGranted   = []string{"openid"}

	happyDownstreamRequestParamsQuery = url.Values{
		"response_type":         []string{"code"},
		"scope":                 []string{strings.Join(happyDownstreamScopesRequested, " ")},
		"client_id":             []string{downstreamClientID},
		"state":                 []string{happyDownstreamState},
		"nonce":                 []string{downstreamNonce},
		"code_challenge":        []string{downstreamPKCEChallenge},
		"code_challenge_method": []string{downstreamPKCEChallengeMethod},
		"redirect_uri":          []string{downstreamRedirectURI},
	}
	happyDownstreamRequestParams = happyDownstreamRequestParamsQuery.Encode()
)

func TestCallbackEndpoint(t *testing.T) {
	require.Len(t, happyDownstreamState, 8, "we expect fosite to allow 8 byte state params, so we want to test that boundary case")

	otherUpstreamOIDCIdentityProvider := oidctestutil.TestUpstreamOIDCIdentityProvider{
		Name:     "other-upstream-idp-name",
		ClientID: "other-some-client-id",
		Scopes:   []string{"other-scope1", "other-scope2"},
	}

	var stateEncoderHashKey = []byte("fake-hash-secret")
	var stateEncoderBlockKey = []byte("0123456789ABCDEF") // block encryption requires 16/24/32 bytes for AES
	var cookieEncoderHashKey = []byte("fake-hash-secret2")
	var cookieEncoderBlockKey = []byte("0123456789ABCDE2") // block encryption requires 16/24/32 bytes for AES
	require.NotEqual(t, stateEncoderHashKey, cookieEncoderHashKey)
	require.NotEqual(t, stateEncoderBlockKey, cookieEncoderBlockKey)

	var happyStateCodec = securecookie.New(stateEncoderHashKey, stateEncoderBlockKey)
	happyStateCodec.SetSerializer(securecookie.JSONEncoder{})
	var happyCookieCodec = securecookie.New(cookieEncoderHashKey, cookieEncoderBlockKey)
	happyCookieCodec.SetSerializer(securecookie.JSONEncoder{})

	happyState := happyUpstreamStateParam().Build(t, happyStateCodec)

	encodedIncomingCookieCSRFValue, err := happyCookieCodec.Encode("csrf", happyDownstreamCSRF)
	require.NoError(t, err)
	happyCSRFCookie := "__Host-pinniped-csrf=" + encodedIncomingCookieCSRFValue

	happyExchangeAndValidateTokensArgs := &oidctestutil.ExchangeAuthcodeAndValidateTokenArgs{
		Authcode:             happyUpstreamAuthcode,
		PKCECodeVerifier:     oidcpkce.Code(happyDownstreamPKCE),
		ExpectedIDTokenNonce: nonce.Nonce(happyDownstreamNonce),
		RedirectURI:          happyUpstreamRedirectURI,
	}

	// Note that fosite puts the granted scopes as a param in the redirect URI even though the spec doesn't seem to require it
	happyDownstreamRedirectLocationRegexp := downstreamRedirectURI + `\?code=([^&]+)&scope=openid&state=` + happyDownstreamState

	tests := []struct {
		name string

		idp        oidctestutil.TestUpstreamOIDCIdentityProvider
		method     string
		path       string
		csrfCookie string

		wantStatus                        int
		wantContentType                   string
		wantBody                          string
		wantRedirectLocationRegexp        string
		wantDownstreamGrantedScopes       []string
		wantDownstreamIDTokenSubject      string
		wantDownstreamIDTokenUsername     string
		wantDownstreamIDTokenGroups       []string
		wantDownstreamRequestedScopes     []string
		wantDownstreamNonce               string
		wantDownstreamPKCEChallenge       string
		wantDownstreamPKCEChallengeMethod string

		wantExchangeAndValidateTokensCall *oidctestutil.ExchangeAuthcodeAndValidateTokenArgs
	}{
		{
			name:                              "GET with good state and cookie and successful upstream token exchange returns 302 to downstream client callback with its state and code",
			idp:                               happyUpstream().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     upstreamUsername,
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream IDP provides no username or group claim configuration, so we use default username claim and skip groups",
			idp:                               happyUpstream().WithoutUsernameClaim().WithoutGroupsClaim().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is missing",
			idp: happyUpstream().WithUsernameClaim("email").
				WithIDTokenClaim("email", "joe@whitehouse.gov").Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with true value",
			idp: happyUpstream().WithUsernameClaim("email").
				WithIDTokenClaim("email", "joe@whitehouse.gov").
				WithIDTokenClaim("email_verified", true).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     "joe@whitehouse.gov",
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name: "upstream IDP configures username claim as anything other than special claim `email` and `email_verified` upstream claim is present with false value",
			idp: happyUpstream().WithUsernameClaim("some-claim").
				WithIDTokenClaim("some-claim", "joe").
				WithIDTokenClaim("email", "joe@whitehouse.gov").
				WithIDTokenClaim("email_verified", false).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound, // succeed despite `email_verified=false` because we're not using the email claim for anything
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     "joe",
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with illegal value",
			idp: happyUpstream().WithUsernameClaim("email").
				WithIDTokenClaim("email", "joe@whitehouse.gov").
				WithIDTokenClaim("email_verified", "supposed to be boolean").Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: email_verified claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name: "upstream IDP configures username claim as special claim `email` and `email_verified` upstream claim is present with false value",
			idp: happyUpstream().WithUsernameClaim("email").
				WithIDTokenClaim("email", "joe@whitehouse.gov").
				WithIDTokenClaim("email_verified", false).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: email_verified claim in upstream ID token has false value\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream IDP provides username claim configuration as `sub`, so the downstream token subject should be exactly what they asked for",
			idp:                               happyUpstream().WithUsernameClaim("sub").Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     upstreamSubject,
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream IDP's configured groups claim in the ID token has a non-array value",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamGroupsClaim, "notAnArrayGroup1 notAnArrayGroup2").Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     upstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"notAnArrayGroup1 notAnArrayGroup2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream IDP's configured groups claim in the ID token is a slice of interfaces",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamGroupsClaim, []interface{}{"group1", "group2"}).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     upstreamUsername,
			wantDownstreamIDTokenGroups:       []string{"group1", "group2"},
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},

		// Pre-upstream-exchange verification
		{
			name:            "PUT method is invalid",
			method:          http.MethodPut,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PUT (try GET)\n",
		},
		{
			name:            "POST method is invalid",
			method:          http.MethodPost,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: POST (try GET)\n",
		},
		{
			name:            "PATCH method is invalid",
			method:          http.MethodPatch,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: PATCH (try GET)\n",
		},
		{
			name:            "DELETE method is invalid",
			method:          http.MethodDelete,
			path:            newRequestPath().String(),
			wantStatus:      http.StatusMethodNotAllowed,
			wantContentType: htmlContentType,
			wantBody:        "Method Not Allowed: DELETE (try GET)\n",
		},
		{
			name:            "code param was not included on request",
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).WithoutCode().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: code param not found\n",
		},
		{
			name:            "state param was not included on request",
			method:          http.MethodGet,
			path:            newRequestPath().WithoutState().String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: state param not found\n",
		},
		{
			name:            "state param was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idp:             happyUpstream().Build(),
			method:          http.MethodGet,
			path:            newRequestPath().WithState("this-will-not-decode").String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error reading state\n",
		},
		{
			// This shouldn't happen in practice because the authorize endpoint should have already run the same
			// validations, but we would like to test the error handling in this endpoint anyway.
			name:   "state param contains authorization request params which fail validation",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery, map[string]string{"prompt": "none login"}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:                        happyCSRFCookie,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
			wantStatus:                        http.StatusInternalServerError,
			wantContentType:                   htmlContentType,
			wantBody:                          "Internal Server Error: error while generating and saving authcode\n",
		},
		{
			name:            "state's internal version does not match what we want",
			idp:             happyUpstream().Build(),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyUpstreamStateParam().WithStateVersion("wrong-state-version").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: state format version is invalid\n",
		},
		{
			name:   "state's downstream auth params element is invalid",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().WithState(happyUpstreamStateParam().
				WithAuthorizeRequestParams("the following is an invalid url encoding token, and therefore this is an invalid param: %z").
				Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error reading state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params are missing required value (e.g., client_id)",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().WithState(
				happyUpstreamStateParam().
					WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery, map[string]string{"client_id": ""}).Encode()).
					Build(t, happyStateCodec),
			).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusBadRequest,
			wantContentType: htmlContentType,
			wantBody:        "Bad Request: error using state downstream auth params\n",
		},
		{
			name:   "state's downstream auth params does not contain openid scope",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery, map[string]string{"scope": "profile email"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername:     upstreamUsername,
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamRequestedScopes:     []string{"profile", "email"},
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:   "state's downstream auth params also included offline_access scope",
			idp:    happyUpstream().Build(),
			method: http.MethodGet,
			path: newRequestPath().
				WithState(
					happyUpstreamStateParam().
						WithAuthorizeRequestParams(shallowCopyAndModifyQuery(happyDownstreamRequestParamsQuery, map[string]string{"scope": "openid offline_access"}).Encode()).
						Build(t, happyStateCodec),
				).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        downstreamRedirectURI + `\?code=([^&]+)&scope=openid\+offline_access&state=` + happyDownstreamState,
			wantDownstreamIDTokenUsername:     upstreamUsername,
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamRequestedScopes:     []string{"openid", "offline_access"},
			wantDownstreamGrantedScopes:       []string{"openid", "offline_access"},
			wantDownstreamIDTokenGroups:       upstreamGroupMembership,
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:            "the OIDCIdentityProvider CRD has been deleted",
			idp:             otherUpstreamOIDCIdentityProvider,
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusUnprocessableEntity,
			wantContentType: htmlContentType,
			wantBody:        "Unprocessable Entity: upstream provider not found\n",
		},
		{
			name:            "the CSRF cookie does not exist on request",
			idp:             happyUpstream().Build(),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF cookie is missing\n",
		},
		{
			name:            "cookie was not signed correctly, has expired, or otherwise cannot be decoded for any reason",
			idp:             happyUpstream().Build(),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyState).String(),
			csrfCookie:      "__Host-pinniped-csrf=this-value-was-not-signed-by-pinniped",
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: error reading CSRF cookie\n",
		},
		{
			name:            "cookie csrf value does not match state csrf value",
			idp:             happyUpstream().Build(),
			method:          http.MethodGet,
			path:            newRequestPath().WithState(happyUpstreamStateParam().WithCSRF("wrong-csrf-value").Build(t, happyStateCodec)).String(),
			csrfCookie:      happyCSRFCookie,
			wantStatus:      http.StatusForbidden,
			wantContentType: htmlContentType,
			wantBody:        "Forbidden: CSRF value does not match\n",
		},

		// Upstream exchange
		{
			name:                              "upstream auth code exchange fails",
			idp:                               happyUpstream().WithoutUpstreamAuthcodeExchangeError(errors.New("some error")).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusBadGateway,
			wantBody:                          "Bad Gateway: error exchanging and validating upstream tokens\n",
			wantContentType:                   htmlContentType,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token does not contain requested username claim",
			idp:                               happyUpstream().WithoutIDTokenClaim(upstreamUsernameClaim).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantBody:                          "Unprocessable Entity: no username claim in upstream ID token\n",
			wantContentType:                   htmlContentType,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token does not contain requested groups claim",
			idp:                               happyUpstream().WithoutIDTokenClaim(upstreamGroupsClaim).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusFound,
			wantRedirectLocationRegexp:        happyDownstreamRedirectLocationRegexp,
			wantBody:                          "",
			wantDownstreamIDTokenSubject:      upstreamIssuer + "?sub=" + queryEscapedUpstreamSubject,
			wantDownstreamIDTokenUsername:     upstreamUsername,
			wantDownstreamRequestedScopes:     happyDownstreamScopesRequested,
			wantDownstreamGrantedScopes:       happyDownstreamScopesGranted,
			wantDownstreamIDTokenGroups:       []string{},
			wantDownstreamNonce:               downstreamNonce,
			wantDownstreamPKCEChallenge:       downstreamPKCEChallenge,
			wantDownstreamPKCEChallengeMethod: downstreamPKCEChallengeMethod,
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token contains username claim with weird format",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamUsernameClaim, 42).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: username claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token does not contain iss claim when using default username claim config",
			idp:                               happyUpstream().WithIDTokenClaim("iss", "").WithoutUsernameClaim().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: issuer claim in upstream ID token missing\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token has an non-string iss claim when using default username claim config",
			idp:                               happyUpstream().WithIDTokenClaim("iss", 42).WithoutUsernameClaim().Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: issuer claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token contains groups claim with weird format",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamGroupsClaim, 42).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: groups claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token contains groups claim where one element is invalid",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamGroupsClaim, []interface{}{"foo", 7}).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: groups claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
		{
			name:                              "upstream ID token contains groups claim with invalid null type",
			idp:                               happyUpstream().WithIDTokenClaim(upstreamGroupsClaim, nil).Build(),
			method:                            http.MethodGet,
			path:                              newRequestPath().WithState(happyState).String(),
			csrfCookie:                        happyCSRFCookie,
			wantStatus:                        http.StatusUnprocessableEntity,
			wantContentType:                   htmlContentType,
			wantBody:                          "Unprocessable Entity: groups claim in upstream ID token has invalid format\n",
			wantExchangeAndValidateTokensCall: happyExchangeAndValidateTokensArgs,
		},
	}
	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			secrets := client.CoreV1().Secrets("some-namespace")

			// Configure fosite the same way that the production code would.
			// Inject this into our test subject at the last second so we get a fresh storage for every test.
			timeoutsConfiguration := oidc.DefaultOIDCTimeoutsConfiguration()
			oauthStore := oidc.NewKubeStorage(secrets, timeoutsConfiguration)
			hmacSecretFunc := func() []byte { return []byte("some secret - must have at least 32 bytes") }
			require.GreaterOrEqual(t, len(hmacSecretFunc()), 32, "fosite requires that hmac secrets have at least 32 bytes")
			jwksProviderIsUnused := jwks.NewDynamicJWKSProvider()
			oauthHelper := oidc.FositeOauth2Helper(oauthStore, downstreamIssuer, hmacSecretFunc, jwksProviderIsUnused, timeoutsConfiguration)

			idpLister := oidctestutil.NewUpstreamIDPListerBuilder().WithOIDC(&test.idp).Build()
			subject := NewHandler(idpLister, oauthHelper, happyStateCodec, happyCookieCodec, happyUpstreamRedirectURI)
			req := httptest.NewRequest(test.method, test.path, nil)
			if test.csrfCookie != "" {
				req.Header.Set("Cookie", test.csrfCookie)
			}
			rsp := httptest.NewRecorder()
			subject.ServeHTTP(rsp, req)
			t.Logf("response: %#v", rsp)
			t.Logf("response body: %q", rsp.Body.String())

			testutil.RequireSecurityHeaders(t, rsp)

			if test.wantExchangeAndValidateTokensCall != nil {
				require.Equal(t, 1, test.idp.ExchangeAuthcodeAndValidateTokensCallCount())
				test.wantExchangeAndValidateTokensCall.Ctx = req.Context()
				require.Equal(t, test.wantExchangeAndValidateTokensCall, test.idp.ExchangeAuthcodeAndValidateTokensArgs(0))
			} else {
				require.Equal(t, 0, test.idp.ExchangeAuthcodeAndValidateTokensCallCount())
			}

			require.Equal(t, test.wantStatus, rsp.Code)
			testutil.RequireEqualContentType(t, rsp.Header().Get("Content-Type"), test.wantContentType)

			if test.wantBody != "" {
				require.Equal(t, test.wantBody, rsp.Body.String())
			} else {
				require.Empty(t, rsp.Body.String())
			}

			if test.wantRedirectLocationRegexp != "" { //nolint:nestif // don't mind have several sequential if statements in this test
				require.Len(t, rsp.Header().Values("Location"), 1)
				oidctestutil.RequireAuthcodeRedirectLocation(
					t,
					rsp.Header().Get("Location"),
					test.wantRedirectLocationRegexp,
					client,
					secrets,
					oauthStore,
					test.wantDownstreamGrantedScopes,
					test.wantDownstreamIDTokenSubject,
					test.wantDownstreamIDTokenUsername,
					test.wantDownstreamIDTokenGroups,
					test.wantDownstreamRequestedScopes,
					test.wantDownstreamPKCEChallenge,
					test.wantDownstreamPKCEChallengeMethod,
					test.wantDownstreamNonce,
					downstreamClientID,
					downstreamRedirectURI,
				)
			}
		})
	}
}

type requestPath struct {
	code, state *string
}

func newRequestPath() *requestPath {
	c := happyUpstreamAuthcode
	s := "4321"
	return &requestPath{
		code:  &c,
		state: &s,
	}
}

func (r *requestPath) WithCode(code string) *requestPath {
	r.code = &code
	return r
}

func (r *requestPath) WithoutCode() *requestPath {
	r.code = nil
	return r
}

func (r *requestPath) WithState(state string) *requestPath {
	r.state = &state
	return r
}

func (r *requestPath) WithoutState() *requestPath {
	r.state = nil
	return r
}

func (r *requestPath) String() string {
	path := "/downstream-provider-name/callback?"
	params := url.Values{}
	if r.code != nil {
		params.Add("code", *r.code)
	}
	if r.state != nil {
		params.Add("state", *r.state)
	}
	return path + params.Encode()
}

type upstreamStateParamBuilder oidctestutil.ExpectedUpstreamStateParamFormat

func happyUpstreamStateParam() *upstreamStateParamBuilder {
	return &upstreamStateParamBuilder{
		U: happyUpstreamIDPName,
		P: happyDownstreamRequestParams,
		N: happyDownstreamNonce,
		C: happyDownstreamCSRF,
		K: happyDownstreamPKCE,
		V: happyDownstreamStateVersion,
	}
}

func (b upstreamStateParamBuilder) Build(t *testing.T, stateEncoder *securecookie.SecureCookie) string {
	state, err := stateEncoder.Encode("s", b)
	require.NoError(t, err)
	return state
}

func (b *upstreamStateParamBuilder) WithAuthorizeRequestParams(params string) *upstreamStateParamBuilder {
	b.P = params
	return b
}

func (b *upstreamStateParamBuilder) WithNonce(nonce string) *upstreamStateParamBuilder {
	b.N = nonce
	return b
}

func (b *upstreamStateParamBuilder) WithCSRF(csrf string) *upstreamStateParamBuilder {
	b.C = csrf
	return b
}

func (b *upstreamStateParamBuilder) WithPKCVE(pkce string) *upstreamStateParamBuilder {
	b.K = pkce
	return b
}

func (b *upstreamStateParamBuilder) WithStateVersion(version string) *upstreamStateParamBuilder {
	b.V = version
	return b
}

type upstreamOIDCIdentityProviderBuilder struct {
	idToken                    map[string]interface{}
	usernameClaim, groupsClaim string
	authcodeExchangeErr        error
}

func happyUpstream() *upstreamOIDCIdentityProviderBuilder {
	return &upstreamOIDCIdentityProviderBuilder{
		usernameClaim: upstreamUsernameClaim,
		groupsClaim:   upstreamGroupsClaim,
		idToken: map[string]interface{}{
			"iss":                 upstreamIssuer,
			"sub":                 upstreamSubject,
			upstreamUsernameClaim: upstreamUsername,
			upstreamGroupsClaim:   upstreamGroupMembership,
			"other-claim":         "should be ignored",
		},
	}
}

func (u *upstreamOIDCIdentityProviderBuilder) WithUsernameClaim(value string) *upstreamOIDCIdentityProviderBuilder {
	u.usernameClaim = value
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutUsernameClaim() *upstreamOIDCIdentityProviderBuilder {
	u.usernameClaim = ""
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutGroupsClaim() *upstreamOIDCIdentityProviderBuilder {
	u.groupsClaim = ""
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithIDTokenClaim(name string, value interface{}) *upstreamOIDCIdentityProviderBuilder {
	u.idToken[name] = value
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutIDTokenClaim(claim string) *upstreamOIDCIdentityProviderBuilder {
	delete(u.idToken, claim)
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) WithoutUpstreamAuthcodeExchangeError(err error) *upstreamOIDCIdentityProviderBuilder {
	u.authcodeExchangeErr = err
	return u
}

func (u *upstreamOIDCIdentityProviderBuilder) Build() oidctestutil.TestUpstreamOIDCIdentityProvider {
	return oidctestutil.TestUpstreamOIDCIdentityProvider{
		Name:          happyUpstreamIDPName,
		ClientID:      "some-client-id",
		UsernameClaim: u.usernameClaim,
		GroupsClaim:   u.groupsClaim,
		Scopes:        []string{"scope1", "scope2"},
		ExchangeAuthcodeAndValidateTokensFunc: func(ctx context.Context, authcode string, pkceCodeVerifier oidcpkce.Code, expectedIDTokenNonce nonce.Nonce) (*oidctypes.Token, error) {
			if u.authcodeExchangeErr != nil {
				return nil, u.authcodeExchangeErr
			}
			return &oidctypes.Token{IDToken: &oidctypes.IDToken{Claims: u.idToken}}, nil
		},
	}
}

func shallowCopyAndModifyQuery(query url.Values, modifications map[string]string) url.Values {
	copied := url.Values{}
	for key, value := range query {
		copied[key] = value
	}
	for key, value := range modifications {
		if value == "" {
			copied.Del(key)
		} else {
			copied[key] = []string{value}
		}
	}
	return copied
}
