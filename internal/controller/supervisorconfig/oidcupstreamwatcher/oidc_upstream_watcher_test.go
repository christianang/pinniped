// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcupstreamwatcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/oidctestutil"
	"go.pinniped.dev/internal/testutil/testlogger"
	"go.pinniped.dev/internal/upstreamoidc"
)

func TestOIDCUpstreamWatcherControllerFilterSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		secret     metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name: "a secret of the right type",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/oidc-client",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "a secret of the wrong type",
			secret: &corev1.Secret{
				Type:       "secrets.pinniped.dev/not-the-oidc-client-type",
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
		{
			name: "resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fakePinnipedClient := pinnipedfake.NewSimpleClientset()
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			fakeKubeClient := fake.NewSimpleClientset()
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			testLog := testlogger.New(t)
			cache := provider.NewDynamicUpstreamIDPProvider()
			cache.SetOIDCIdentityProviders([]provider.UpstreamOIDCIdentityProviderI{
				&upstreamoidc.ProviderConfig{Name: "initial-entry"},
			})
			secretInformer := kubeInformers.Core().V1().Secrets()
			withInformer := testutil.NewObservableWithInformerOption()

			New(
				cache,
				nil,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				secretInformer,
				testLog,
				withInformer.WithInformer,
			)

			unrelated := corev1.Secret{}
			filter := withInformer.GetFilterForInformer(secretInformer)
			require.Equal(t, test.wantAdd, filter.Add(test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(&unrelated, test.secret))
			require.Equal(t, test.wantUpdate, filter.Update(test.secret, &unrelated))
			require.Equal(t, test.wantDelete, filter.Delete(test.secret))
		})
	}
}

func TestOIDCUpstreamWatcherControllerSync(t *testing.T) {
	t.Parallel()
	now := metav1.NewTime(time.Now().UTC())
	earlier := metav1.NewTime(now.Add(-1 * time.Hour).UTC())

	// Start another test server that answers discovery successfully.
	testIssuerCA, testIssuerURL := newTestIssuer(t)
	testIssuerCABase64 := base64.StdEncoding.EncodeToString([]byte(testIssuerCA))
	testIssuerAuthorizeURL, err := url.Parse("https://example.com/authorize")
	require.NoError(t, err)

	var (
		testNamespace        = "test-namespace"
		testName             = "test-name"
		testSecretName       = "test-client-secret"
		testAdditionalScopes = []string{"scope1", "scope2", "scope3"}
		testExpectedScopes   = []string{"openid", "scope1", "scope2", "scope3"}
		testClientID         = "test-oidc-client-id"
		testClientSecret     = "test-oidc-client-secret"
		testValidSecretData  = map[string][]byte{"clientID": []byte(testClientID), "clientSecret": []byte(testClientSecret)}
		testGroupsClaim      = "test-groups-claim"
		testUsernameClaim    = "test-username-claim"
	)
	tests := []struct {
		name                   string
		inputUpstreams         []runtime.Object
		inputSecrets           []runtime.Object
		wantErr                string
		wantLogs               []string
		wantResultingCache     []provider.UpstreamOIDCIdentityProviderI
		wantResultingUpstreams []v1alpha1.OIDCIdentityProvider
	}{
		{
			name: "no upstreams",
		},
		{
			name: "missing secret",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL,
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{},
			wantErr:      controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="secret \"test-client-secret\" not found" "reason"="SecretNotFound" "status"="False" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="secret \"test-client-secret\" not found" "name"="test-name" "namespace"="test-namespace" "reason"="SecretNotFound" "type"="ClientCredentialsValid"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretNotFound",
							Message:            `secret "test-client-secret" not found`,
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "discovered issuer configuration",
						},
					},
				},
			}},
		},
		{
			name: "secret has wrong type",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL,
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "some-other-type",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="referenced Secret \"test-client-secret\" has wrong type \"some-other-type\" (should be \"secrets.pinniped.dev/oidc-client\")" "reason"="SecretWrongType" "status"="False" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="referenced Secret \"test-client-secret\" has wrong type \"some-other-type\" (should be \"secrets.pinniped.dev/oidc-client\")" "name"="test-name" "namespace"="test-namespace" "reason"="SecretWrongType" "type"="ClientCredentialsValid"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretWrongType",
							Message:            `referenced Secret "test-client-secret" has wrong type "some-other-type" (should be "secrets.pinniped.dev/oidc-client")`,
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "discovered issuer configuration",
						},
					},
				},
			}},
		},
		{
			name: "secret is missing key",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL,
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="referenced Secret \"test-client-secret\" is missing required keys [\"clientID\" \"clientSecret\"]" "reason"="SecretMissingKeys" "status"="False" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="referenced Secret \"test-client-secret\" is missing required keys [\"clientID\" \"clientSecret\"]" "name"="test-name" "namespace"="test-namespace" "reason"="SecretMissingKeys" "type"="ClientCredentialsValid"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "SecretMissingKeys",
							Message:            `referenced Secret "test-client-secret" is missing required keys ["clientID" "clientSecret"]`,
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "discovered issuer configuration",
						},
					},
				},
			}},
		},
		{
			name: "TLS CA bundle is invalid base64",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name"},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &v1alpha1.TLSSpec{
						CertificateAuthorityData: "invalid-base64",
					},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: append(testAdditionalScopes, "xyz", "openid")},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="spec.certificateAuthorityData is invalid: illegal base64 data at input byte 7" "reason"="InvalidTLSConfig" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="spec.certificateAuthorityData is invalid: illegal base64 data at input byte 7" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidTLSConfig" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidTLSConfig",
							Message:            `spec.certificateAuthorityData is invalid: illegal base64 data at input byte 7`,
						},
					},
				},
			}},
		},
		{
			name: "TLS CA bundle does not have any certificates",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name"},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer: testIssuerURL,
					TLS: &v1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("not-a-pem-ca-bundle")),
					},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: append(testAdditionalScopes, "xyz", "openid")},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="spec.certificateAuthorityData is invalid: no certificates found" "reason"="InvalidTLSConfig" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="spec.certificateAuthorityData is invalid: no certificates found" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidTLSConfig" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidTLSConfig",
							Message:            `spec.certificateAuthorityData is invalid: no certificates found`,
						},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              "invalid-url-that-is-really-really-long",
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "msg"="failed to perform OIDC discovery" "error"="Get \"invalid-url-that-is-really-really-long/.well-known/openid-configuration\": unsupported protocol scheme \"\"" "issuer"="invalid-url-that-is-really-really-long" "name"="test-name" "namespace"="test-namespace"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to perform OIDC discovery against \"invalid-url-that-is-really-really-long\":\nGet \"invalid-url-that-is-really-really-long/.well-known/openid-configuration\": unsupported protocol  [truncated 9 chars]" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to perform OIDC discovery against \"invalid-url-that-is-really-really-long\":\nGet \"invalid-url-that-is-really-really-long/.well-known/openid-configuration\": unsupported protocol  [truncated 9 chars]" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message: `failed to perform OIDC discovery against "invalid-url-that-is-really-really-long":
Get "invalid-url-that-is-really-really-long/.well-known/openid-configuration": unsupported protocol  [truncated 9 chars]`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns invalid authorize URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL + "/invalid",
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to parse authorization endpoint URL: parse \"%\": invalid URL escape \"%\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to parse authorization endpoint URL: parse \"%\": invalid URL escape \"%\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `failed to parse authorization endpoint URL: parse "%": invalid URL escape "%"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer returns insecure authorize URL",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL + "/insecure",
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="authorization endpoint URL scheme must be \"https\", not \"http\"" "reason"="InvalidResponse" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="authorization endpoint URL scheme must be \"https\", not \"http\"" "name"="test-name" "namespace"="test-namespace" "reason"="InvalidResponse" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "InvalidResponse",
							Message:            `authorization endpoint URL scheme must be "https", not "http"`,
						},
					},
				},
			}},
		},
		{
			name: "upstream becomes valid",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "test-name"},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL,
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: append(testAdditionalScopes, "xyz", "openid")},
					Claims:              v1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{Type: "ClientCredentialsValid", Status: "False", LastTransitionTime: earlier, Reason: "SomeError1", Message: "some previous error 1"},
						{Type: "OIDCDiscoverySucceeded", Status: "False", LastTransitionTime: earlier, Reason: "SomeError2", Message: "some previous error 2"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{
				&oidctestutil.TestUpstreamOIDCIdentityProvider{
					Name:             testName,
					ClientID:         testClientID,
					AuthorizationURL: *testIssuerAuthorizeURL,
					Scopes:           append(testExpectedScopes, "xyz"),
					UsernameClaim:    testUsernameClaim,
					GroupsClaim:      testGroupsClaim,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: now, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: now, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
		},
		{
			name: "existing valid upstream",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL,
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
					Claims:              v1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{
				&oidctestutil.TestUpstreamOIDCIdentityProvider{
					Name:             testName,
					ClientID:         testClientID,
					AuthorizationURL: *testIssuerAuthorizeURL,
					Scopes:           testExpectedScopes,
					UsernameClaim:    testUsernameClaim,
					GroupsClaim:      testGroupsClaim,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "existing valid upstream with trailing slash",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL + "/ends-with-slash/",
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
					Claims:              v1alpha1.OIDCClaims{Groups: testGroupsClaim, Username: testUsernameClaim},
				},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials"},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration"},
					},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantLogs: []string{
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="discovered issuer configuration" "reason"="Success" "status"="True" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{
				&oidctestutil.TestUpstreamOIDCIdentityProvider{
					Name:             testName,
					ClientID:         testClientID,
					AuthorizationURL: *testIssuerAuthorizeURL,
					Scopes:           testExpectedScopes,
					UsernameClaim:    testUsernameClaim,
					GroupsClaim:      testGroupsClaim,
				},
			},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName, Generation: 1234},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Ready",
					Conditions: []v1alpha1.Condition{
						{Type: "ClientCredentialsValid", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "loaded client credentials", ObservedGeneration: 1234},
						{Type: "OIDCDiscoverySucceeded", Status: "True", LastTransitionTime: earlier, Reason: "Success", Message: "discovered issuer configuration", ObservedGeneration: 1234},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL, missing trailing slash",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL + "/ends-with-slash",
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "msg"="failed to perform OIDC discovery" "error"="oidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\"" "issuer"="` + testIssuerURL + `/ends-with-slash" "name"="test-name" "namespace"="test-namespace"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/ends-with-slash\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\"" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/ends-with-slash\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/ends-with-slash\" got \"` + testIssuerURL + `/ends-with-slash/\"" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/ends-with-slash":
oidc: issuer did not match the issuer returned by provider, expected "` + testIssuerURL + `/ends-with-slash" got "` + testIssuerURL + `/ends-with-slash/"`,
						},
					},
				},
			}},
		},
		{
			name: "issuer is invalid URL, extra trailing slash",
			inputUpstreams: []runtime.Object{&v1alpha1.OIDCIdentityProvider{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Spec: v1alpha1.OIDCIdentityProviderSpec{
					Issuer:              testIssuerURL + "/",
					TLS:                 &v1alpha1.TLSSpec{CertificateAuthorityData: testIssuerCABase64},
					Client:              v1alpha1.OIDCClient{SecretName: testSecretName},
					AuthorizationConfig: v1alpha1.OIDCAuthorizationConfig{AdditionalScopes: testAdditionalScopes},
				},
			}},
			inputSecrets: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testSecretName},
				Type:       "secrets.pinniped.dev/oidc-client",
				Data:       testValidSecretData,
			}},
			wantErr: controllerlib.ErrSyntheticRequeue.Error(),
			wantLogs: []string{
				`oidc-upstream-observer "msg"="failed to perform OIDC discovery" "error"="oidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\"" "issuer"="` + testIssuerURL + `/" "name"="test-name" "namespace"="test-namespace"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="loaded client credentials" "reason"="Success" "status"="True" "type"="ClientCredentialsValid"`,
				`oidc-upstream-observer "level"=0 "msg"="updated condition" "name"="test-name" "namespace"="test-namespace" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\"" "reason"="Unreachable" "status"="False" "type"="OIDCDiscoverySucceeded"`,
				`oidc-upstream-observer "msg"="found failing condition" "error"="OIDCIdentityProvider has a failing condition" "message"="failed to perform OIDC discovery against \"` + testIssuerURL + `/\":\noidc: issuer did not match the issuer returned by provider, expected \"` + testIssuerURL + `/\" got \"` + testIssuerURL + `\"" "name"="test-name" "namespace"="test-namespace" "reason"="Unreachable" "type"="OIDCDiscoverySucceeded"`,
			},
			wantResultingCache: []provider.UpstreamOIDCIdentityProviderI{},
			wantResultingUpstreams: []v1alpha1.OIDCIdentityProvider{{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testName},
				Status: v1alpha1.OIDCIdentityProviderStatus{
					Phase: "Error",
					Conditions: []v1alpha1.Condition{
						{
							Type:               "ClientCredentialsValid",
							Status:             "True",
							LastTransitionTime: now,
							Reason:             "Success",
							Message:            "loaded client credentials",
						},
						{
							Type:               "OIDCDiscoverySucceeded",
							Status:             "False",
							LastTransitionTime: now,
							Reason:             "Unreachable",
							Message: `failed to perform OIDC discovery against "` + testIssuerURL + `/":
oidc: issuer did not match the issuer returned by provider, expected "` + testIssuerURL + `/" got "` + testIssuerURL + `"`,
						},
					},
				},
			}},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fakePinnipedClient := pinnipedfake.NewSimpleClientset(tt.inputUpstreams...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClient, 0)
			fakeKubeClient := fake.NewSimpleClientset(tt.inputSecrets...)
			kubeInformers := informers.NewSharedInformerFactory(fakeKubeClient, 0)
			testLog := testlogger.New(t)
			cache := provider.NewDynamicUpstreamIDPProvider()
			cache.SetOIDCIdentityProviders([]provider.UpstreamOIDCIdentityProviderI{
				&upstreamoidc.ProviderConfig{Name: "initial-entry"},
			})

			controller := New(
				cache,
				fakePinnipedClient,
				pinnipedInformers.IDP().V1alpha1().OIDCIdentityProviders(),
				kubeInformers.Core().V1().Secrets(),
				testLog,
				controllerlib.WithInformer,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, strings.Join(tt.wantLogs, "\n"), strings.Join(testLog.Lines(), "\n"))

			actualIDPList := cache.GetOIDCIdentityProviders()
			require.Equal(t, len(tt.wantResultingCache), len(actualIDPList))
			for i := range actualIDPList {
				actualIDP := actualIDPList[i].(*upstreamoidc.ProviderConfig)
				require.Equal(t, tt.wantResultingCache[i].GetName(), actualIDP.GetName())
				require.Equal(t, tt.wantResultingCache[i].GetClientID(), actualIDP.GetClientID())
				require.Equal(t, tt.wantResultingCache[i].GetAuthorizationURL().String(), actualIDP.GetAuthorizationURL().String())
				require.Equal(t, tt.wantResultingCache[i].GetUsernameClaim(), actualIDP.GetUsernameClaim())
				require.Equal(t, tt.wantResultingCache[i].GetGroupsClaim(), actualIDP.GetGroupsClaim())
				require.ElementsMatch(t, tt.wantResultingCache[i].GetScopes(), actualIDP.GetScopes())
			}

			actualUpstreams, err := fakePinnipedClient.IDPV1alpha1().OIDCIdentityProviders(testNamespace).List(ctx, metav1.ListOptions{})
			require.NoError(t, err)

			// Assert on the expected Status of the upstreams. Preprocess the upstreams a bit so that they're easier to assert against.
			require.ElementsMatch(t, tt.wantResultingUpstreams, normalizeOIDCUpstreams(actualUpstreams.Items, now))

			// Running the sync() a second time should be idempotent except for logs, and should return the same error.
			// This also helps exercise code paths where the OIDC provider discovery hits cache.
			if err := controllerlib.TestSync(t, controller, syncCtx); tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func normalizeOIDCUpstreams(upstreams []v1alpha1.OIDCIdentityProvider, now metav1.Time) []v1alpha1.OIDCIdentityProvider {
	result := make([]v1alpha1.OIDCIdentityProvider, 0, len(upstreams))
	for _, u := range upstreams {
		normalized := u.DeepCopy()

		// We're only interested in comparing the status, so zero out the spec.
		normalized.Spec = v1alpha1.OIDCIdentityProviderSpec{}

		// Round down the LastTransitionTime values to `now` if they were just updated. This makes
		// it much easier to encode assertions about the expected timestamps.
		for i := range normalized.Status.Conditions {
			if time.Since(normalized.Status.Conditions[i].LastTransitionTime.Time) < 5*time.Second {
				normalized.Status.Conditions[i].LastTransitionTime = now
			}
		}
		result = append(result, *normalized)
	}

	return result
}

func newTestIssuer(t *testing.T) (string, string) {
	mux := http.NewServeMux()
	caBundlePEM, testURL := testutil.TLSTestServer(t, mux.ServeHTTP)

	type providerJSON struct {
		Issuer   string `json:"issuer"`
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
		JWKSURL  string `json:"jwks_uri"`
	}

	// At the root of the server, serve an issuer with a valid discovery response.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:  testURL,
			AuthURL: "https://example.com/authorize",
		})
	})

	// At "/invalid", serve an issuer that returns an invalid authorization URL (not parseable).
	mux.HandleFunc("/invalid/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:  testURL + "/invalid",
			AuthURL: "%",
		})
	})

	// At "/insecure", serve an issuer that returns an insecure authorization URL (not https://).
	mux.HandleFunc("/insecure/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:  testURL + "/insecure",
			AuthURL: "http://example.com/authorize",
		})
	})

	// handle the four issuer with trailing slash configs

	// valid case in= out=
	// handled above at the root of testURL

	// valid case in=/ out=/
	mux.HandleFunc("/ends-with-slash/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(&providerJSON{
			Issuer:  testURL + "/ends-with-slash/",
			AuthURL: "https://example.com/authorize",
		})
	})

	// invalid case in= out=/
	// can be tested using /ends-with-slash/ endpoint

	// invalid case in=/ out=
	// can be tested using root endpoint

	return caBundlePEM, testURL
}
