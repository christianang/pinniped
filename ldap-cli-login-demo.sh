#!/usr/bin/env bash

#
# This is a demo of using the spike code on this branch.
# It is idempotent and can be run multiple times.
#
# Assumes that your current working directory is the root of the Pinniped repo.
# Also assumes that you have already compiled and deployed the server-side apps
# using `hack/prepare-for-integration-tests.sh`.
#
# Depends on `step` which can be installed by `brew install step`.
#

set -euo pipefail

squid="127.0.0.1:12346"
issuer_host=pinniped-supervisor-nodeport.supervisor.svc.cluster.local
issuer="https://$issuer_host"
audience=my-workload-cluster-aud

# Scale down the apps to make looking at server logs easier.
#kubectl scale --replicas 1 -n supervisor deployment/pinniped-supervisor
#kubectl scale --replicas 1 -n concierge deployment/pinniped-concierge

# Create a CA and TLS serving certificates for the Supervisor.
step certificate create \
  "Supervisor CA" root_ca.crt root_ca.key \
  --profile root-ca \
  --no-password --insecure --force
step certificate create \
  "$issuer_host" tls.crt tls.key \
  --profile leaf \
  --not-after 8760h \
  --ca root_ca.crt --ca-key root_ca.key \
  --no-password --insecure --force

# Put the TLS certificate into a Secret for the Supervisor.
kubectl create secret tls -n supervisor my-federation-domain-tls --cert tls.crt --key tls.key \
  --dry-run=client --output yaml | kubectl apply -f -

# Make a FederationDomain using the TLS Secret from above.
cat <<EOF | kubectl apply --namespace supervisor -f -
apiVersion: config.supervisor.pinniped.dev/v1alpha1
kind: FederationDomain
metadata:
  name: my-federation-domain
spec:
  issuer: $issuer
  tls:
    secretName: my-federation-domain-tls
EOF

echo "Waiting for FederationDomain to initialize..."
sleep 5

# Test that the federation domain is working before we proceed.
https_proxy="$squid" curl -fLsS --cacert root_ca.crt "$issuer/.well-known/openid-configuration"

# Make a JWTAuthenticator which respects JWTs from the Supervisor's issuer.
# The issuer URL must be accessible from within the cluster for OIDC discovery.
cat <<EOF | kubectl apply -f -
apiVersion: authentication.concierge.pinniped.dev/v1alpha1
kind: JWTAuthenticator
metadata:
  name: my-jwt-authenticator
spec:
  issuer: $issuer
  audience: $audience
  tls:
    certificateAuthorityData: $(cat root_ca.crt | base64)
EOF

echo "Waiting for JWTAuthenticator to initialize..."
# Our integration tests wait 10 seconds, so use that same value here.
sleep 10

# Compile the CLI.
go build ./cmd/pinniped

# Use the CLI to get the kubeconfig.
./pinniped get kubeconfig >kubeconfig

# This spike's authorize endpoint hard-codes the downstream OIDC ID token username to be "some-ldap-username",
# so grant that user some RBAC permissions here.
kubectl create clusterrolebinding test-user-can-view --clusterrole view --user some-ldap-username \
  --dry-run=client --output yaml | kubectl apply -f -

# Clear the local CLI cache to ensure that the kubectl command will need to perform a fresh login.
rm -f $HOME/.config/pinniped/sessions.yaml

# Perform an LDAP login using the spike code. The CLI sends the username and password to the
# Supervisor's OIDC authorize endpoint as basic auth credentials. Use squid to resolve hostnames
# other than 127.0.0.1 because we need squid to resolve the issuer, but do not need squid to
# resolve the concierge and the Kube API server localhost port mappings.
https_proxy="$squid" no_proxy="127.0.0.1" kubectl --kubeconfig ./kubeconfig get pods -A
