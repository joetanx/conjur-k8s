## 1. Overview

### 1.1. How does Kubernetes integration with Conjur using JWT work?

The Kubernetes cluster API implements an OpenID Connect authentication (OIDC) endpoint at `https://<cluster-url>/.well-known/openid-configuration`
- Service accounts are issued with ServiceAccount tokens, which are in JSON Web Token (JWT) format
- Pods of Deployments can be associated with a ServiceAccount and are issued JWTs via [downward API](https://kubernetes.io/docs/concepts/workloads/pods/downward-api/)
  - Example JWT:
    ```json
    {
      "aud": [
        "https://conjur.vx/"
      ],
      "exp": 1693376769,
      "iat": 1693370769,
      "iss": "https://kubernetes.default.svc.cluster.local",
      "kubernetes.io": {
        "namespace": "app-cje",
        "pod": {
          "name": "p2f-68db995878-7hg8n",
          "uid": "861be607-ff6f-4bb6-850b-42b842e44a33"
        },
        "serviceaccount": {
          "name": "p2f",
          "uid": "ddb1ca36-0231-4ecc-81b8-25fd0d11a087"
        }
      },
      "nbf": 1693370769,
      "sub": "system:serviceaccount:app-cje:p2f"
    }
    ```
- The public keys of the JSON Web Key Set (JWKS) on the authentication endpoint can be used to validate the tokens
  - The public keys of the JWKS can be retrieve by running: `kubectl get --raw $(kubectl get --raw /.well-known/openid-configuration | jq -r '.jwks_uri')`
  - Example JWKS:
    ```json
    {
      "keys":[
        {
          "use":"sig",
          "kty":"RSA",
          "kid":"qgR3hxR6c9ortKnfd96TK8FfasK-L77vRoPtVz1z91o",
          "alg":"RS256",
          "n":"462bF75dDmlqY-PaVRTVpMkIQwIEakzt1MfKGXqbCGJRNYDbY4KRbn0aO5FcFv2-zgROmYVs5QJluCCUwrZ0odCX3GzhgdupRBENOnCI8E7_-Xg4AqT6uhjoV5tQWm0yJGxOw4WfXtAImkI0-RufQMRPPbJMVHyPBE_fSXCevaeoPo3QX_zniFcQiPBQpu9ONDLgGfS3zO7rc-Of8XXozpKGNImUxrUKFOtZADtpAgdzd392SNXItxuBzov8UavcwcvJdvGlKN0G_WIiBOzS88w5EvoOYMtDH8c_LeCB0qG6EPgNpPhIdicgfmj2aLkT25ALoXK1z3B7f13zMP5nHw",
          "e":"AQAB"
        }
      ]
    }
    ```

Ref: https://kubernetes.io/docs/reference/access-authn-authz/authentication/

Conjur leverages on the Kubernetes OIDC authentication endpoint as an Identity Provider (IdP) to authenticate workloads
- Validity of the JWTs can be verified against the JWKS
- Claims in the JWTs can be verified against configured host annotations for authorization checks

![overview](https://github.com/joetanx/conjur-k8s/assets/90442032/75398653-810c-44f1-b5b9-e82e8cc0b965)

### 1.2. Retrieving secrets from Conjur with [secrets provider for k8s](https://github.com/cyberark/secrets-provider-for-k8s)

### Push to file (p2f)

![p2f](https://github.com/joetanx/conjur-k8s/assets/90442032/6a8c564b-5e5f-43c6-9b1c-15d7585d43a5)

### Push to Kubernetes secrets (p2s)

#### Environment variables mode

![p2s-env](https://github.com/joetanx/conjur-k8s/assets/90442032/8577e1a7-7e1f-416e-8e35-180c7f5b97fb)

#### Volume mount mode

![p2s-vol](https://github.com/joetanx/conjur-k8s/assets/90442032/f26dca90-2b93-4529-bf31-23ce820ec055)

## 2. Setting up the integration

### 2.1. Lab details

#### Software Versions

- RHEL 9.2
- Conjur Enterprise 13.0
- Kubernetes 1.28

#### Servers

|Hostname|Role|
|---|---|
|conjur.vx|Conjur master|
|mysql.vx|MySQL server|
|kube.vx|Single-node Kubernetes cluster|

### 2.2. Kubernetes cluster

- This demo should work with any flavour of Kubernetes clusters (On-prem, AKS, EKS), but was tested with a single-node on-prem Kubernetes cluster in my lab
- For a guide to setup a single-node on-prem Kubernetes cluster: <https://github.com/joetanx/setup/blob/main/cri-o-kube.md>

### 2.3. Setup MySQL database

- Setup MySQL database according to this guide: <https://github.com/joetanx/setup/blob/main/mysql.md>

### 2.4. Setup Conjur master

- Setup Conjur master according to this guide: <https://github.com/joetanx/setup/blob/main/conjur.md>

## 3. Preparing Conjur configurations

There are 2 Conjur policies provider in the [`policies`](./policies) directory of this repository: `authn-jwt-k8s.yaml` and `k8s-hosts.yaml`

### 3.1. JWT authenticator policy

The policy [`authn-jwt-k8s.yaml`](./policies/authn-jwt-k8s.yaml) performs the following:

1. Define the JWT authenticator endpoint in Conjur

- Ref: [2. Define the JWT Authenticator endpoint in Conjur](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- Creates `conjur/authn-jwt/k8s` policy with the necessary variables
- Creates the `webservice` for the authenticator with `consumers` group allowed to authenticate to the webservice

2. Enable the seed generation service

- Ref: [6. Enable the seed generation service](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- Creates `conjur/seed-generation` policy
- Creates the `webservice` for the seed generation with `consumers` group allowed to authenticate to the webservice

### 3.2. Host identity policy

The policy [`k8s-hosts.yaml`](./policies/k8s-hosts.yaml) performs the following:

1. Define `jwt-apps/k8s` policy with:

- Host identities for:
  - Conjur Follower in Kubernetes identified by `system:serviceaccount:conjur:follower`
    - Ref: [2. Define an identity in Conjur for the Conjur Follower](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-conjfollower.htm)
  - Demo applications
    |Host identity|Service account|
    |---|---|
    |`p2f`|`system:serviceaccount:app-cje:p2f`|
    |`p2s-env`|`system:serviceaccount:app-cje:p2s-env`|
    |`p2s-vol`|`system:serviceaccount:app-cje:p2s-vol`|
    |`sl`|`system:serviceaccount:app-cje:sl`|
    - Ref: [2. Define the application as a Conjur host in policy + 3.Grant access to secrets](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-authn-client-authjwt.htm#Setuptheapplicationtoretrievesecrets)

2. The follower and demo applications are granted access the following permissions by adding them to the respective `consumers` group:
    |Host identity|Authorization|
    |---|---|
    |Follower|• Allowed to authenticate to `auth-jwt/k8s`<br>• Allowed to request seed|
    |Demo applications|• Allowed to authenticate to `auth-jwt/k8s`<br>• Allowed to retrieve secrets from `db_cityapp`|

> [!Note]
> 
> `k8s-hosts.yaml` builds on top of `app-vars.yaml` in <https://github.com/joetanx/setup/blob/main/conjur.md>
> 
> Loading `k8s-hosts.yaml` without having `app-vars.yaml` loaded previously will not work

Download and load the Conjur policy:

```console
curl -sLO https://github.com/joetanx/conjur-k8s/raw/main/policies/authn-jwt-k8s.yaml
curl -sLO https://github.com/joetanx/conjur-k8s/raw/main/policies/k8s-hosts.yaml
conjur policy load -b root -f authn-jwt-k8s.yaml
conjur policy load -b root -f k8s-hosts.yaml
```

### 3.3. Populate the variables required by the JWT Authenticator

Ref: [3. Populate the policy variables](https://docs.cyberark.com/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)

```console
PUBLIC_KEYS="$(kubectl get --raw $(kubectl get --raw /.well-known/openid-configuration | jq -r '.jwks_uri'))"
ISSUER="$(kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer')"
conjur variable set -i conjur/authn-jwt/k8s/public-keys -v "{\"type\":\"jwks\", \"value\":$PUBLIC_KEYS}"
conjur variable set -i conjur/authn-jwt/k8s/issuer -v $ISSUER
conjur variable set -i conjur/authn-jwt/k8s/token-app-property -v sub
conjur variable set -i conjur/authn-jwt/k8s/identity-path -v jwt-apps/k8s
conjur variable set -i conjur/authn-jwt/k8s/audience -v vxlab
```

### 3.4. Allowlist the JWT authenticator in Conjur

Ref:
- [4. Enable the JWT Authenticator in Conjur](https://docs.cyberark.com/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator)
- [Step 2: Allowlist the authenticators](https://docs.cyberark.com/AAM-DAP/Latest/en/Content/Operations/Services/authentication-types.htm#Allowlis)

> [!Note]
> 
> This step requires that the `authenticators` section in `/etc/conjur/config/conjur.yml` to be configured
> 
> Ref: [2.5. Allowlist the Conjur default authenticator](https://github.com/joetanx/setup/blob/main/conjur.md#25-allowlist-the-conjur-default-authenticator)

```console
podman exec conjur sed -i -e '/authenticators:/a\  - authn-jwt/k8s' /etc/conjur/config/conjur.yml
podman exec conjur evoke configuration apply
```

Verify that the Kubernetes authenticator is configured and allowlisted:

```console
curl -k https://conjur.vx/info
```

## 4. Preparing Kubernetes configurations

The Conjur master and follower information is passed to the follower and application pods using ConfigMaps

### 4.1. Create namespaces

```console
kubectl create namespace conjur
kubectl create namespace app-hc
kubectl create namespace app-cje
```

### 4.2. Prepare the necessary values as environments variables to be loaded into ConfigMaps:

```console
CA_CERT="$(curl -sL https://github.com/joetanx/conjur-k8s/raw/main/central.pem)"
CONJUR_MASTER_URL=https://conjur.vx
CONJUR_FOLLOWER_URL=https://follower.conjur.svc.cluster.local
AUTHENTICATOR_ID=k8s
CONJUR_ACCOUNT=cyberark
CONJUR_SEED_FILE_URL=$CONJUR_MASTER_URL/configuration/$CONJUR_ACCOUNT/seed/follower
CONJUR_AUTHN_URL=$CONJUR_FOLLOWER_URL/authn-jwt/k8s
```

> [!Note]
> 
> On `CONJUR_SSL_CERTIFICATE`:
> 
> - `dap-seedfetcher` container needs to verify the Conjur **master** certificate
> - 
> - `conjur-authn-k8s-client` and `secretless-broker` containers need to verify the Conjur **follower** certificate
> - 
> - Since both the master and follower certificates in this demo are signed by the same CA `central.pem`, using the CA certificate will suffice

### 4.3. Create ConfigMap `follower-cm` for follower

Ref: [3. Set up a ConfigMap](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-conjfollower.htm):

```console
kubectl -n conjur create configmap follower-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_MASTER_URL \
--from-literal CONJUR_SEED_FILE_URL=$CONJUR_SEED_FILE_URL \
--from-literal AUTHENTICATOR_ID=$AUTHENTICATOR_ID \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

### 4.4. Create ConfigMap `apps-cm` for applications

Ref:
- [Prepare the Kubernetes cluster and Golden ConfigMap](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-set-up-apps.htm#PreparetheKubernetesclusterandGoldenConfigMap)
- [CyberArk raw manifest repository](https://github.com/cyberark/conjur-authn-k8s-client/blob/master/helm/conjur-config-namespace-prep/generated/conjur-config-namespace-prep.yaml)

```console
kubectl -n cityapp create configmap apps-cm \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_FOLLOWER_URL \
--from-literal CONJUR_AUTHN_URL=$CONJUR_AUTHN_URL \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```

### 4.5. Optional - add static host entries in CoreDNS

- The `dap-seedfetcher` container uses `wget` to retrieve the seed file from Conjur Master.
- Depending on network configurations, some dual stacked kubernetes may not be able to resolve static host entries in DNS properly, causing `wget: unable to resolve host address` error.
- This is seen in my lab using Sophos Firewall with my Conjur Master FQDN configured as an IPv4 A record. The wget attempts to resolve for both A and AAAA; Sophos Firewall replies to AAAA with an NXDOMAIN response, causing wget to fail.
- This dual-stack behaviour is somewhat explained in: <https://umbrella.cisco.com/blog/dual-stack-search-domains-host-roulette>
- We can ensure resolution of our Conjur Master FQDN by loading it into the Kubernetes CoreDNS. Ref: <https://coredns.io/plugins/hosts/>

```console
kubectl -n kube-system edit cm coredns
```

Add the hosts portion into the Corefile section:

```console
  Corefile: |
    .:53 {
        errors
        health {
           lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
           pods insecure
           fallthrough in-addr.arpa ip6.arpa
           ttl 30
        }
        prometheus :9153
        forward . /etc/resolv.conf {
           max_concurrent 1000
        }
        cache 30
        loop
        reload
        loadbalance
        hosts {
           192.168.17.90 conjur.vx
           192.168.17.90 mysql.vx
           fallthrough
        }
    }
```

Restart the CoreDNS deployment:

```console
kubectl rollout restart deploy coredns -n kube-system
```

# ⚠ WORK IN PROGRESS ⚠

# ⚠ THE CONTENT BELOW ARE IN PROCESS OF BEING UPDATED ⚠

## 3. Deploy the follower

The `follower.yaml` manifest defines the necessary configurations to deploy the Conjur Follower into Kubernetes; review the file and read the ref link to understand how it works

Ref: [4. Set up the Follower service and deployment manifest](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-conjfollower.htm)

Deploy the manifest file into the Kubernetes cluster:

```console
kubectl apply -f https://github.com/joetanx/conjur-k8s/raw/main/follower.yaml
```

## 4. Preparing for cityapp deployment

The cityapp application is used to demostrate the various scenarios: hard-coded, secrets-provider, and secretless methods to consume the secrets

The deployment manifest files in this repo is configured use `docker.io/joetanx/cityapp:php`

### 4.1. Optional - build cityapp container image

To build the container image from [source](https://github.com/joetanx/cityapp-php)

```console
curl -sLO https://github.com/joetanx/cityapp-php/raw/main/Dockerfile
curl -sLO https://github.com/joetanx/cityapp-php/raw/main/index.php
podman build -t cityapp:php .
rm -rf Dockerfile index.php
```

## 5. Deploy cityapp-hardcode

> **Note** The provided manifest exposes the deployment through NGINX ingress controller at host `hardcode.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/conjur-k8s/raw/main/cityapp-hardcode.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n cityapp get pods -o wide
```

Browse to the service to verify that the application is working
- The cityapp connects to the MySQL world database to display random city information
- The database, username and password information is displayed for debugging, and the application is using the credentials hardcoded in the pod environment variables

![image](https://github.com/joetanx/conjur-k8s/assets/90442032/6e053aab-c571-4e16-9156-b2436ca1d25e)

Rotate the password on the MySQL server and update the new password in Conjur:

| Target | Command |
| --- | --- |
| MySQL Server | `mysql -u root -e "ALTER USER 'cityapp'@'%' IDENTIFIED BY 'qBIs3urqM0aG';"` |
| Conjur | `conjur variable set -i db_cityapp/password -v qBIs3urqM0aG` |

Refresh the cityapp-hardcode page: the page will throw an authentication error, since the hard-coded credentials are no longer valid:

```console
SQLSTATE[HY000] [1045] Access denied for user 'cityapp'@'10.244.0.6' (using password: YES)
```

## 6. Retrieving credentials using Secrets Provider for Kubernetes

Ref: [Secrets Provider - Push-to-File mode](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-jwt-sp-ic-p2f.htm)

![image](images/architectureCityappSecretsProvider.png)

> **Note** The provided manifest exposes the deployment through NGINX ingress controller at host `secretsprovider.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/conjur-k8s/raw/main/cityapp-secretsprovider.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n cityapp get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list the credentials retrieved from Conjur:

![image](https://github.com/joetanx/conjur-k8s/assets/90442032/7f9ac05b-a05e-4466-a998-d6dd4ba99967)

## 7. Deploy cityapp-secretless

### 7.1. Avoiding secrets from ever touching your application - Secretless Broker

The [Secretless Broker](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm) enables applications to connect securely to services without ever having to fetch secrets

In this demo, `secretless broker` will run as a sidecar container alongside with the `cityapp` container

The Secretless Broker will:
- Authenticate to Conjur
- Retreive the secrets
- Connect to the database
- Enable a database listener for the application to connect to

Application connection flow with Secretless Broker:

![image](images/architectureCityappSecretless.png)

### 7.2. Prepare the ConfigMap to be used by Secretless Broker

Secretless Broker needs some configuration to determine where to listen for new connection requests, where to route those connections, and where to get the credentials for each connection

- Ref: [Prepare the Secretless configuration](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-secretless-sidecar.htm#PreparetheSecretlessconfiguration)

We will map the `cityapp-secretless-cm.yaml` to the `cityapp` container using a ConfigMap

☝️ Secretless Broker also need to locate Conjur to authenticate and retrieve credentials, this was done in the previous step where we loaded the `apps-cm` ConfigMap

```console
curl -sLO https://github.com/joetanx/conjur-k8s/raw/main/secretless-cm.yaml
kubectl -n cityapp create configmap secretless-cm --from-file=secretless-cm.yaml
```

### 7.3. Deploy the Secretless-based cityapp

> **Note** The provided manifest exposes the deployment through NGINX ingress controller at host `secretless.cityapp.vx`
> 
> Edit the service and ingress according to the environment before applying

```console
kubectl apply -f https://github.com/joetanx/conjur-k8s/raw/main/cityapp-secretless.yaml
```

Verify that the application is deployed successfully:

```console
kubectl -n cityapp get pods -o wide
```

Browse to the service to verify that the application is working

- Notice that the database connection details list that the application is connecting to `127.0.0.1` using empty credentials

![image](https://github.com/joetanx/conjur-k8s/assets/90442032/7a435644-d7e4-41bd-8017-ea58b91959e4)
