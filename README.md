# Integrate Kubernetes with Conjur Enterprise using the JWT authenticator
### Software Versions
- RHEL 8.5
- Conjur Enterprise 12.5
- Kubernetes 1.23

### Servers

| Hostname  | Role |
| --- | --- |
| conjur.vx  | Conjur master  |
| mysql.vx  | MySQL server  |
| * (any)  | Single-node Kubernetes cluster  |

# 0. Kubernetes cluster
- This demo should work with any flavour of Kubernetes clusters (On-prem, AKS, EKS), but was tested with a single-node on-prem Kubernetes cluster in my lab
- For a guide to setup a single-node on-prem Kubernetes cluster: <https://joetanx.github.io/cri-o-kube>

# 1. Setup MySQL database
- Setup MySQL database according to this guide: <https://joetanx.github.io/mysql-world_db>

# 2. Setup Conjur master
- Setup Conjur master according to this guide: <https://joetanx.github.io/conjur-master>

# 3. Preparing necessary configurations for the JWT authenticator
## 3.1. Configure and enable JWT authenticator
- The policy `authn-jwt-k8s.yaml` performs the following:
  - Define the JWT authenticator endpoint in Conjur
    - Ref: (step 2) <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator>
    - Creates `conjur/authn-jwt/k8s` policy with the necessary variables
    - Creates the `webservice` for the authenticator with `consumers` group allowed to authenticate to the webservice
  - Enable the seed generation service
    - Ref: (step 6) <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator>
    - Creates `conjur/seed-generation` policy
    - Creates the `webservice` for the seed generation with `consumers` group allowed to authenticate to the webservice
  - Define `jwt-apps/k8s` policy with:
    - Conjur Follower in Kubernetes identified by `system:serviceaccount:conjur:authn-jwt-sa`
      - Ref: (step 2) <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-follower.htm>
      - The Conjur Follower is granted access to the JWT authenticator `conjur/authn-jwt/k8s` and seed generation `conjur/seed-generation` webservices by adding it into `consumers` group of respective webservices
    - Demo application `cityapp-summon` and `cityapp-secretless` identified by `system:serviceaccount:cityapp:cityapp-summon` and `system:serviceaccount:cityapp:cityapp-secretless`
      - Ref: (step 2) <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-authn-client-authjwt.htm#Setuptheapplicationtoretrievesecrets>
      - The demo applications are granted access to the JWT authenticator `conjur/authn-jwt/k8s` and demo database secrets `world_db` by adding them to `consumers` group of respective webservice and policy
- **Note**: `authn-jwt-k8s.yaml` builds on top of `app-vars.yaml` in https://joetanx.github.io/conjur-master. Loading `authn-jwt-k8s.yaml` without having `app-vars.yaml` loaded previously will not work.
```console
curl -L -o authn-jwt-k8s.yaml https://github.com/joetanx/conjur-k8s-jwt/raw/main/authn-jwt-k8s.yaml
conjur policy load -f authn-jwt-k8s.yaml -b root
```
- Clean-up
```console
rm -f authn-jwt-k8s.yaml
```

## 3.2 Populate the variables required by the JWT Authenticator
- Ref: (step 3) <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator>
```console
PUBLIC_KEYS="$(kubectl get --raw $(kubectl get --raw /.well-known/openid-configuration | jq -r '.jwks_uri'))"
ISSUER="$(kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer')"
conjur variable set -i conjur/authn-jwt/k8s/public-keys -v "{\"type\":\"jwks\", \"value\":$PUBLIC_KEYS}"
conjur variable set -i conjur/authn-jwt/k8s/issuer -v $ISSUER
conjur variable set -i conjur/authn-jwt/k8s/token-app-property -v sub
conjur variable set -i conjur/authn-jwt/k8s/identity-path -v jwt-apps/k8s
conjur variable set -i conjur/authn-jwt/k8s/audience -v vxlab
```

## 3.3 Allowlist the JWT authenticator in Conjur
- Ref: (step 4) <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-authn.htm#ConfiguretheJWTAuthenticator>
- Ref: <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/authentication-types.htm#Allowlis>
```console
podman exec conjur sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-jwt/k8s"' /opt/conjur/etc/conjur.conf
podman exec conjur sv restart conjur
```
- Verify that the Kubernetes authenticator is configured and allowlisted
```console
curl -k https://conjur.vx/info
```

## 3.4 Prepare the ConfigMaps
- The follower and application pods in Kubernetes needs to be able to locate the Conjur master and follower - this is done by the means of ConfigMaps
- Prepare the namespace `conjur` and `cityapp`, and service account `authn-jwt-sa`
```console
curl -L -o conjur-k8s-prep.yaml https://github.com/joetanx/conjur-k8s-jwt/raw/main/conjur-k8s-prep.yaml
kubectl apply -f conjur-k8s-prep.yaml
```
- Clean-up
```console
rm -f conjur-k8s-prep.yaml
```
- Prepare the variables required for ConfigMaps
- **Note** on `CONJUR_SSL_CERTIFICATE`:
  - `dap-seedfetcher` container needs to verify the Conjur **master** certificate
  - `conjur-authn-k8s-client` and `secretless-broker` containers needs to verify the Conjur **follower** certificate
  - Since both the master and follower certificates in this demo are signed by the same CA `central.pem`, using the CA certificate will suffice

```console
CA_CERT="$(curl -L https://github.com/joetanx/conjur-k8s-jwt/raw/main/central.pem)"
CONJUR_MASTER_URL=https://conjur.vx
CONJUR_FOLLOWER_URL=https://follower.conjur.svc.cluster.local
AUTHENTICATOR_ID=k8s
CONJUR_ACCOUNT=cyberark
CONJUR_SEED_FILE_URL=$CONJUR_MASTER_URL/configuration/$CONJUR_ACCOUNT/seed/follower
CONJUR_AUTHN_URL=$CONJUR_FOLLOWER_URL/authn-jwt/k8s
```
- Create ConfigMap `conjur-connect-follower` for follower
```console
kubectl -n conjur create configmap conjur-connect-followers \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_MASTER_URL \
--from-literal CONJUR_SEED_FILE_URL=$CONJUR_SEED_FILE_URL \
--from-literal AUTHENTICATOR_ID=$AUTHENTICATOR_ID \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```
- Create ConfigMap `conjur-connect-apps` for applications
```console
kubectl -n cityapp create configmap conjur-connect-apps \
--from-literal CONJUR_ACCOUNT=$CONJUR_ACCOUNT \
--from-literal CONJUR_APPLIANCE_URL=$CONJUR_FOLLOWER_URL \
--from-literal CONJUR_AUTHN_URL=$CONJUR_AUTHN_URL \
--from-literal "CONJUR_SSL_CERTIFICATE=${CA_CERT}"
```
## 3.5. Load hosts in CoreDNS
- The `dap-seedfetcher` container uses `wget` to retrieve the seed file from Conjur Master.
- Depending on network configurations, some dual stacked kubernetes may not be able to resolve static host entries in DNS properly, causing `wget: unable to resolve host address` error.
- This is seen in my lab using Sophos Firewall with my Conjur Master FQDN configured as an IPv4 A record. The wget attempts to resolve for both A and AAAA; Sophos Firewall replies to AAAA with an NXDOMAIN response, causing wget to fail.
- This dual-stack behaviour is somewhat explained in: <https://umbrella.cisco.com/blog/dual-stack-search-domains-host-roulette>
- We can ensure resolution of our Conjur Master FQDN by loading it into the Kubernetes CoreDNS. Ref: <https://coredns.io/plugins/hosts/>
```console
kubectl edit cm coredns -n kube-system
```
- Add the hosts portion into the Corefile section
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
- Restart the CoreDNS deployment
```console
kubectl rollout restart deploy coredns -n kube-system
```

# 4. Deploy the follower
- Ref: (step 4-5) <https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-jwt-follower.htm>
- The `follower.yaml` manifest defines the necessary configurations to deploy the Conjur Follower into Kubernetes; review the file and read the ref link to understand how it works
- Download the manifest file and deploy into the Kubernetes cluster
```console
curl -L -o follower.yaml https://github.com/joetanx/conjur-k8s-jwt/raw/main/follower.yaml
kubectl -n conjur apply -f follower.yaml
```

# 5. Preparing for cityapp deployment
- The cityapp application is used to demostrate the various scenarios: hard-coded, summon, and secretless ways to consume the secrets
- Build cityapp container image
```console
mkdir cityapp && cd $_
curl -L -o cityapp.tgz https://github.com/joetanx/conjur-k8s/raw/main/cityapp.tgz
tar xvf cityapp.tgz
./build.sh
```
- Clean-up
```console
cd .. && rm -rf cityapp
```

## 5.2. Deploy cityapp-hardcode
- Notice that the MySQL credentials are hard-coded in `cityapp-hardcode.yaml`
```console
curl -L -o cityapp-hardcode.yaml https://github.com/joetanx/conjur-jwt-k8s/raw/main/cityapp-hardcode.yaml
kubectl apply -f cityapp-hardcode.yaml -n cityapp
```
- Clean-up
```console
rm -f cityapp-hardcode.yaml
```
- Verify that the application is deployed successfully
```console
kubectl get pods -o wide -n cityapp
```

# 6. Deploy cityapp-summon
-  Load the summon configuration yaml file as Kubernetes ConfigMap
```console
curl -L -o cityapp-summon-cm.yaml https://github.com/joetanx/conjur-k8s-jwt/raw/main/cityapp-summon-cm.yaml
kubectl -n cityapp create configmap cityapp-summon-cm --from-file=cityapp-summon-cm.yaml
```
- Deploy the Summon-based cityapp
```console
curl -L -o cityapp-summon.yaml https://github.com/joetanx/conjur-k8s-jwt/raw/main/cityapp-summon.yaml
kubectl -n cityapp apply -f cityapp-summon.yaml
```
- Clean-up
```console
rm -f *.yaml
```

# 7. Deploy cityapp-secretless
-  Load the secretless configuration yaml file as Kubernetes ConfigMap
```console
curl -L -o cityapp-secretless-cm.yaml https://github.com/joetanx/conjur-k8s-jwt/raw/main/cityapp-secretless-cm.yaml
kubectl -n cityapp create configmap cityapp-secretless-cm --from-file=cityapp-secretless-cm.yaml
```
- Deploy the Secretless-based cityapp
```console
curl -L -o cityapp-secretless.yaml https://github.com/joetanx/conjur-k8s-jwt/raw/main/cityapp-secretless.yaml
kubectl -n cityapp apply -f cityapp-secretless.yaml
```
- Clean-up
```console
rm -f *.yaml
```
