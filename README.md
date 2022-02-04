# 1. Setup MySQL database
- Setup MySQL database according to this guide: https://github.com/joetanx/mysql-world_db
# 2. Setup Conjur master
- Setup Conjur master according to this guide: https://github.com/joetanx/conjur-master
# 3. Preparing necessary configurations for Kubernetes authenticator
## 3.1. Configure and enable Kubernetes authenticator
- The policy `authn-k8s.yaml` performs the following:
  - Define the Kubernetes authenticator endpoint in Conjur
    - Ref: (step 2) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8s-authn.htm
    - Creates `conjur/authn-k8s/demo` policy with necessary variables
    - Creates the `webservice` for the authenticator with `consumers` group allowed to authenticate to the webservice
  - Enable the seed generation service
    - Ref: (step 3) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8s-authn.htm
    - Creates `conjur/seed-generation` policy
    - Creates the `webservice` for the seed generation with `consumers` group allowed to authenticate to the webservice
  - Define identity in Conjur for Follower in Kubernetes
    - Ref: (step 2) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-follower.htm
    - Creates `conjur/followers` policy
    - Creates 'conjur/followers/k8s-follower` host with specifications for `conjur` namespace and `authn-k8s-sa` service account
    - Adds 'conjur/followers/k8s-follower` host to `conjur/authn-k8s/demo/consumers` to allow authentication to Kubernetes authenticator
    - Adds 'conjur/followers/k8s-follower` host to `conjur/seed-generation/consumers` to allow seed retrieval from seed generation webservice
  - Define applications as Conjur hosts in policy
    - Ref: (setp 2) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/cjr-k8s-authn-client.htm
    - Creates `k8s-apps` policy
    - Creates 'k8s-apps\cityapp-summon` and 'k8s-apps\cityapp-secretless` hosts with specifications for `cityapp` namespace and `cityapp-summon`/`cityapp-secretless` service accounts
    - Creates `k8s-apps` layer with 'k8s-apps\cityapp-summon` and 'k8s-apps\cityapp-secretless` hosts as members
    - Adds `k8s-apps` layer to `conjur/authn-k8s/demo/consumers` to allow authentication to Kubernetes authenticator
    - Adds `k8s-apps` layer to `world_db/consumers` to allow access to secrets in `world_db`
```console
curl -L -o authn-k8s.yaml https://github.com/joetanx/conjur-k8s/raw/main/authn-k8s.yaml
conjur policy load -f authn-k8s.yaml -b root
```
- Clean-up
```console
rm -f authn-k8s.yaml
```
## 3.2. Initialize the Kubernetes authenticator CA
- Ref: (step 4) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8s-authn.htm
- Generate the CA with openssl and set them to respective variables created by `authn-k8s.yaml` in previous step
```console
SERVICE_ID=demo
CONJUR_ACCOUNT=cyberark
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem -subj "/CN=conjur.authn-k8s.demo/OU=Conjur Kubernetes CA/O=cyberark"
openssl x509 -in ca.pem -text -noout
conjur variable set -i conjur/authn-k8s/demo/ca/key -v "$(cat ca.key)"
conjur variable set -i conjur/authn-k8s/demo/ca/cert -v "$(cat ca.pem)"
```
- Clean-up
```console
rm -f ca.pem ca.key
```
- Note: in Conjur version 11.7 and earlier, the following one-liner was used to initialize the CA
- Ref: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/11.7/en/Content/Integrations/ConjurDeployFollowers.htm
```console
podman exec conjur chpst -u conjur conjur-plugin-service possum rake authn_k8s:ca_init["conjur/authn-k8s/demo"]
```
## 3.3. Create Kubernetes resources for the Kubernetes Authenticator
- Ref: (step 5) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8s-authn.htm
- The policy `conjur-config-prep.yaml` performs the following:
  - Creates namespaces for `conjur` and `cityapp`
  - Creates `authn-k8s-sa` ServiceAccount
  - Creates `conjur-authenticator` ClusterRole with the necessary permissions required for Conjur to verify Kubernetes resources information
  - Binds the `authn-k8s-sa` ServiceAccount to `conjur-authenticator` ClusterRole with `conjur-authenticator-clusterrole-binding` ClusterRoleBinding
```console
curl -L -o conjur-config-prep.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-config-prep.yaml
kubectl apply -f conjur-config-prep.yaml
```
- Clean-up
```console
rm -f conjur-config-prep.yaml
```
## 3.4. Configure Conjur to access the Kubernetes API
- Ref: (step 6) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8s-authn.htm
- Conjur requires the following information to access the Kubernetes API
  - Service Account Token of the `authn-k8s-sa` ServiceAccount
  - CA certificate of the Kubernetes API
  - URL of the Kubernetes API
```console
TOKEN_SECRET_NAME="$(kubectl get secrets -n conjur | grep 'authn-k8s-sa.*service-account-token' | head -n1 | awk '{print $1}')"
SERVICE_ACCOUNT_TOKEN="$(kubectl get secret $TOKEN_SECRET_NAME -n conjur -o='go-template={{ .data.token }}' | base64 -d)"
CA_CERT="$(kubectl config view --raw --minify --flatten --output='jsonpath={.clusters[].cluster.certificate-authority-data}' | base64 -d)"
API_URL="$(kubectl config view --raw --minify --flatten --output='jsonpath={.clusters[].cluster.server}')"
```
- Verify the information retrieved
```console
echo $TOKEN_SECRET_NAME
echo $SERVICE_ACCOUNT_TOKEN
echo $CA_CERT
echo $API_URL
```
- Set them to respective variables created by `authn-k8s.yaml` in previous step
```console
conjur variable set -i conjur/authn-k8s/demo/kubernetes/ca-cert -v "$CA_CERT"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/service-account-token -v "$SERVICE_ACCOUNT_TOKEN"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/api-url -v "$API_URL"
```
## 3.5. Allowlist the Kubernetes authenticator in Conjur
- Ref: (step 7) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8s-authn.htm
- Ref: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/authentication-types.htm#!#Allowlis
```console
podman exec conjur sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-k8s/demo"' /opt/conjur/etc/conjur.conf
podman exec conjur sv restart conjur
```
- Verify that the Kubernetes authenticator is configured and allowlisted
```console
curl -k https://conjur.vx/info
```
## 3.6. Load hosts in CoreDNS
- The `dap-seedfetcher` container uses `wget` to retrieve the seed file from Conjur Master.
- Depending on network configurations, some dual stacked kubernetes may not be able to resolve static host entries in DNS properly, causing `wget: unable to resolve host address` error.
- This is seen in my lab using Sophos Firewall with my Conjur Master FQDN configured as an IPv4 A record. The wget attempts to resolve for both A and AAAA; Sophos Firewall replies to AAAA with an NXDOMAIN response, causing wget to fail.
- This dual-stack behaviour is somewhat explained in: https://umbrella.cisco.com/blog/dual-stack-search-domains-host-roulette
- We can ensure resolution of our Conjur Master FQDN by loading it into the Kubernetes CoreDNS. Ref: https://coredns.io/plugins/hosts/
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
# 4. Set up Follower in Kubernetes
- Ref: (step 4-6) https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-follower.htm
- Setup and apply ConfigMap for Follower
```console
curl -L -o conjur-connect-followers.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-connect-followers.yaml
openssl s_client -showcerts -connect conjur.vx:443 </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > master-certificate.pem
sed -i 's/^/    /' master-certificate.pem
sed -i '/<insert-master-certificate>/ r master-certificate.pem' conjur-connect-followers.yaml
sed -i '/<insert-master-certificate>/d' conjur-connect-followers.yaml
kubectl apply -f conjur-connect-followers.yaml
```
- Deploy the Follower in Kubernetes
```console
curl -L -o conjur-follower.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-follower.yaml
kubectl apply -f conjur-follower.yaml -n conjur
```
- Clean-up
```console
rm -f master-certificate.pem conjur-connect-followers.yaml conjur-follower.yaml
```
# 5. Preparing for cityapp deployment
## 5.1. Setup and apply ConfigMap for cityapp
- Ref: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-set-up-apps.htm
```console
curl -L -o conjur-connect-apps.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-connect-apps.yaml
FOLLOWER_POD_NAME="$(kubectl get pods -n conjur | grep follower | head -n1 | awk '{print $1}')"
kubectl exec -it $FOLLOWER_POD_NAME -n conjur -c conjur-appliance -- cat /opt/conjur/etc/ssl/conjur.pem > follower-certificate.pem
sed -i 's/^/    /' follower-certificate.pem
sed -i '/<insert-follower-certificate>/ r follower-certificate.pem' conjur-connect-apps.yaml
sed -i '/<insert-follower-certificate>/d' conjur-connect-apps.yaml
kubectl apply -f conjur-connect-apps.yaml
```
- Clean-up
```console
rm -f follower-certificate.pem conjur-connect-apps.yaml
```
## 5.2. Build cityapp container image
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
## 5.3. Deploy cityapp-hardcode
- Notice that the MySQL credentials are hard-coded in `cityapp-hardcode.yaml`
```console
curl -L -o cityapp-hardcode.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-hardcode.yaml
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
curl -L -o cityapp-summon-config.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-summon-config.yaml
kubectl create configmap cityapp-summon-config --from-file=cityapp-summon-config.yaml -n cityapp
```
- Deploy the Summon-based cityapp
```console
curl -L -o cityapp-summon.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-summon.yaml
kubectl apply -f cityapp-summon.yaml -n cityapp
```
- Clean-up
```console
rm -f *.yaml
```
# 7. Deploy cityapp-secretless
-  Load the secretless configuration yaml file as Kubernetes ConfigMap
```console
curl -L -o cityapp-secretless-config.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-secretless-config.yaml
kubectl create configmap cityapp-secretless-config --from-file=cityapp-secretless-config.yaml -n cityapp
```
- Deploy the Secretless-based cityapp
```console
curl -L -o cityapp-secretless.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-secretless.yaml
kubectl apply -f cityapp-secretless.yaml -n cityapp
```
- Clean-up
```console
rm -f *.yaml
```
