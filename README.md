> Conjur + RHEL8 + Kubernetes
> 
> Work in Progress
# 1. Setup MySQL database
- Install MySQL server
- Enable MySQL server to start with system
- Allow MySQL communiction on firewalld
```console
yum -y install mysql-server
systemctl enable --now mysqld
firewall-cmd --permanent --add-service mysql && firewall-cmd --reload
```
- Download sample world database
```console
curl -L -o world-db.tar.gz https://downloads.mysql.com/docs/world-db.tar.gz
tar xvf world-db.tar.gz
```
- Load sample world database
- Create MySQL account to be used for the sample application
```console
mysql -u root
CREATE USER 'cityapp'@'%' IDENTIFIED BY 'Cyberark1';
GRANT ALL PRIVILEGES ON *.* TO 'cityapp'@'%';
SOURCE /root/world-db/world.sql
SHOW DATABASES;
SELECT user,host FROM mysql.user;
QUIT;
```
- Clean-up
```console
ls -l /var/lib/mysql/world
rm -f world-db.tar.gz
rm -rf world-db
```
# 2. Create cityapp image
- Install podman - required to build the cityapp container image
```console
yum -y install podman
```
- Build cityapp container image
```console
mkdir cityapp && cd $_
curl -L -o cityapp.tgz https://github.com/joetan1/conjur-k8s/raw/main/cityapp.tgz
tar xvf cityapp.tgz
./build.sh
```
- Clean-up
```console
cd .. && rm -rf cityapp
```
# 3. Deploy cityapp-hardcode
- Download the Kubernetes manifest file
- The MySQL credentials are hard-coded into the Kubernetes manifest file
- The cityapp pod is configured to be deployed into `default` namespace
- Edit `cityapp-hardcode.yaml` according to your environment
```console
curl -L -o cityapp-hardcode.yaml https://github.com/joetan1/conjur-k8s/raw/main/cityapp-hardcode.yaml
kubectl apply -f cityapp-hardcode.yaml
```
- Clean-up
```console
rm -f cityapp-hardcode.yaml
```
- Verify that the application is deployed successfully
```console
kubectl get pods -o wide
```
# 4. Setup Conjur Master
Conjur Master deployment options:
1. On RHEL directly - Conjur on RHEL is under Controlled Availability, contact CyberArk for this deployment option
2. As a container
## 4.1. RHEL Based Master
- The Conjur-RHEL installer comes with an older version of keyutils in its repository which will fail to install if your RHEL is updated or if you're installing on RHEL 8.5. Manually installing keyutils resolves this.
```console
yum -y install http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/keyutils-1.5.10-9.el8.x86_64.rpm
```
- Upload the Conjur CLI and add execute permissions
- Ref: https://github.com/cyberark/conjur-api-python3/releases
```console
chmod +x /usr/local/bin/conjur
```
- Obtain the Conjur installation package from CyberArk
- Unpack and install Conjur node
```console
cd conjur
tar xvf Conjur-Enterprise-RHELinux-Intel-Rls-v12.4.0+Conjur.RHEL.CA.tar.gz
sed -i '$ s/accept_eula\:/accept_eula\: true/' conjur_enterprise_node_config.yml
./conjur_enterprise_setup.sh --install-node
```
- Setup environment variables and allow Conjur communications through firewalld
```console
source /etc/profile.d/conjur_enterprise.sh
firewall-cmd --add-service http --permanent
firewall-cmd --add-service https --permanent
firewall-cmd --add-service ldaps --permanent
firewall-cmd --add-port 1999/tcp --permanent
firewall-cmd --add-service postgresql --permanent
firewall-cmd --reload
```
- Clean-up
```console
cd .. && rm -rf conjur
```
- Setup the Conjur node as master
- Edit the admin account password in `-p` option and the Conjur account (`cyberark`) according to your environment
```console
evoke configure master --accept-eula -h conjur.vx --master-altnames conjur.vx -p CyberArk123! cyberark
```
- Setup Conjur certificates
- The `conjur-certs.tgz` include CA, Master and follower certificates for my lab use, you should generate your own certificates
> Note: In event of "error: cert already in hash table", ensure that conjur/follower certificates do not contain the CA certificate
```console
curl -L -o conjur-certs.tgz https://github.com/joetan1/conjur-k8s/raw/main/conjur-certs.tgz
tar xvf conjur-certs.tgz
evoke ca import --root central.pem
evoke ca import --key follower.default.svc.cluster.local.key follower.default.svc.cluster.local.pem
evoke ca import --key conjur.vx.key --set conjur.vx.pem
```
- Clean-up
```console
rm -f *.key
rm -f *.pem
```
- Initialize Conjur CLI and login to conjur
```console
conjur init -u https://conjur.vx
conjur login -i admin -p CyberArk123!
```
## 4.2. Container Based Master
- Obtain the Conjur container image from CyberArk
- Upload the Conjur container image to the container host
```console
podman load -i conjur-appliance_12.4.0.tar.gz
```
- Clean-up
```console
rm -f conjur-appliance_12.4.0.tar.gz
```
- Upload the Conjur CLI and add execute permissions
- Ref: https://github.com/cyberark/conjur-api-python3/releases
```console
chmod +x /usr/local/bin/conjur
```
- Run the Conjur container
```console
podman run --name conjur -d --security-opt seccomp=unconfined -p "443:443" -p "636:636" -p "5432:5432" -p "1999:1999" conjur-appliance:12.4.0
```
- Setup the Conjur container as master
- Edit the admin account password in `-p` option and the Conjur account (`cyberark`) according to your environment
```console
podman exec conjur evoke configure master --accept-eula -h conjur.vx --master-altnames "conjur.vx" -p CyberArk123! cyberark
```
- Run the Conjur container as systemd service and configure it to setup with container host
- Ref: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/managing_containers/running_containers_as_systemd_services_with_podman
```console
podman generate systemd -fn conjur
mv container-conjur.service /usr/lib/systemd/system
systemctl enable container-conjur
```
- Setup Conjur certificates
- The `conjur-certs.tgz` include CA, Master and follower certificates for my lab use, you should generate your own certificates
> Note: In event of "error: cert already in hash table", ensure that conjur/follower certificates do not contain the CA certificate
```console
curl -L -o conjur-certs.tgz https://github.com/joetan1/conjur-k8s/raw/main/conjur-certs.tgz
podman cp conjur-certs.tgz conjur:/tmp/
podman exec conjur tar xvf /tmp/conjur-certs.tgz -C /tmp/
podman exec conjur evoke ca import --root /tmp/central.pem
podman exec conjur evoke ca import --key /tmp/follower.default.svc.cluster.local.key /tmp/follower.default.svc.cluster.local.pem
podman exec conjur evoke ca import --key /tmp/conjur.vx.key --set /tmp/conjur.vx.pem
```
- Clean-up
```console
podman exec conjur /bin/sh -c "rm -f /tmp/conjur-certs.tgz /tmp/*.pem /tmp/*key"
rm -f conjur-certs.tgz
```
- Initialize Conjur CLI and login to conjur
```console
conjur init -u https://conjur.vx
conjur login -i admin -p CyberArk123!
```
# 5. Deploy Conjur Follower
## 5.1. RHEL Based Master
```console
podman load -i conjur-appliance_12.4.0.tar.gz
rm -f conjur-appliance_12.4.0.tar.gz
kubectl create serviceaccount conjur-cluster
curl -L -o conjur-authn-k8s.yaml https://github.com/joetan1/conjur-k8s/raw/main/conjur-authn-k8s.yaml
conjur policy load -f conjur-authn-k8s.yaml -b root
su conjur -c 'conjur-plugin-service possum rake authn_k8s:ca_init["conjur/authn-k8s/demo"]'
sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-k8s/demo"' /opt/conjur/etc/conjur.conf
systemctl restart conjur
curl -k https://conjur.vx/info
curl -L -o conjur-k8s-rbac.yaml https://github.com/joetan1/conjur-k8s/raw/main/conjur-k8s-rbac.yaml
kubectl apply -f conjur-k8s-rbac.yaml
yum -y install jq
TOKEN_SECRET_NAME="$(kubectl get secrets | grep 'conjur.*service-account-token' | head -n1 | awk '{print $1}')"
CA_CERT="$(kubectl get secret $TOKEN_SECRET_NAME -o json | jq -r '.data["ca.crt"]' | base64 --decode)"
SERVICE_ACCOUNT_TOKEN="$(kubectl get secret $TOKEN_SECRET_NAME -o json | jq -r .data.token | base64 --decode)"
API_URL="$(kubectl config view --minify -o json | jq -r '.clusters[0].cluster.server')"
echo $TOKEN_SECRET_NAME
echo $CA_CERT
echo $SERVICE_ACCOUNT_TOKEN
echo $API_URL
conjur variable set -i conjur/authn-k8s/demo/kubernetes/ca-cert -v "$CA_CERT"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/service-account-token -v "$SERVICE_ACCOUNT_TOKEN"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/api-url -v "$API_URL"
openssl s_client -showcerts -connect conjur.vx:443 </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > master-certificate.pem
kubectl create configmap master-certificate --from-file=ssl-certificate=<(cat master-certificate.pem)
curl -L -o conjur-follower.yaml https://github.com/joetan1/conjur-k8s/raw/main/conjur-follower.yaml
```
> For Conjur Master on RHEL, the Conjur CLI .netrc file will cause the follower deployment to fail. Logout and delete the .netrc before deploying the follower.
```console
conjur logout
rm -f .netrc
```
> Deploy the follower after clean-up
```console
kubectl apply -f conjur-follower.yaml
```
## 5.2. Container Based Master
```console
kubectl create serviceaccount conjur-cluster
curl -L -o conjur-authn-k8s.yaml https://github.com/joetan1/conjur-k8s/raw/main/conjur-authn-k8s.yaml
conjur policy load -f conjur-authn-k8s.yaml -b root
podman exec conjur chpst -u conjur conjur-plugin-service possum rake authn_k8s:ca_init["conjur/authn-k8s/demo"]
podman exec conjur sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-k8s/demo"' /opt/conjur/etc/conjur.conf
podman exec conjur sv restart conjur
curl -k https://conjur.vx/info
curl -L -o conjur-k8s-rbac.yaml https://github.com/joetan1/conjur-k8s/raw/main/conjur-k8s-rbac.yaml
kubectl apply -f conjur-k8s-rbac.yaml
yum -y install jq
TOKEN_SECRET_NAME="$(kubectl get secrets | grep 'conjur.*service-account-token' | head -n1 | awk '{print $1}')"
CA_CERT="$(kubectl get secret $TOKEN_SECRET_NAME -o json | jq -r '.data["ca.crt"]' | base64 --decode)"
SERVICE_ACCOUNT_TOKEN="$(kubectl get secret $TOKEN_SECRET_NAME -o json | jq -r .data.token | base64 --decode)"
API_URL="$(kubectl config view --minify -o json | jq -r '.clusters[0].cluster.server')"
echo $TOKEN_SECRET_NAME
echo $CA_CERT
echo $SERVICE_ACCOUNT_TOKEN
echo $API_URL
conjur variable set -i conjur/authn-k8s/demo/kubernetes/ca-cert -v "$CA_CERT"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/service-account-token -v "$SERVICE_ACCOUNT_TOKEN"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/api-url -v "$API_URL"
openssl s_client -showcerts -connect conjur.vx:443 </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > master-certificate.pem
kubectl create configmap master-certificate --from-file=ssl-certificate=<(cat master-certificate.pem)
curl -L -o conjur-follower.yaml https://github.com/joetan1/conjur-k8s/raw/main/conjur-follower.yaml
kubectl apply -f conjur-follower.yaml
```
## 5.3. Load hosts in CoreDNS
> The `dap-seedfetcher` container uses wget to retrieve the seed file from Conjur Master.

> Depending on network configurations, some dual stacked kubernetes may not be able to resolve static host entries in DNS properly, causing `wget: unable to resolve host address` error.

> This is seen in my lab using Sophos Firewall with my Conjur Master FQDN configured as an IPv4 A record. The wget attempts to resolve for both A and AAAA; Sophos Firewall replies to AAAA with an NXDOMAIN response, causing wget to fail.

> This dual-stack behaviour is some what explained in: https://umbrella.cisco.com/blog/dual-stack-search-domains-host-roulette

> We can ensure resolution of our Conjur Master FQDN by loading it into the Kubernetes CoreDNS. https://coredns.io/plugins/hosts/
```console
kubectl edit cm coredns -n kube-system
```
> Add the hosts portion into the Corefile section
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
> Restart the CoreDNS deployment
```console
kubectl rollout restart deploy coredns -n kube-system
```
# 6. Setup authenticators, AppIdentities, variables, and permissions in Conjur
```console
curl -L -o conjur-app-var.yaml https://github.com/joetan1/conjur-k8s/raw/main/conjur-app-var.yaml
conjur policy load -f conjur-app-var.yaml -b root
conjur variable set -i world_db/username -v cityapp
conjur variable set -i world_db/password -v Cyberark1
```
# 7. Create ConfigMap for follower certificate
```console
FOLLOWER_POD_NAME="$(kubectl get pods | grep follower | head -n1 | awk '{print $1}')"
kubectl exec -it $FOLLOWER_POD_NAME -c conjur -- cat /opt/conjur/etc/ssl/conjur.pem > follower-certificate.pem
kubectl create configmap follower-certificate --from-file=ssl-certificate=<(cat follower-certificate.pem)
```
# 8. Deploy cityapp-summon
```console
curl -L -o cityapp-summon-config.yaml https://github.com/joetan1/conjur-k8s/raw/main/cityapp-summon-config.yaml
kubectl create configmap cityapp-summon-config --from-file=cityapp-summon-config.yaml
curl -L -o cityapp-summon.yaml https://github.com/joetan1/conjur-k8s/raw/main/cityapp-summon.yaml
kubectl apply -f cityapp-summon.yaml
```
# 9. Deploy cityapp-secretless
```console
curl -L -o cityapp-secretless-config.yaml https://github.com/joetan1/conjur-k8s/raw/main/cityapp-secretless-config.yaml
kubectl create configmap cityapp-secretless-config --from-file=cityapp-secretless-config.yaml
curl -L -o cityapp-secretless.yaml https://github.com/joetan1/conjur-k8s/raw/main/cityapp-secretless.yaml
kubectl apply -f cityapp-secretless.yaml
```
