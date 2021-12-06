> Conjur + RHEL8 + Kubernetes
> 
> Work in Progress
0. Install base tools
```console
yum -y install wget tar podman
```
1. Setup MySQL database
```console
yum -y install mysql-server
systemctl enable --now mysqld
firewall-cmd --permanent --add-service mysql && firewall-cmd --reload
curl https://downloads.mysql.com/docs/world-db.tar.gz -o world-db.tar.gz
tar xvf world-db.tar.gz
mysql -u root
CREATE USER 'cityapp'@'%' IDENTIFIED BY 'Cyberark1';
GRANT ALL PRIVILEGES ON *.* TO 'cityapp'@'%';
SOURCE /root/world-db/world.sql
SHOW DATABASES;
SELECT user,host FROM mysql.user;
ls -l /var/lib/mysql/world
rm -f world-db.tar.gz
rm -rf world-db
```
2. Create cityapp image
```console
mkdir cityapp && cd $_
wget https://github.com/joetan1/conjur-k8s/raw/main/cityapp.tgz
tar xvf cityapp.tgz
./build.sh
cd .. && rm -rf cityapp
```
3. Deploy cityapp-hardcode
```console
wget https://github.com/joetan1/conjur-k8s/raw/main/cityapp-harcode.yaml
kubectl apply -f cityapp-hardcode.yaml
rm -f cityapp-hardcode.yaml
kubectl get all
```
4. Setup Conjur Master
- 4.1. RHEL Based
> Installing on RHEL 8.5
```console
yum -y install http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/keyutils-1.5.10-9.el8.x86_64.rpm
```
```console
chmod +x /usr/local/bin/conjur
cd conjur
tar xvf Conjur-Enterprise-RHELinux-Intel-Rls-v12.4.0+Conjur.RHEL.CA.tar.gz
sed -i '$ s/accept_eula\:/accept_eula\: true/' conjur_enterprise_node_config.yml
./conjur_enterprise_setup.sh --install-node
cd .. && rm -rf conjur
source /etc/profile.d/conjur_enterprise.sh
evoke configure master --accept-eula -h conjur.vx --master-altnames conjur.vx -p CyberArk123! cyberark
firewall-cmd --add-service http --permanent
firewall-cmd --add-service https --permanent
firewall-cmd --reload
evoke ca import --root central.pem
evoke ca import --key follower.default.svc.cluster.local.key follower.default.svc.cluster.local.pem
evoke ca import --key conjur.vx.key --set conjur.vx.pem
rm -f *.key
rm -f *.pem
conjur init -u https://conjur.vx
```
- 4.2. Container Based
```console
podman load -i conjur-appliance_12.3.0.tar.gz
podman load -i dap-seedfetcher_0.3.0.tar.gz
chmod +x /usr/local/bin/conjur
rm -f conjur-appliance_12.3.0.tar.gz
rm -f dap-seedfetcher_0.3.0.tar.gz
podman run --name conjur -d --security-opt seccomp=unconfined -p "443:443" -p "636:636" -p "5432:5432" -p "1999:1999" conjur-appliance:12.3.0
podman exec conjur evoke configure master --accept-eula -h conjur.vx --master-altnames "conjur.vx" -p CyberArk123! cyberark
podman generate systemd -fn conjur
mv container-conjur.service /usr/lib/systemd/system
systemctl enable container-conjur
wget https://github.com/joetan1/conjur-k8s/raw/main/conjur-certs.tgz
podman cp conjur-certs.tgz conjur:/tmp/
podman exec conjur tar xvf /tmp/conjur-certs.tgz -C /tmp/
podman exec conjur evoke ca import --root /tmp/central.pem
podman exec conjur evoke ca import --key /tmp/follower.default.svc.cluster.local.key /tmp/follower.default.svc.cluster.local.pem
podman exec conjur evoke ca import --key /tmp/conjur.vx.key --set /tmp/conjur.vx.pem
# Note: In event of "error: cert already in hash table", ensure that conjur/follower certificates do not contain the CA certificate
podman exec conjur /bin/sh -c "rm -f /tmp/conjur-certs.tgz /tmp/*.pem /tmp/*key"
rm -f conjur-certs.tgz
conjur init -u https://conjur.vx
```
5. Deploy Conjur follower
```console
kubectl create serviceaccount conjur-cluster
wget https://github.com/joetan1/conjur-k8s/raw/main/conjur-authn-k8s.yaml
conjur policy load -f conjur-authn-k8s.yaml -b root
podman exec conjur chpst -u conjur conjur-plugin-service possum rake authn_k8s:ca_init["conjur/authn-k8s/demo"]
podman exec conjur sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-k8s/demo"' /opt/conjur/etc/conjur.conf
podman exec conjur sv restart conjur
curl -k https://conjur.vx/info
wget https://github.com/joetan1/conjur-k8s/raw/main/conjur-k8s-rbac.yaml
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
wget https://github.com/joetan1/conjur-k8s/raw/main/conjur-follower.yaml
kubectl apply -f conjur-follower.yaml
```
6. Setup authenticators, AppIdentities, variables, and permissions in Conjur
```console
wget https://github.com/joetan1/conjur-k8s/raw/main/conjur-app-var.yaml
conjur policy load -f conjur-app-var.yaml -b root
conjur variable set -i world_db/username -v cityapp
conjur variable set -i world_db/password -v Cyberark1
```
7. Create ConfigMap for follower certificate
```console
FOLLOWER_POD_NAME="$(kubectl get pods | grep follower | head -n1 | awk '{print $1}')"
kubectl exec -it $FOLLOWER_POD_NAME -c conjur -- cat /opt/conjur/etc/ssl/conjur.pem > follower-certificate.pem
kubectl create configmap follower-certificate --from-file=ssl-certificate=<(cat follower-certificate.pem)
```
8. Deploy cityapp-summon
```console
wget https://github.com/joetan1/conjur-k8s/raw/main/cityapp-summon-config.yaml
kubectl create configmap cityapp-summon-config --from-file=cityapp-summon-config.yaml
wget https://github.com/joetan1/conjur-k8s/raw/main/cityapp-summon.yaml
kubectl apply -f cityapp-summon.yaml
```
9. Deploy cityapp-secretless
```console
wget https://github.com/joetan1/conjur-k8s/raw/main/cityapp-secretless-config.yaml
kubectl create configmap cityapp-secretless-config --from-file=cityapp-secretless-config.yaml
wget https://github.com/joetan1/conjur-k8s/raw/main/cityapp-secretless.yaml
kubectl apply -f cityapp-secretless.yaml
```
