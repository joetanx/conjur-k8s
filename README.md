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
- Verify
```console
ls -l /var/lib/mysql/world
```
- Clean-up
```console
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
curl -L -o cityapp.tgz https://github.com/joetanx/conjur-k8s/raw/main/cityapp.tgz
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
curl -L -o cityapp-hardcode.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-hardcode.yaml
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
- Download the Conjur CLI and add execute permissions
- Ref: https://github.com/cyberark/conjur-api-python3/releases
```console
curl -L -o conjur-cli-rhel-8.tar.gz https://github.com/cyberark/conjur-api-python3/releases/download/v7.1.0/conjur-cli-rhel-8.tar.gz
tar xvf conjur-cli-rhel-8.tar.gz
mv conjur /usr/local/bin/
chmod +x /usr/local/bin/conjur
```
- Clean-up
```console
rm -f conjur-cli-rhel-8.tar.gz
```
- Obtain the Conjur installation package from CyberArk
- Unpack and install Conjur node
```console
mkdir conjur && cd $_
# upload Conjur-Enterprise-RHELinux-Intel-Rls-v12.4.0+Conjur.RHEL.CA.tar.gz to conjur folder
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
- Refer to https://github.com/joetanx/conjur-k8s/blob/main/generate-conjur-certificates.md for a guide to generate your own certificates
> Note: In event of "error: cert already in hash table", ensure that conjur/follower certificates do not contain the CA certificate
```console
curl -L -o conjur-certs.tgz https://github.com/joetanx/conjur-k8s/raw/main/conjur-certs.tgz
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
- Install podman
```console
yum -y installl podman
```
- Obtain the Conjur container image from CyberArk
- Upload the Conjur container image to the container host
```console
podman load -i conjur-appliance_12.4.1.tar.gz
```
- Clean-up
```console
rm -f conjur-appliance_12.4.1.tar.gz
```
- Stage the volume mounts and download the conjur configuration file
```console
mkdir -p /opt/cyberark/dap/{security,config,backups,seeds,logs}
curl -L -o /opt/cyberark/dap/config/conjur.yml https://github.com/joetanx/conjur-k8s/raw/main/conjur.yml
```
- Download the Conjur CLI and add execute permissions
- Ref: https://github.com/cyberark/conjur-api-python3/releases
```console
curl -L -o conjur-cli-rhel-8.tar.gz https://github.com/cyberark/conjur-api-python3/releases/download/v7.1.0/conjur-cli-rhel-8.tar.gz
tar xvf conjur-cli-rhel-8.tar.gz
mv conjur /usr/local/bin/
chmod +x /usr/local/bin/conjur
```
- Clean-up
```console
rm -f conjur-cli-rhel-8.tar.gz
```
- Run the Conjur container
```console
podman run --name conjur -d \
--restart=unless-stopped \
--security-opt seccomp=unconfined \
-p "443:443" -p "444:444" -p "5432:5432" -p "1999:1999" \
--log-driver journald \
-v /opt/cyberark/dap/config:/etc/conjur/config:Z \
-v /opt/cyberark/dap/security:/opt/cyberark/dap/security:Z \
-v /opt/cyberark/dap/backups:/opt/conjur/backup:Z \
-v /opt/cyberark/dap/seeds:/opt/cyberark/dap/seeds:Z \
-v /opt/cyberark/dap/logs:/var/log/conjur:Z \
registry.tld/conjur-appliance:12.4.1
```
- Setup the Conjur container as master
- Edit the admin account password in `-p` option and the Conjur account (`cyberark`) according to your environment
```console
podman exec conjur evoke configure master --accept-eula -h conjur.vx --master-altnames "conjur.vx" -p CyberArk123! cyberark
```
- Run the Conjur container as systemd service and configure it to setup with container host
- Ref: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/managing_containers/running_containers_as_systemd_services_with_podman
```console
podman generate systemd conjur --name --container-prefix="" --separator="" > /etc/systemd/system/conjur.service
systemctl enable conjur
```
- Setup Conjur certificates
- The `conjur-certs.tgz` include CA, Master and follower certificates for my lab use, you should generate your own certificates
- Refer to https://github.com/joetanx/conjur-k8s/blob/main/generate-conjur-certificates.md for a guide to generate your own certificates
> Note: In event of "error: cert already in hash table", ensure that conjur/follower certificates do not contain the CA certificate
```console
curl -L -o conjur-certs.tgz https://github.com/joetanx/conjur-k8s/raw/main/conjur-certs.tgz
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
# 5. Deploy Conjur Follower with Seed Fetcher
The Conjur follower will be deployed in the Kubernetes cluster

- Obtain the Conjur container image from CyberArk
- Upload the Conjur container image to the Kubernetes node
```console
podman load -i conjur-appliance_12.4.1.tar.gz
```
- Clean-up
```console
rm -f conjur-appliance_12.4.1.tar.gz
```
- Create service account for conjur follower deployment
```console
kubectl create serviceaccount conjur-cluster
```
- Load Conjur Policy to:
  - Define the Kubernetes Authenticator endpoint in Conjur
  - Enable the seed generation service
- Ref: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/k8s-ocp/k8s-k8s-authn.htm
```console
curl -L -o conjur-authn-k8s.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-authn-k8s.yaml
conjur policy load -f conjur-authn-k8s.yaml -b root
```
- Initialize the Conjur internal CA that will be used for the Kubernetes authenticator
> For RHEL-based Conjur Master:
```console
su conjur -c 'conjur-plugin-service possum rake authn_k8s:ca_init["conjur/authn-k8s/demo"]'
```
> For container-based Conjur Master:
```console
podman exec conjur chpst -u conjur conjur-plugin-service possum rake authn_k8s:ca_init["conjur/authn-k8s/demo"]
```
- Enable Kubernetes authenticator on Conjur Master
Add `CONJUR_AUTHENTICATORS="authn,authn-k8s/demo"` to `/opt/conjur/etc/conjur.conf` in Conjur container
> For RHEL-based Conjur Master:
```console
sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-k8s/demo"' /opt/conjur/etc/conjur.conf
systemctl restart conjur
```
> For container-based Conjur Master:
```console
podman exec conjur sed -i -e '$aCONJUR_AUTHENTICATORS="authn,authn-k8s/demo"' /opt/conjur/etc/conjur.conf
podman exec conjur sv restart conjur
```
- Verify that k8s authenticator is now enabled on Master
```console
curl -k https://conjur.vx/info
```
- Create cluster role and role binding for conjur-cluster service account
```console
curl -L -o conjur-k8s-rbac.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-k8s-rbac.yaml
kubectl apply -f conjur-k8s-rbac.yaml
```
- Configure Kubernetes cluster API details in Conjur
> You may need to install `jq` to retrieve the required information
```console
yum -y install jq
```
  - Retrieve the Kubernetes cluster API details
```console
TOKEN_SECRET_NAME="$(kubectl get secrets | grep 'conjur.*service-account-token' | head -n1 | awk '{print $1}')"
CA_CERT="$(kubectl get secret $TOKEN_SECRET_NAME -o json | jq -r '.data["ca.crt"]' | base64 --decode)"
SERVICE_ACCOUNT_TOKEN="$(kubectl get secret $TOKEN_SECRET_NAME -o json | jq -r .data.token | base64 --decode)"
API_URL="$(kubectl config view --minify -o json | jq -r '.clusters[0].cluster.server')"
```
  - Verify the values of the environment variables
```console
echo $TOKEN_SECRET_NAME
echo $CA_CERT
echo $SERVICE_ACCOUNT_TOKEN
echo $API_URL
```
  - Load the values to Conjur variables
```console
conjur variable set -i conjur/authn-k8s/demo/kubernetes/ca-cert -v "$CA_CERT"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/service-account-token -v "$SERVICE_ACCOUNT_TOKEN"
conjur variable set -i conjur/authn-k8s/demo/kubernetes/api-url -v "$API_URL"
```
- Add Conjur Master certificate to config map
- The seedfetcher will use ConfigMap value to validate the Conjur Master
```console
openssl s_client -showcerts -connect conjur.vx:443 </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > master-certificate.pem
kubectl create configmap master-certificate --from-file=ssl-certificate=<(cat master-certificate.pem)
```
- Extra step for Conjur Master on RHEL before follower deployment
> For Conjur Master on RHEL, the Conjur CLI .netrc file will cause the follower deployment to fail.
> 
> Logout and delete the .netrc before deploying the follower.
```console
conjur logout
rm -f .netrc
```
- Deploy the Follower with seedfetcher
```console
curl -L -o conjur-follower.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-follower.yaml
kubectl apply -f conjur-follower.yaml
```
- Verify that follower replication is healthy
```console
curl -k https://conjur.vx/health
```
- Clean-up
```console
rm -f master-certificate.pem
rm -f conjur-authn-k8s.yaml
rm -f conjur-k8s-rbac.yaml
```
## 5.1. Load hosts in CoreDNS
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
# 6. Setup authenticators, AppIdentities, variables, and permissions in Conjur
The policies in `conjur-app-var.yaml` configures the following:
- Authenticators
  - Creates the `conjur/authn-k8s/demo/apps` policy and creates Summon and Secretless authenticators
- AppIdentities
  - Creates the `k8s-apps/default` policy and layer
  - The authenticators created in `Authenticators` section is added to the `k8s-apps/default` layer
- Variables and permissions
  - Creates the `world_db` policy and creates variables `username` and `password`, as well as a group `consumers` under this policy
  - The `world_db/consumers` group is granted read and execute permissions on the variables
  - The `k8s-apps/default` layer created in `AppIdentities` section is added to the `world_db/consumers` group
- Download the policy file and load to Conjur
```console
curl -L -o conjur-app-var.yaml https://github.com/joetanx/conjur-k8s/raw/main/conjur-app-var.yaml
conjur policy load -f conjur-app-var.yaml -b root
```
- Populate the variables with the username and password of the MySQL database
```console
conjur variable set -i world_db/username -v cityapp
conjur variable set -i world_db/password -v Cyberark1
```
- Clean-up
```console
rm -f conjur-app-var.yaml
```
# 7. Create ConfigMap for follower certificate
- The `conjur-authn-k8s-client` and `secretless-broker` containers validate the follower service using the follower certificate
- Create a Kubernetes ConfigMap for follower certificate, the Summon and Secretless cityapp deployment will use this ConfigMap
```console
FOLLOWER_POD_NAME="$(kubectl get pods | grep follower | head -n1 | awk '{print $1}')"
kubectl exec -it $FOLLOWER_POD_NAME -c conjur -- cat /opt/conjur/etc/ssl/conjur.pem > follower-certificate.pem
kubectl create configmap follower-certificate --from-file=ssl-certificate=<(cat follower-certificate.pem)
```
- Clean-up
```console
rm -f follower-certificate.pem
```
# 8. Deploy cityapp-summon
-  Load the summon configuration yaml file as Kubernetes ConfigMap
```console
curl -L -o cityapp-summon-config.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-summon-config.yaml
kubectl create configmap cityapp-summon-config --from-file=cityapp-summon-config.yaml
```
- Deploy the Summon-based cityapp
```console
curl -L -o cityapp-summon.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-summon.yaml
kubectl apply -f cityapp-summon.yaml
```
- Clean-up
```console
rm -f *.yaml
```
# 9. Deploy cityapp-secretless
-  Load the secretless configuration yaml file as Kubernetes ConfigMap
```console
curl -L -o cityapp-secretless-config.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-secretless-config.yaml
kubectl create configmap cityapp-secretless-config --from-file=cityapp-secretless-config.yaml
```
- Deploy the Secretless-based cityapp
```console
curl -L -o cityapp-secretless.yaml https://github.com/joetanx/conjur-k8s/raw/main/cityapp-secretless.yaml
kubectl apply -f cityapp-secretless.yaml
```
- Clean-up
```console
rm -f *.yaml
```
