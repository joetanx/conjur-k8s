# Guide to generate Conjur certificate chain using OpenSSL

Conjur uses certificates for communication between the Master, Standby, and follower nodes in Conjur cluster.

To understand Conjur certificate architecture, read: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Deployment/HighAvailability/certificate-architecture.htm

This optional step generates a self-signed CA, and uses the self-signed CA to sign the Conjur Master and followers certificates.

1.0 Generate a self-signed certificate authority
- Generate private key of the self-signed certificate authority
```console
root@conjur:~# openssl genrsa -out ConjurDemoCA.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
.....................................................+++++
............................+++++
e is 65537 (0x010001)
```
- Generate certificate of the self-signed certificate authority
> Note: change the common name of the certificate according to your environment
```console
root@conjur:~# openssl req -x509 -new -nodes -key ConjurDemoCA.key -days 365 -sha256 -out ConjurDemoCA.pem
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:SG
State or Province Name (full name) [Some-State]:Singapore
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:CyberArk Software Pte. Ltd.
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:Conjur Demo Certificate Authority
Email Address []:joe.tan@cyberark.com
```
2.0 Generate certificate for Conjur Master
> Note: change the common name/subject alternative name of the certificate according to your environment
> 
> The name must match the Conjur Master FQDN that the follower will be using to communicate to the Conjur Master
- Generate private key of the Conjur Master certificate
```console
openssl genrsa -out master.conjur.demo.key 2048
```
- Create certificate signing request for the Conjur Master certificate
```console
openssl req -new -key master.conjur.demo.key -subj "/CN=master.conjur.demo" -out master.conjur.demo.csr
```
- Create OpenSSL configuration file to add subject alternative name
```console
echo "subjectAltName=DNS:master.conjur.demo" > master.conjur.demo-openssl.cnf
```
- Generate certificate of the Conjur Master certificate
```console
openssl x509 -req -in master.conjur.demo.csr -CA ConjurDemoCA.pem -CAkey ConjurDemoCA.key -CAcreateserial -days 365 -sha256 -out master.conjur.demo.pem -extfile master.conjur.demo-openssl.cnf
```
3.0 Generate certificate for Conjur Follower
> Note: change the common name/subject alternative name of the certificate according to your environment
> 
> The name must match the follower FQDN that the follower will be using to communicate to the Conjur Master
> 
> For follower deployment in Kubernetes, the name will be the Kubernetes service FQDN in the form of `<service-name>.<namespace>.svc.cluster.local`
- Generate private key of the Conjur Follower certificate
```console
openssl genrsa -out follower.conjur.svc.cluster.local.key 2048
```
- Create certificate signing request for the Conjur Follower certificate
```console
openssl req -new -key follower.conjur.svc.cluster.local.key -subj "/CN=follower.conjur.svc.cluster.local" -out follower.conjur.svc.cluster.local.csr
```
- Create OpenSSL configuration file to add subject alternative name
```console
echo "subjectAltName=DNS:follower.conjur.svc.cluster.local" > follower.conjur.svc.cluster.local-openssl.cnf
```
- Generate certificate of the Conjur Follower certificate
```console
openssl x509 -req -in follower.conjur.svc.cluster.local.csr -CA ConjurDemoCA.pem -CAkey ConjurDemoCA.key -CAcreateserial -days 365 -sha256 -out follower.conjur.svc.cluster.local.pem -extfile follower.conjur.svc.cluster.local-openssl.cnf
```
