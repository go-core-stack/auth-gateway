# Self Signed certificates

These are the default certificates packaged as part of the container image to
render https endpoint, which can be overriden as part of the deployment.

These certificates are generated using following command
```
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout tls.key -out tls.crt -subj "/CN=localhost"
chmod 644 certs/tls.key
```
ensure that the tls.key has read permissions set for the user in container to read the file
