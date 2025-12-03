#!/bin/bash

set -ex

sudo docker run -d -p 8443:8443 -p 8080:8080 -v ./certs:/opt/certs -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=password quay.io/keycloak/keycloak:26.2.2 start-dev --https-certificate-file=/opt/certs/keycloak.local.crt --https-certificate-key-file=/opt/certs/keycloak.local.key 
