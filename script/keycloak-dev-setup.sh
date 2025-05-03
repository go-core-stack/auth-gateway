#!/bin/bash

set -ex

sudo docker run -d -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=password quay.io/keycloak/keycloak:26.2.2 start-dev