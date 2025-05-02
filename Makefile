# Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
# Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

include config.mk

# image name of the auth-gateway container
IMG:= $(REPO)/auth-gateway:$(VERSION)

# root directory for the build
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: all

all: build

build: go-format go-vet go-lint
	sudo docker build --build-arg GIT_TOKEN="${GIT_TOKEN}" \
		-t ${IMG} .

go-format:
	go fmt ./...

go-vet:
	go vet ./...

go-lint:
	golangci-lint run