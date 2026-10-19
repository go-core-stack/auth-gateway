# syntax=docker/dockerfile:1
FROM golang:1.24 AS builder

WORKDIR /workspace

COPY ./ .

# GIT_TOKEN is passed as a BuildKit secret so it never lands in image
# layers or history; when present it is used for private GitHub modules
RUN --mount=type=secret,id=git_token,required=false \
	if [ -s /run/secrets/git_token ]; then \
		export GIT_CONFIG_COUNT=1 \
			GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/git_token)@github.com/.insteadOf" \
			GIT_CONFIG_VALUE_0="https://github.com/"; \
	fi; \
	go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o auth-gateway main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/auth-gateway .
COPY swagger /opt/swagger
COPY default.yaml /opt/config.yaml
USER 65532:65532

ENTRYPOINT ["/auth-gateway", "-config", "/opt/config.yaml"]
