FROM golang:1.24 as builder
ARG GIT_TOKEN

WORKDIR /workspace

COPY ./ .

RUN git config --global url."https://${GIT_TOKEN}:x-oauth-basic@github.com/Prabhjot-Sethi".insteadOf "https://github.com/Prabhjot-Sethi"
RUN git config --global url."https://${GIT_TOKEN}:x-oauth-basic@github.com/go-core-stack".insteadOf "https://github.com/go-core-stack"

RUN go env -w GOPRIVATE="github.com/Prabhjot-Sethi/*,github.com/go-core-stack/*"

RUN go mod download

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
