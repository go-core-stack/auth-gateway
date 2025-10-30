# Repository Guidelines

## Project Structure & Module Organization
The entry point lives in `main.go`, orchestrating gRPC, HTTP, and gateway setup. Core domain logic is grouped under `pkg/`, with subpackages for `auth`, `controller`, `server`, `keycloak`, and `table` models. Generated protobuf stubs sit in `api/`, while shared API descriptions and Swagger assets live under `docs/` and `swagger/`. Configuration defaults are tracked in `default.yaml`, and reusable scripts (for example, Keycloak bootstrap) are in `script/`. Integration fixtures and smoke tests reside in `test/` with sample API keys in `test/api-keys/`. Third-party schemas and assets are vendored beneath `third_party/`.

## Build, Test, and Development Commands
- `make build` — runs `go fmt`, `go vet`, `golangci-lint`, then produces the container image (`REPO`/`auth-gateway:VERSION`).
- `go test ./...` — executes unit and integration tests; pass `-run` to scope modules during rapid iteration.
- `go run main.go -config default.yaml` — launches the gateway locally; override ports via `API_PORT`, `GATEWAY_PORT`, and `GRPC_PORT`.
- `script/keycloak-dev-setup.sh` — provisions a development Keycloak realm to mirror tenant flows before running integration suites.

## Coding Style & Naming Conventions
Target Go 1.24 and rely on `go fmt` for formatting; lint fixes must satisfy `golangci-lint run`. Use tabs for indentation (Go default) and keep files in UTF-8 ASCII. Package names stay lower_snake (for example, `pkg/controller`), exported identifiers use PascalCase with leading doc comments, and configuration structs mirror YAML keys in lowerCamel. Generated files in `api/` should be updated via `buf` or `protoc` pipelines, never edited manually.

## Testing Guidelines
Prefer table-driven tests inside `_test.go` files colocated with the code. Name tests with the pattern `Test<Feature><Scenario>` and use subtests (`t.Run`) to capture edge cases. Integration flows that depend on Keycloak or MongoDB belong in `test/main.go`; gate them behind environment checks so `go test ./...` remains reliable in CI. Aim to cover error branches around tenant provisioning, controller requests, and auth flows before submitting a change.

## Commit & Pull Request Guidelines
Commit messages must stay short, specific, and actionable so reviewers immediately see what will happen if the change is applied.

### Before you commit
- Configure git with your name, email, and preferred editor (`git config --global user.name "Firstname Lastname"`, etc.). Drop the `--global` flag if you need repo-specific values.
- Sign commits with `git commit -s` so the `Signed-off-by` trailer is added automatically.

### Commit message format
- Subject line: ≤55 characters, imperative mood (`Fix tenant lookup`, not `Fixed...`), no trailing period.
- Always add a blank line between the subject and body.
- Wrap body text at 72 characters and explain the what and why of the change; skip how unless it clarifies intent.
- Bullets are fine (use `-` and a following space) and should use hanging indents for wrapped lines.
- Include relevant trackers near the end of the message (for example, `Jira ID: CLOUD-123` or `Refs: #456`).
- Finish with the `Signed-off-by` line inserted by `git commit -s`.

Remember that a good subject line should complete the sentence: "If applied, this commit will ...".

### Branching workflow
- Develop changes on a purpose-built branch named after the work (`feature/mfa-enrollment`, `fix/tenant-timeout`, etc.) and push that branch upstream before opening a pull request.
- When a pull request is already under review, stack follow-up tweaks onto the existing commit with `git commit --amend` (or an interactive rebase) and update the remote branch with `git push --force-with-lease` so the PR stays focused.

### Pull requests
- Keep PR descriptions concise and highlight behavioral changes first.
- Reference linked issues or design docs and include evidence (screenshots, curl transcripts) for new endpoints.
- Call out schema or configuration updates and commit regenerated protobufs when applicable.
- Confirm `make build` and `go test ./...` succeed before requesting review.
- When the PR merges, append the tracking issue ID to the title in parentheses (`(#123)`).
