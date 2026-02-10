# API Key Integration Guide

This guide documents API key authentication for consuming services integrating with auth-gateway, including the key format, authentication flow, management operations, and recommended integration patterns.

## Overview

API keys provide programmatic access for:
- Service-to-service communication
- CLI tools and scripts
- CI/CD pipelines
- External integrations

API keys use HMAC-SHA256 signed requests rather than sending the secret directly. Each request is signed with a timestamp, preventing replay attacks.

## API Key Authentication Headers

API key authentication uses three HTTP headers:

| Header | Description | Format |
|--------|-------------|--------|
| `x-api-key-id` | Public key identifier (UUID) | `550e8400-e29b-41d4-a716-446655440000` |
| `x-signature` | HMAC-SHA256 signature | Hex-encoded string |
| `x-timestamp` | Request timestamp | RFC3339 (e.g., `2025-01-15T10:30:00Z`) |

### Signature Computation

The signature is computed as:

```
HMAC-SHA256(secret, method + "\n" + path + "\n" + timestamp)
```

Where:
- `secret` is the API key secret (returned once at creation)
- `method` is the HTTP method (e.g., `GET`, `POST`)
- `path` is the request URL path (e.g., `/api/user/v1/users`)
- `timestamp` is the RFC3339 timestamp from the `x-timestamp` header
- Fields are joined with newline (`\n`)

### Example: Signing a Request

```go
import (
    "github.com/go-core-stack/auth/hash"
    "net/http"
)

// Create a generator with your key ID and secret
gen := hash.NewGenerator("your-key-id", "your-secret")

// Create an HTTP request
req, _ := http.NewRequest("GET", "https://gateway.example.com/api/user/v1/users", nil)

// AddAuthHeaders sets x-api-key-id, x-signature, and x-timestamp headers
req = gen.AddAuthHeaders(req)
```

### Request Validity Window

Signed requests are valid for **5 minutes** (300 seconds) from the timestamp. After this window, the gateway rejects the request as expired.

## API Key Lifecycle

### Creation (via MyAccount API)

```
POST /api/myaccount/v1/api-key
```

```json
{
    "name": "my-service-key",
    "validity": 7776000
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable name for the key |
| `validity` | int64 | Key lifetime in seconds from creation (0 = no expiry) |

Response:

```json
{
    "name": "my-service-key",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "Active",
    "created": 1707577200,
    "expireAt": 1715353200,
    "secret": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
}
```

**Important**: The `secret` field is only returned at creation time. Store it securely -- it cannot be retrieved later.

### Management Operations

| Operation | Method | Endpoint | Description |
|-----------|--------|----------|-------------|
| Create | POST | `/api/myaccount/v1/api-key` | Create a new API key |
| List | GET | `/api/myaccount/v1/api-keys` | List user's API keys |
| Enable | POST | `/api/myaccount/v1/api-key/{id}/enable` | Re-enable a disabled key |
| Disable | POST | `/api/myaccount/v1/api-key/{id}/disable` | Disable a key (reversible) |
| Delete | DELETE | `/api/myaccount/v1/api-key/{id}` | Permanently delete a key |

All management operations require authentication (bearer token or API key) and operate within the authenticated user's scope.

## Authentication Flow (Gateway Perspective)

When a request arrives at auth-gateway with API key headers:

```
1. Extract key ID from x-api-key-id header
2. Look up key entry in MongoDB (api-keys collection) by key ID
3. Verify user info exists for the key
4. Check key expiration (expireAt vs current time)
5. Validate HMAC signature against stored secret
6. Look up the key owner's user record
7. Check if the user is disabled
8. Build Auth-Info header (realm, username, email, roles)
9. Forward request to backend with Auth-Info header
```

### Auth-Info Output

After successful API key authentication, the gateway injects the same `Auth-Info` header as for JWT authentication. Backend services receive:

```
Auth-Info: <base64-encoded JSON>
```

Decoded:

```json
{
    "realm": "acme-corp",
    "preferred_username": "john.doe",
    "email": "john@example.com",
    "given_name": "John",
    "family_name": "Doe",
    "name": "John Doe",
    "roles": ["admin", "default"],
    "isRoot": false
}
```

See [JWT Token Integration Guide](jwt-tokens.md) for full details on the `Auth-Info` header structure and how to extract it in backend services.

## Integration Patterns

### Pattern A: Proxy Through Auth-Gateway (Recommended)

Route all requests through auth-gateway's external port (8080). The gateway handles signature validation and injects the `Auth-Info` header for downstream services.

```
Client → Auth-Gateway:8080 → Your Service
         (validates key)     (receives Auth-Info)
```

```go
import (
    "net/http"
    "github.com/go-core-stack/auth/hash"
)

type Client struct {
    gatewayURL string
    signer     hash.Generator
}

func NewClient(gatewayURL, keyID, secret string) *Client {
    return &Client{
        gatewayURL: gatewayURL,
        signer:     hash.NewGenerator(keyID, secret),
    }
}

func (c *Client) ListUsers(ctx context.Context) (*http.Response, error) {
    req, _ := http.NewRequestWithContext(ctx, "GET", c.gatewayURL+"/api/user/v1/users", nil)
    req = c.signer.AddAuthHeaders(req)
    return http.DefaultClient.Do(req)
}
```

### Pattern B: Service Account API Key

Create a dedicated API key for platform backend services that need to call auth-gateway admin APIs:

```go
// Platform backend configuration
type Config struct {
    AuthGatewayURL string
    KeyID          string
    KeySecret      string
}

func (c *Config) NewSigner() hash.Generator {
    return hash.NewGenerator(c.KeyID, c.KeySecret)
}

// Use API key for auth-gateway admin calls
func (svc *Service) CreateUser(ctx context.Context, req *CreateUserRequest) error {
    httpReq, _ := http.NewRequestWithContext(ctx, "POST", svc.cfg.AuthGatewayURL+"/api/user/v1/users", body)
    httpReq = svc.signer.AddAuthHeaders(httpReq)
    // ...
}
```

### Pattern C: Shared Collection Access (Advanced)

For services needing direct API key validation (e.g., ai-gateway), import auth-gateway's table package and validate against the shared MongoDB collection:

```go
import "github.com/go-core-stack/auth-gateway/pkg/table"

// Use auth-gateway's table package for consistent access
apiKeysTable, _ := table.LocateApiKeyTable(mongoClient)

// Look up key
entry, err := apiKeysTable.Find(ctx, &table.ApiKeyId{
    Id: keyId,
})
if err != nil {
    return errors.Unauthorized
}

// Check user info exists
if entry.UserInfo == nil {
    return errors.Unauthorized
}

// Check expiration
if entry.Config.ExpireAt != 0 && entry.Config.ExpireAt < time.Now().Unix() {
    return errors.Unauthorized
}

// Validate HMAC signature
ok, err := validator.Validate(r, entry.Secret.Value)
if !ok {
    return errors.Unauthorized
}
```

**Note**: This pattern requires importing auth-gateway packages and sharing MongoDB access. Only use for tightly-coupled internal services.

## API Key Scoping

**Current State**: API keys are user-scoped. The key inherits all permissions of the creating user, including their realm roles.

**Limitation**: Cannot create keys limited to specific resources (workflows, agents).

**Workaround**:
- Create service accounts with limited roles
- Platform implements resource-level authorization on top of user context

## Key Rotation Strategy

```
1. Create new API key via POST /api/myaccount/v1/api-key
2. Update consuming services with new key ID and secret
3. Monitor old key usage (lastUsed field from list endpoint)
4. Disable old key after migration verified
5. Delete old key after grace period
```

## Security Best Practices

| Practice | Description |
|----------|-------------|
| Use expiration | Set `validity` for temporary keys |
| Rotate regularly | Rotate production keys every 90 days |
| Least privilege | Create service accounts with minimal roles |
| Monitor usage | Track `lastUsed` for anomaly detection |
| Disable before delete | Disable first to allow recovery |
| Secure secret storage | Store secrets in vault or encrypted config |

## Error Responses

| Scenario | Error Message | Cause |
|----------|---------------|-------|
| Key not found | `Invalid Api Key` | Key ID doesn't exist in database |
| Missing user info | `user not available` | Key has no associated user |
| Key expired | `Api Key is {id} expired` | Key past `expireAt` timestamp |
| Bad signature | `Invalid Signature` | HMAC signature doesn't match |
| User not found | `User {name} not found in tenant {tenant}` | Key owner's user record deleted |
| User disabled | `User {name} is disabled in tenant {tenant}` | Key owner account is disabled |
| Request expired | `expired access` | Timestamp outside 5-minute validity window |

## Related Documentation

- [JWT Token Integration](jwt-tokens.md) -- alternative authentication via bearer tokens and Auth-Info header details
- [Collection Schemas](collection-schemas.md) -- api-keys collection schema reference
- [Change Streams](change-streams.md) -- real-time event monitoring for key state changes
