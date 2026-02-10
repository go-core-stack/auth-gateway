# Auth Context and JWT Token Integration Guide

This guide documents the authentication flow for services consuming auth-gateway, including the JWT token structure issued by Keycloak and the `Auth-Info` header forwarded to backend services.

## Overview

**Important**: JWT tokens are validated at auth-gateway and **do not propagate to backend services**. Instead, auth-gateway extracts claims and forwards a base64-encoded digest as the `Auth-Info` header.

```
┌──────────┐     JWT Token      ┌───────────────┐     Auth-Info        ┌─────────────┐
│  Client  │ ─────────────────▶ │ Auth-Gateway  │ ──────────────────▶ │   Backend   │
│          │                    │ (validates)   │   (base64 digest)   │   Service   │
└──────────┘                    └───────────────┘                     └─────────────┘
                                       │
                                       ▼
                                ┌───────────────┐
                                │   Keycloak    │
                                │   (OIDC)      │
                                └───────────────┘
```

**Token Flow**:
1. Client authenticates and receives JWT from Keycloak
2. Client sends JWT to auth-gateway in `Authorization: Bearer` header (or via `AUTH_TOKEN` cookie for WebSocket connections)
3. Auth-gateway extracts realm from JWT payload (without validation) to determine the Keycloak endpoint
4. Auth-gateway validates JWT signature against the realm-specific Keycloak OIDC provider
5. Auth-gateway extracts claims into an `Auth-Info` header (base64-encoded JSON)
6. Backend services receive **only** `Auth-Info`, never the raw JWT

## JWT Claims Structure

### Standard OIDC Claims

| Claim | Type | Description | Example |
|-------|------|-------------|---------|
| `sub` | string | User ID (Keycloak UUID) | `"f47ac10b-58cc..."` |
| `preferred_username` | string | Username | `"john.doe"` |
| `email` | string | Email address | `"john@example.com"` |
| `email_verified` | bool | Email verification status | `true` |
| `given_name` | string | First name | `"John"` |
| `family_name` | string | Last name | `"Doe"` |
| `name` | string | Full name | `"John Doe"` |
| `sid` | string | Session ID | `"abc123"` |
| `iss` | string | Issuer URL | `"https://keycloak/realms/tenant1"` |
| `aud` | string/array | Audience | `"auth-gateway"` |
| `exp` | number | Expiration (epoch) | `1707580800` |
| `iat` | number | Issued at (epoch) | `1707577200` |

### Auth-Gateway Specific Claims

| Claim | Type | Description | Usage |
|-------|------|-------------|-------|
| `realm` | string | Tenant identifier | **Use as tenant_id** |
| `realm_access.roles` | array | Realm-level roles | `["admin", "default"]` |

### Example Token Payload

```json
{
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "preferred_username": "john.doe",
  "email": "john@example.com",
  "email_verified": true,
  "given_name": "John",
  "family_name": "Doe",
  "name": "John Doe",
  "sid": "session-xyz",
  "realm": "acme-corp",
  "realm_access": {
    "roles": ["admin", "default"]
  },
  "iss": "https://keycloak.example.com/realms/acme-corp",
  "aud": "auth-gateway",
  "exp": 1707580800,
  "iat": 1707577200
}
```

## Tenant ID Extraction

**Important**: The `realm` claim is the tenant identifier used for data isolation throughout the platform.

Auth-gateway extracts the realm from the JWT payload before validation (to determine the correct Keycloak endpoint). The realm is embedded as a custom claim in the token payload:

```go
// From pkg/auth/verifier.go — extracts realm without full validation
func getRealmFromToken(token string) (string, error) {
    // JWT has 3 dot-separated parts: header.payload.signature
    tParts := strings.Split(token, ".")
    if len(tParts) != 3 {
        return "", errors.New("invalid JWT token")
    }

    // Decode payload (part 2) to extract realm
    jsonData, err := base64.RawURLEncoding.DecodeString(tParts[1])
    if err != nil {
        return "", err
    }

    info := &struct {
        Realm string `json:"realm,omitempty"`
    }{}
    return info.Realm, json.Unmarshal(jsonData, info)
}
```

## Auth-Info Header (Backend Services)

Backend services behind auth-gateway receive the `Auth-Info` header containing a **base64-encoded JSON** digest of the authenticated user. **This is the primary way backend services access auth information.**

### Header Name

| Protocol | Header Name | Notes |
|----------|-------------|-------|
| HTTP | `Auth-Info` | Base64-encoded JSON |
| gRPC | `auth-info` | Same format, lowercase per gRPC convention |

### Header Format

The `Auth-Info` header value is the base64 (raw URL encoding) of the JSON-serialized `AuthInfo` struct:

```
Auth-Info: eyJyZWFsbSI6ImFjbWUtY29ycCIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9lIiwiZW1haWwiOiJqb2huQGV4YW1wbGUuY29tIn0
```

Decoded, this is:

```json
{"realm":"acme-corp","preferred_username":"john.doe","email":"john@example.com"}
```

### AuthInfo Structure

```go
// From github.com/go-core-stack/auth/context
type AuthInfo struct {
    Realm         string   `json:"realm,omitempty"`
    UserName      string   `json:"preferred_username"`
    Email         string   `json:"email,omitempty"`
    EmailVerified bool     `json:"email_verified,omitempty"`
    FullName      string   `json:"name,omitempty"`
    FirstName     string   `json:"given_name,omitempty"`
    LastName      string   `json:"family_name,omitempty"`
    SessionID     string   `json:"sid,omitempty"`
    Roles         []string `json:"roles,omitempty"`
    IsRoot        bool     `json:"isRoot,omitempty"`
}
```

> **Note on JSON field names**: The JSON tags use JWT/OIDC claim names (e.g., `preferred_username`, `given_name`) rather than Go-style camelCase. This is because the struct is also used to unmarshal JWT token claims directly.

### Extracting Auth Context in Backend Services (HTTP)

```go
import (
    common "github.com/go-core-stack/auth/context"
)

func MyHandler(w http.ResponseWriter, r *http.Request) {
    // Extract auth info from the Auth-Info header
    authInfo, err := common.GetAuthInfoHeader(r)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    tenantID := authInfo.Realm
    username := authInfo.UserName
    isAdmin := authInfo.IsRoot

    // Use for authorization, data filtering, etc.
}
```

### Extracting Auth Context in Backend Services (gRPC)

For gRPC services, the auth context is extracted from gRPC metadata. Use the `ProcessAuthInfo` function to populate the context, then retrieve with `GetAuthInfoFromContext`:

```go
import (
    common "github.com/go-core-stack/auth/context"
)

// In your gRPC interceptor or handler:
func MyGRPCHandler(ctx context.Context, req *MyRequest) (*MyResponse, error) {
    // ProcessAuthInfo extracts auth-info from gRPC metadata and stores in context
    authCtx, err := common.ProcessAuthInfo(ctx)
    if err != nil {
        return nil, status.Error(codes.Unauthenticated, "missing auth context")
    }

    // Retrieve from context
    authInfo, err := common.GetAuthInfoFromContext(authCtx)
    if err != nil {
        return nil, status.Error(codes.Unauthenticated, "invalid auth context")
    }

    tenantID := authInfo.Realm
    // ...
}
```

### Why No JWT in Backend?

| Concern | Resolution |
|---------|------------|
| Token validation | Already done by auth-gateway |
| Signature verification | Not needed -- internal network trusted |
| Token expiry | Gateway rejects expired tokens |
| Reduced payload size | Digest is smaller than full JWT |
| No Keycloak dependency | Backends don't need JWKS/OIDC |

## Internal Gateway: Service-to-Service Routing

Auth-gateway supports an **internal mode** for service-to-service communication. When configured with `internal=true`, the gateway:

- Accepts pre-processed `Auth-Info` headers from trusted sources (typically the external gateway)
- Skips authentication (AuthN) but still performs full authorization (AuthZ) checks
- Bypasses rate limiting

```
┌──────────┐      ┌──────────────────┐   Auth-Info    ┌──────────────────┐   Auth-Info    ┌─────────┐
│  Client  │ ───▶ │ External Gateway │ ────────────▶ │ Internal Gateway │ ────────────▶ │ Backend │
│          │      │ (authenticates)  │               │ (authorizes)     │               │ Service │
└──────────┘      └──────────────────┘               └──────────────────┘               └─────────┘
```

## JWT Token Validation (Gateway-Side Reference)

This section documents how auth-gateway validates JWTs. **Backend services should use the `Auth-Info` header, not validate JWTs directly.**

### JWKS Endpoint

```
https://{keycloak-host}/realms/{realm-name}/protocol/openid-connect/certs
```

### Multi-Tenant Verifier

Auth-gateway maintains a per-realm verifier cache. When a request arrives for a new realm, a verifier is created on demand:

```go
// Simplified from pkg/auth/auth.go
type authManager struct {
    url      string
    clientId string
    mu       sync.RWMutex
    authMap  map[string]*authVerifier
}

// Fast path: read lock for existing verifiers
func (m *authManager) getVerifier(realm string) *authVerifier {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.authMap[realm]
}

// Slow path: write lock to create new verifier
func (m *authManager) locateVerifier(realm string) *authVerifier {
    m.mu.Lock()
    defer m.mu.Unlock()
    // Double-check after acquiring write lock
    if v, ok := m.authMap[realm]; ok {
        return v
    }
    // Create OIDC provider for this realm
    provider, _ := oidc.NewProvider(ctx, m.url+"/realms/"+realm)
    v := &authVerifier{
        verifier: provider.Verifier(&oidc.Config{ClientID: m.clientId}),
    }
    m.authMap[realm] = v
    return v
}
```

### Root Tenant Detection

When the `realm` claim is `"root"`, the gateway sets the `IsRoot` flag on the auth info. Root tenants have elevated privileges including access to root-only routes:

```go
if info.Realm == "root" {
    info.IsRoot = true
}
```

### Realm Role Extraction

The gateway extracts `realm_access.roles` from the JWT claims and maps them into the `Roles` field of `AuthInfo`:

```go
type localAuthInfo struct {
    common.AuthInfo `json:",inline"`
    RealmAccess     struct {
        Roles []string `json:"roles,omitempty"`
    } `json:"realm_access,omitempty"`
}

// After decoding:
info.Roles = info.RealmAccess.Roles
```

## Token Lifetimes

| Token Type | Default Lifetime | Configurable |
|------------|------------------|--------------|
| Access Token | 5 minutes | Yes (Keycloak realm settings) |
| Refresh Token | 30 minutes | Yes (Keycloak realm settings) |
| ID Token | 5 minutes | Yes |

**Recommendation**: Implement token refresh flow for long-running sessions.

## Common Roles

| Role | Description |
|------|-------------|
| `admin` | Tenant administrator -- full access to all tenant resources |
| `auditor` | Read-only access for compliance |
| `default` | Standard user role |

## Related Documentation

- [Change Streams](change-streams.md) -- real-time event monitoring via MongoDB
- [Collection Schemas](collection-schemas.md) -- MongoDB collection reference
