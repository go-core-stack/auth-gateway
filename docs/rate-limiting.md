# Rate Limiting Architecture in Auth-Gateway

## 1. Context

### Auth-Gateway as Control Plane

Auth-gateway serves as the control plane gateway for platform management operations. All control plane APIs (local handlers and proxied backend services) flow through auth-gateway uniformly.

### Deployment Model

```
                              ┌─────────────────┐
                              │  Load Balancer  │
                              └────────┬────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
     ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
     │  Auth-Gateway   │      │  Auth-Gateway   │      │  Auth-Gateway   │
     │   Replica 1     │      │   Replica 2     │      │   Replica N     │
     │   (Stateless)   │      │   (Stateless)   │      │   (Stateless)   │
     └─────────────────┘      └─────────────────┘      └─────────────────┘
```

**Key Constraints:**
- Multiple stateless replicas behind load balancer
- Requests can route to any replica
- No shared runtime state for rate limiting
- Each replica operates independently

## 2. Rate Limiting Requirements

### Scope

Rate limiting applies to **all authenticated requests** at the gateway, regardless of authentication method:

| Auth Method | Rate Limited |
|-------------|--------------|
| JWT/Bearer Token | Yes |
| API Key (HMAC) | Yes |
| Client Certificate | Yes |

### Initial Configuration (Phase 1)

| Parameter | Value |
|-----------|-------|
| Default Rate Limit | 200 requests per second per tenant |
| Scope | Per-tenant |
| Configuration | Global default (config file) |
| Per-tenant overrides | Phase 2 (future) |

## 3. Available Libraries

### Standard Library: golang.org/x/time/rate

The Go standard extended library provides a token bucket rate limiter:

```go
import "golang.org/x/time/rate"

// Create a limiter: 200 requests/second with burst of 200
limiter := rate.NewLimiter(rate.Limit(200), 200)

// Check if request is allowed (non-blocking)
if limiter.Allow() {
    // Process request
}

// Or wait for permission (blocking)
err := limiter.Wait(ctx)
```

**Features:**
- Token bucket algorithm
- Configurable rate and burst
- Non-blocking (`Allow()`) and blocking (`Wait()`) modes
- Context support for cancellation

### Extended Library: github.com/go-core-stack/core/rate

The core stack provides extended rate limiting capabilities:

```go
import "github.com/go-core-stack/core/rate"

// Create a manager with aggregate capacity
mgr := rate.NewLimitManager(totalCapacity)

// Create per-tenant limiters
limiter, err := mgr.NewLimiter("tenant-key", sustainedRate, burstSize)

// Dynamic capacity rebalancing
limiter.SetInUse(true)  // Activate - gets share of capacity
limiter.SetInUse(false) // Deactivate - capacity redistributed
```

**Features:**
- Per-key (per-tenant) limiter management
- Dynamic capacity rebalancing among active limiters
- I/O wrappers for readers and HTTP writers
- Built on `golang.org/x/time/rate`

## 4. Design: Local Rate Limiting

### Approach

Each replica maintains independent local rate limiters using `golang.org/x/time/rate`. Accept that:
- Effective limit is approximately `Limit × N` in worst case
- In practice, with good load balancing, effective limit is closer to target
- Acceptable for control plane abuse prevention

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LOCAL RATE LIMITING (Per Replica)                         │
│                                                                              │
│  Replica 1                 Replica 2                 Replica N               │
│  ┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐    │
│  │ rate.Limiter map  │    │ rate.Limiter map  │    │ rate.Limiter map  │    │
│  │                   │    │                   │    │                   │    │
│  │ tenant:acme → 200 │    │ tenant:acme → 200 │    │ tenant:acme → 200 │    │
│  │ tenant:globex→200 │    │ tenant:globex→200 │    │ tenant:globex→200 │    │
│  └───────────────────┘    └───────────────────┘    └───────────────────┘    │
│                                                                              │
│  Worst case: Tenant gets N × 200 RPS (if perfectly distributed)             │
│  Typical case: Close to 200 RPS (load balancer tends to be sticky-ish)      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 5. Configuration

### Config File (default.yaml)

```yaml
# Rate limiting configuration
rateLimits:
  enabled: true
  defaultRPS: 200      # Requests per second per tenant
  burstSize: 200       # Max burst (defaults to defaultRPS)
  cleanup:
    interval: 5m       # Cleanup check frequency
    maxIdle: 10m       # Remove limiters idle longer than this
```

### Config Struct

```go
// pkg/config/config.go

type Config struct {
    // ... existing fields ...
    RateLimits RateLimitsConfig `yaml:"rateLimits"`
}

type RateLimitsConfig struct {
    Enabled    bool          `yaml:"enabled"`
    DefaultRPS float64       `yaml:"defaultRPS"`
    BurstSize  int           `yaml:"burstSize"`
    Cleanup    CleanupConfig `yaml:"cleanup"`
}

type CleanupConfig struct {
    Interval time.Duration `yaml:"interval"`
    MaxIdle  time.Duration `yaml:"maxIdle"`
}
```

## 6. Request Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REQUEST PROCESSING FLOW                              │
│                                                                              │
│  Incoming Request                                                            │
│        │                                                                     │
│        ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 1. AUTHENTICATION                                                    │    │
│  │    - JWT Token / API Key / Certificate                               │    │
│  │    - Extract tenant from auth context                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│        │                                                                     │
│        │ tenant = authInfo.Realm                                            │
│        ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 2. RATE LIMIT CHECK                                                  │    │
│  │    - rateLimiter.Allow(tenant)                                       │    │
│  │    - Uses golang.org/x/time/rate.Limiter.Allow()                    │    │
│  │    - If not allowed: Return 429                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│        │                                                                     │
│        ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 3. AUTHORIZATION                                                     │    │
│  │    - RBAC/PBAC checks                                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│        │                                                                     │
│        ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ 4. ROUTE & HANDLE                                                    │    │
│  │    - Execute handler or proxy to backend                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 7. Special Cases

### Internal Gateway (Port 8081)

Skip rate limiting for internal gateway - trusted service-to-service communication.

### Public Endpoints

Unauthenticated endpoints have no tenant identity. Consider IP-based rate limiting separately if needed.

### Root Tenant

Phase 1: Same limit as other tenants.
Phase 2: Configurable higher or unlimited rate.

## 8. Limitations and Trade-offs

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Approximate limiting with N replicas | Effective limit up to N × configured | Acceptable for abuse prevention |
| No cross-replica visibility | Per-replica remaining count | Minimal impact for control plane |
| State lost on restart | Fresh bucket after restart | Bucket starts full, minimal impact |

### For Stricter Limiting (Future)

If stricter rate limiting is needed:
1. **Sticky Sessions**: Configure load balancer to route same tenant to same replica
2. **Lower per-replica limits**: Set limit to `target / expected_replicas`

## 9. Implementation Phases

### Phase 1: Global Rate Limiting (Current Scope)

| Task | Description |
|------|-------------|
| 1 | Add `RateLimitsConfig` to config package |
| 2 | Implement `TenantRateLimiter` using `golang.org/x/time/rate` |
| 3 | Integrate into gateway request flow |
| 4 | Add cleanup routine for idle limiters |
| 5 | Skip rate limiting for internal gateway |
| 6 | Update `default.yaml` with rate limit config |

### Phase 2: Per-Tenant Configuration (Future)

| Task | Description |
|------|-------------|
| 1 | Add `RateLimits` field to `TenantConfig` |
| 2 | Load tenant-specific limits from MongoDB |
| 3 | Watch for config changes via reconciler |

## 10. Summary

| Aspect | Decision |
|--------|----------|
| Library | `golang.org/x/time/rate` |
| Algorithm | Token Bucket |
| State | Local in-memory per replica |
| Default Limit | 200 RPS per tenant |
| Burst | 200 requests |
| Auth Types | All (JWT, API Key, Cert) |
| Internal Gateway | Skip rate limiting |
| Trade-off | Approximate limiting, acceptable for control plane |
