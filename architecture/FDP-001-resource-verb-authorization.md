# FDP-001: Resource-Verb Authorization

## Metadata
- **ID**: FDP-001
- **Title**: Resource-Verb Based Authorization Enforcement
- **Epic**: EPIC-001 (Fine-Grained RBAC Enhancement)
- **Author**: Engineering Head
- **Created**: 2026-02-10
- **Updated**: 2026-02-13
- **Status**: Draft
- **Reviewers**: TBD

---

## 1. Overview

### 1.1 Problem

The route table contains resource and verb information for each endpoint, but the gateway authorization logic does not use this information. Authorization decisions are based solely on role types (admin/auditor/default) rather than specific resource-action permissions.

### 1.2 Proposal

Enhance the gateway authorization flow to:
1. Extract resource and verb from the matched route
2. Evaluate permissions based on resource-verb pairs with scope awareness
3. Support constraint-based access control via headers to backend
4. Maintain zero-latency impact through in-memory operations only

### 1.3 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Gateway-level resource-verb checks | Domain-specific authorization logic |
| Scope-level authorization (unscoped/tenant/org-unit) | Cross-tenant permission sharing |
| Permission evaluation for org-unit roles | Full ABAC or policy languages |
| Constraint header passing to backend | Request body inspection |
| Fallback behavior for routes without resource | Custom scopes (deferred) |

---

## 2. Critical Performance Requirements

### 2.1 Zero Latency Impact (NON-NEGOTIABLE)

**All permission checks MUST execute entirely in-memory. No database or network calls during request handling.**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    REQUEST PATH (LATENCY CRITICAL)                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ✓ ALLOWED                        ✗ PROHIBITED                      │
│  ══════════                       ════════════                      │
│  • In-memory lookups              • Database queries                │
│  • Pre-compiled matchers          • Network calls                   │
│  • Lock-free reads                • File I/O                        │
│  • O(1) or O(log n) operations    • Mutex contention                │
│  • CPU-cache-friendly structures  • Dynamic memory allocation       │
│  • Atomic pointer swaps           • Blocking operations             │
│                                                                      │
│  TARGET LATENCY: < 5 microseconds for full authorization check     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                  BACKGROUND PATH (EVENTUAL CONSISTENCY)              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ✓ ALLOWED                        ACCEPTABLE DELAY                  │
│  ══════════                       ════════════════                  │
│  • MongoDB change streams         • Permission changes: 3-10 sec    │
│  • Async reconciliation           • Role updates: 3-10 sec          │
│  • Debounced cache rebuilds       • Route changes: 3-10 sec         │
│  • Atomic cache swaps                                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Performance Targets

| Operation | Target | Max Acceptable |
|-----------|--------|----------------|
| Route match | < 500 ns | < 1 µs |
| Permission lookup | < 200 ns | < 500 ns |
| Pattern match | < 100 ns | < 200 ns |
| Full authorization | < 2 µs | < 5 µs |
| Memory per request | 0 bytes | < 64 bytes |
| Allocations per request | 0 | ≤ 1 |

### 2.3 Implementation Requirements

| Component | Requirement | Current Solution |
|-----------|-------------|------------------|
| Route matching | O(k) lookup, thread-safe, zero allocations | `github.com/go-core-stack/patricia` |
| Permission cache | Lock-free reads, atomic updates | Atomic pointer swap or sync.Map |
| Object pooling | Reduce GC pressure for hot paths | `sync.Pool` (stdlib) |
| Cache updates | Copy-on-write with atomic swap | `sync/atomic` (stdlib) |

**Note:** Do not replace existing libraries without benchmarking. Only evaluate alternatives if current implementation fails to meet performance targets.

### 2.4 Benchmarking Requirements

```go
// REQUIRED: Benchmark all authorization paths
func BenchmarkFullAuthorization(b *testing.B) {
    // Expected output:
    // BenchmarkFullAuthorization-8   500000   2341 ns/op   0 B/op   0 allocs/op
    //                                                       ↑        ↑
    //                                              Zero bytes  Zero allocs
}
```

---

## 3. Route Schema

### 3.1 Enhanced Route Data Structure

```go
type Route struct {
    Key      *Key   `bson:"key,omitempty"`      // {Url, Method}
    Endpoint string `bson:"endpoint,omitempty"`

    // AUTHENTICATION FLAGS (Orthogonal to Scope)
    // Both flags are kept - they serve different purposes
    IsPublic bool `bson:"isPublic,omitempty"`  // No authentication required
    IsRoot   bool `bson:"isRoot,omitempty"`    // Root tenancy only (admin portal APIs)

    // RBAC
    Resource string `bson:"resource,omitempty"` // e.g., "workflow"
    Verb     string `bson:"verb,omitempty"`     // e.g., "execute"

    // SCOPE DEFINITION (replaces Scopes []string)
    Scope ScopeDefinition `bson:"scope,omitempty"`

    // RESOURCE IDENTIFIER (for constraint matching in URL)
    ResourceIdentifier *ResourceIdentifier `bson:"resourceIdentifier,omitempty"`

    // METADATA
    Group  string `bson:"group,omitempty"`  // Service group
    Source string `bson:"source,omitempty"` // Origin: "auth-gateway", "config", etc.
}

type ScopeType string

const (
    // Unscoped: Authentication required, no scope-based authorization
    // User just needs to be authenticated. User-specific resources fall here.
    ScopeTypeUnscoped ScopeType = ""

    // Tenant: Resource is scoped to tenant, accessible across all org-units
    // Requires tenant-level permissions (tenant-admin or explicit grant)
    ScopeTypeTenant ScopeType = "tenant"

    // Org-Unit: Resource is scoped to specific org-unit
    // Requires org-unit membership with appropriate role
    ScopeTypeOrgUnit ScopeType = "org-unit"

    // Custom: Backend-defined scope (deferred to future phase)
    ScopeTypeCustom ScopeType = "custom"
)

type ScopeDefinition struct {
    Type         ScopeType `yaml:"type" bson:"type"`
    PathParam    string    `yaml:"pathParam,omitempty" bson:"pathParam,omitempty"`
    PathPosition int       `yaml:"pathPosition,omitempty" bson:"pathPosition,omitempty"`

    // For custom scopes (deferred)
    CustomType    string            `yaml:"customType,omitempty" bson:"customType,omitempty"`
    ParentScope   *ScopeDefinition  `yaml:"parentScope,omitempty" bson:"parentScope,omitempty"`
    CustomContext map[string]string `yaml:"customContext,omitempty" bson:"customContext,omitempty"`
}

type ResourceIdentifier struct {
    PathParam    string `yaml:"pathParam" bson:"pathParam"`       // "name", "id"
    PathPosition int    `yaml:"pathPosition" bson:"pathPosition"` // Position in URL
    Field        string `yaml:"field,omitempty" bson:"field,omitempty"` // Constraint field (default: "name")
}
```

### 3.2 Scope Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                      SCOPE HIERARCHY                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  SCOPE TYPE         │ MEANING                                       │
│  ═══════════════════╪═══════════════════════════════════════════════│
│                     │                                                │
│  "" (unscoped)      │ Authentication required, no scope authZ       │
│                     │ User-specific resources fall here             │
│                     │ Examples: user-profile, personal tokens       │
│                     │                                                │
│  "tenant"           │ Tenant-scoped ("global within tenant")        │
│                     │ Accessible across all org-units               │
│                     │ Requires tenant-level permissions             │
│                     │ Examples: org-unit mgmt, tenant-settings      │
│                     │                                                │
│  "org-unit"         │ Org-unit scoped                               │
│                     │ Requires org-unit membership + role           │
│                     │ Examples: workflow, model, dataset            │
│                     │                                                │
│  "custom"           │ Backend-defined scope (DEFERRED)              │
│                     │ Examples: project, team, workspace            │
│                     │                                                │
└─────────────────────────────────────────────────────────────────────┘

ORTHOGONAL FLAGS (Separate from Scope):
  • isPublic: true  → No authentication required
  • isRoot: true    → Root tenancy only (can combine with any scope)

A resource can be:
  • isRoot: true + scope: tenant → Root tenancy only, tenant-scoped
  • isRoot: false + scope: tenant → Any tenant, tenant-scoped
  • isRoot: false + scope: "" → Any authenticated user, no scope check
```

---

## 4. Authorization Flow

### 4.1 Complete Authorization Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AUTHORIZATION FLOW                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. PUBLIC CHECK                                                     │
│     └─ isPublic: true → Allow (skip all checks)                     │
│                                                                      │
│  2. AUTHENTICATION                                                   │
│     └─ Validate JWT, extract tenant/user                            │
│                                                                      │
│  3. ROOT TENANCY CHECK                                               │
│     └─ isRoot: true && !authInfo.IsRoot → Deny                      │
│                                                                      │
│  4. SCOPE-BASED AUTHORIZATION                                        │
│     │                                                                │
│     ├─ UNSCOPED (""): User authenticated → check permissions        │
│     │                                                                │
│     ├─ TENANT: Check tenant-level permissions                       │
│     │                                                                │
│     ├─ ORG-UNIT: Extract org-unit from path                         │
│     │            Check org-unit role permissions                    │
│     │                                                                │
│     └─ CUSTOM: Backend-defined rules (DEFERRED)                     │
│                                                                      │
│  5. RESOURCE IDENTIFIER CONSTRAINT CHECK (if applicable)            │
│     └─ For GET/UPDATE/DELETE: Extract name from URL                 │
│        Check against permission constraints                         │
│                                                                      │
│  6. SET AUTH HEADERS & PROXY TO BACKEND                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Authorization Implementation

```go
// pkg/gateway/permission.go

func (g *gateway) Authorize(
    ctx context.Context,
    authInfo *auth.AuthInfo,
    route *Route,
    r *http.Request,
) error {
    // 1. PUBLIC CHECK
    if route.IsPublic {
        return nil
    }

    // 2. AUTHENTICATION (already done by middleware)
    if authInfo == nil {
        return ErrUnauthenticated
    }

    // 3. ROOT TENANCY CHECK
    if route.IsRoot && !authInfo.IsRoot {
        return ErrRootTenancyRequired
    }

    // 4. SCOPE-BASED AUTHORIZATION
    scopeCtx, err := g.extractScopeContext(authInfo, route, r)
    if err != nil {
        return err
    }

    perms, err := g.checkScopePermission(authInfo, scopeCtx, route.Resource, route.Verb)
    if err != nil {
        return err
    }

    // 5. RESOURCE IDENTIFIER CONSTRAINT CHECK
    if route.ResourceIdentifier != nil && perms.HasConstraints() {
        resourceName := extractPathParam(r,
            route.ResourceIdentifier.PathParam,
            route.ResourceIdentifier.PathPosition)

        if resourceName != "" {
            field := route.ResourceIdentifier.Field
            if field == "" {
                field = "name"
            }
            if err := perms.CheckConstraint(field, resourceName); err != nil {
                return ErrForbidden
            }
        }
    }

    // 6. SET AUTH HEADERS & PROXY
    g.setAuthHeaders(r, authInfo, scopeCtx, perms)
    return nil
}
```

---

## 5. Constraint Header Approach

### 5.1 Design Principle: No Body Inspection at Gateway

The gateway does NOT inspect request bodies. Constraints are passed to backend via headers for enforcement.

**Benefits:**
- Keeps gateway simple (no body parsing)
- Enables efficient LIST filtering at database level
- Consistent enforcement across all operations
- Prevents data leakage (users never see disallowed items in LIST)

### 5.2 Auth Context Headers

```yaml
# Headers passed from Gateway to Backend
headers:
  # Identity
  X-Auth-Tenant:
    description: "Tenant ID (from JWT realm)"
    example: "acme-corp"
    always: true

  X-Auth-User:
    description: "Authenticated username"
    example: "john.doe"
    always: true

  X-Auth-Is-Root:
    description: "Whether user is from root tenancy"
    example: "true"
    always: true

  # Scope context
  X-Auth-OrgUnit:
    description: "Org-unit from URL path (if applicable)"
    example: "engineering"
    when: "scope.type == org-unit"

  X-Auth-Role:
    description: "User's role in current org-unit"
    example: "admin"
    when: "scope.type == org-unit"

  # Permissions
  X-Auth-Allowed-Verbs:
    description: "Comma-separated verbs user can perform on this resource"
    example: "list,get,create,update"
    when: "resource is defined"

  X-Auth-Constraints:
    description: "JSON-encoded field constraints for this resource"
    example: '{"name":{"prefix":"abc-"},"type":{"values":["etl","ml"]}}'
    when: "user has constrained permissions"
```

### 5.3 Backend Constraint Usage

| Operation | Gateway Check | Backend Enforcement |
|-----------|---------------|---------------------|
| LIST | Passes constraints via header | Filter query at DB level |
| CREATE | No body inspection | Validate request body fields against constraints |
| GET | Check URL param against constraints | Defense-in-depth verification |
| UPDATE | Check URL param against constraints | Defense-in-depth verification |
| DELETE | Check URL param against constraints | Defense-in-depth verification |

---

## 6. Match Criteria

### 6.1 Scope Matching (Simple)

Scope matching is intentionally simple - either specific or wildcard.

| Type | Pattern | Example | Matches |
|------|---------|---------|---------|
| specific | `"engineering"` | `"engineering"` | Exact match only |
| wildcard | `"*"` | Any value | All scopes |

### 6.2 Resource Matching (Flexible)

Resource matching supports common patterns. Regex is intentionally deferred.

| Type | Pattern | Example | Matches |
|------|---------|---------|---------|
| specific | `"my-workflow"` | `"my-workflow"` | Exact match only |
| wildcard | `"*"` | Any value | All resources |
| prefix | `"abc-*"` | `"abc-test"`, `"abc-prod"` | Starts with `abc-` |
| suffix | `"*-prod"` | `"workflow-prod"` | Ends with `-prod` |
| contains | `"*test*"` | `"my-test-workflow"` | Contains `test` |

**Deferred:** Regex matching is not implemented. Re-evaluate if patterns above prove insufficient.

### 6.3 Match Schema

```go
type ScopeMatchType string

const (
    ScopeMatchSpecific ScopeMatchType = "specific"
    ScopeMatchWildcard ScopeMatchType = "wildcard"
)

type ResourceMatchType string

const (
    ResourceMatchSpecific ResourceMatchType = "specific"
    ResourceMatchWildcard ResourceMatchType = "wildcard"
    ResourceMatchPrefix   ResourceMatchType = "prefix"
    ResourceMatchSuffix   ResourceMatchType = "suffix"
    ResourceMatchContains ResourceMatchType = "contains"
)

type ScopeMatch struct {
    Type  ScopeMatchType `json:"type" yaml:"type"`
    Value string         `json:"value,omitempty" yaml:"value,omitempty"`
}

type ResourceMatch struct {
    Type  ResourceMatchType `json:"type" yaml:"type"`
    Value string            `json:"value,omitempty" yaml:"value,omitempty"`
}

// Compact pattern parsing (auto-detect type from pattern string)
func ParseResourceMatch(pattern string) *ResourceMatch {
    if pattern == "*" {
        return &ResourceMatch{Type: ResourceMatchWildcard}
    }

    hasLeadingWildcard := strings.HasPrefix(pattern, "*")
    hasTrailingWildcard := strings.HasSuffix(pattern, "*")

    switch {
    case hasLeadingWildcard && hasTrailingWildcard:
        value := strings.Trim(pattern, "*")
        return &ResourceMatch{Type: ResourceMatchContains, Value: value}
    case hasTrailingWildcard:
        value := strings.TrimSuffix(pattern, "*")
        return &ResourceMatch{Type: ResourceMatchPrefix, Value: value}
    case hasLeadingWildcard:
        value := strings.TrimPrefix(pattern, "*")
        return &ResourceMatch{Type: ResourceMatchSuffix, Value: value}
    default:
        return &ResourceMatch{Type: ResourceMatchSpecific, Value: pattern}
    }
}
```

---

## 7. Caching Architecture

### 7.1 Multi-Level Cache

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MULTI-LEVEL CACHE ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  REQUEST PATH (Read-Only, Lock-Free)                                │
│  ═══════════════════════════════════                                │
│                                                                      │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │   Route Trie    │    │  Permission     │    │  Role           │ │
│  │   (Immutable)   │    │  Cache          │    │  Definitions    │ │
│  │                 │    │  (Lock-free)    │    │  (Immutable)    │ │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘ │
│           │                      │                      │          │
│           └──────────────────────┼──────────────────────┘          │
│                                  │                                  │
│                     Atomic Pointer Swap                            │
│                                  │                                  │
│  ════════════════════════════════╪══════════════════════════════════│
│                                  │                                  │
│  BACKGROUND PATH (Reconciliation)│                                  │
│  ════════════════════════════════╪══════════════════════════════════│
│                                  │                                  │
│  ┌───────────────────────────────▼───────────────────────────────┐ │
│  │                     Cache Builder                              │ │
│  │  • Watches MongoDB change streams                             │ │
│  │  • Debounces updates (3 second window)                        │ │
│  │  • Builds new immutable cache                                 │ │
│  │  • Atomic pointer swap (zero-downtime)                        │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Copy-on-Write Cache Updates

```go
type AuthorizationCache struct {
    snapshot atomic.Pointer[CacheSnapshot]
}

type CacheSnapshot struct {
    routes      RouteTrie                      // Use existing go-core-stack/patricia
    permissions map[string]*CompiledPermissions // Immutable after creation
    roles       map[string]*CompiledRole        // Immutable after creation
    buildTime   time.Time
    version     uint64
}

// Read path: Lock-free (atomic pointer load, then read immutable data)
func (c *AuthorizationCache) Authorize(req *AuthRequest) error {
    snap := c.snapshot.Load()  // Atomic load - no lock
    return snap.authorize(req) // Read from immutable snapshot
}

// Write path: Build entirely new snapshot, atomic swap
func (c *AuthorizationCache) Rebuild(ctx context.Context) error {
    // Build new immutable snapshot in background
    newSnap := &CacheSnapshot{
        routes:      buildRouteTrie(ctx),
        permissions: buildPermissionCache(ctx),
        roles:       buildRoleCache(ctx),
        buildTime:   time.Now(),
        version:     c.snapshot.Load().version + 1,
    }
    // Atomic swap - readers see old or new, never partial state
    c.snapshot.Store(newSnap)
    // Old snapshot garbage collected when no readers remain
    return nil
}
```

**Key Pattern:** The snapshot is immutable after creation. No locks needed for reads. Updates build a completely new snapshot and swap atomically.
```

---

## 8. Backward Compatibility

### 8.1 Routes Without Resource/Verb

```go
if route.Resource == "" {
    return s.legacyRoleTypeCheck(authInfo, orgUnit, r.Method)
}
```

### 8.2 Feature Flag

```yaml
authorization:
  enableResourceVerbCheck: true  # false = legacy behavior only
  dryRun: false                  # Log but don't enforce
  logDeniedRequests: true
```

---

## 9. Implementation Tasks

| Task ID | Description | Effort | Dependencies |
|---------|-------------|--------|--------------|
| FDP-001-T1 | Define ScopeDefinition and ResourceIdentifier structs | S | None |
| FDP-001-T2 | Update Route schema with new fields | S | T1 |
| FDP-001-T3 | Implement scope extraction from URL | M | T2 |
| FDP-001-T4 | Implement resource identifier extraction | S | T2 |
| FDP-001-T5 | Implement match criteria (prefix/suffix/contains) | M | None |
| FDP-001-T6 | Implement constraint header generation | M | T5 |
| FDP-001-T7 | Implement in-memory permission cache | L | None |
| FDP-001-T8 | Implement copy-on-write cache updates | M | T7 |
| FDP-001-T9 | Add performance benchmarks | M | T8 |
| FDP-001-T10 | Write unit and integration tests | M | All |

---

## 10. Open Questions

| Question | Status | Answer |
|----------|--------|--------|
| Support regex matching? | DEFERRED | Not implemented. Re-evaluate if needed. |
| Custom scopes? | DEFERRED | Backend-defined scopes for future phase. |
| Distributed cache (Redis)? | DECIDED | Start with local. Evaluate if needed. |

---

## 11. References

- [Route Table Schema](https://github.com/go-core-stack/auth/blob/main/route/route.go)
- [Current Gateway Authorization](https://github.com/go-core-stack/auth-gateway/blob/main/pkg/gateway/server.go)
