# RBAC Architecture Decisions

This document captures key architectural decisions for the fine-grained RBAC
implementation. It explains the reasoning behind each decision so future
developers understand **why** the system works the way it does.

---

## 1. Scope Model Design

**Decision:** Three scope types -- unscoped, tenant, org-unit.

**Context:**

Auth-gateway authorizes requests at different organizational boundaries.
Resources naturally belong to one of three levels:

| Scope | Config Value | Meaning | Examples |
|-------|-------------|---------|----------|
| Unscoped | `""` (empty) | Authentication only, no scope-based authorization | user-profile, personal tokens |
| Tenant | `"tenant"` | Global within a tenant, accessible across all org-units | org-unit management, tenant settings |
| Org-unit | `"org-unit"` | Requires membership and role in a specific org-unit | workflow, model, dataset |

**Why this design:**

- `isRoot` and `isPublic` are kept as **separate flags** because they control
  access restrictions (who can reach the endpoint), not authorization scope
  (what boundary applies). A resource can be `isRoot: true` with any scope.
- Empty scope means **unscoped**, not "global". Unscoped resources only need
  authentication -- the user's identity is enough. This avoids confusion between
  "no scope check needed" and "global across the platform".
- User-specific resources (profile, personal API tokens) fall naturally under
  unscoped because they belong to the authenticated user, not to any
  organizational boundary.

**Alternatives considered:**

- *Single "global" scope for both root and tenant resources* -- rejected because
  it conflates two different concerns: root tenancy restriction and tenant-level
  authorization.
- *User as a separate scope tier* -- rejected because user-specific resources
  don't need scope-based authorization; authentication is sufficient.

---

## 2. Constraint Passing via Headers

**Decision:** The gateway will pass authorization constraints to backend services
via a dedicated header and will **not** inspect request bodies.

> **Note:** Today the gateway only forwards identity context via `X-Auth-Context`
> (see `pkg/gateway/server.go`). The constraint header (`X-Auth-Constraints`) is
> a planned addition as part of the resource-verb authorization work (FDP-001).
> This section documents the architectural reasoning behind that design.

**Why this design:**

- **Keeps the gateway simple.** Body parsing would couple the gateway to every
  service's request schema and add latency on every request.
- **Enables efficient LIST filtering.** Backends can apply constraints directly
  at the database query level, ensuring users never see resources they shouldn't.
- **Consistent enforcement.** The same constraint mechanism works for all
  operations (LIST, CREATE, GET, UPDATE, DELETE).
- **Backend has full context.** For CREATE, the resource identifier is in the
  request body -- only the backend can validate it meaningfully.

**How operations will differ:**

| Operation | Gateway Role | Backend Role |
|-----------|-------------|--------------|
| LIST | Pass constraints via header | Filter query at DB level |
| CREATE | No body inspection | Validate body fields against constraints |
| GET/UPDATE/DELETE | Check URL parameter against constraints | Defense-in-depth verification |

**Alternatives considered:**

- *Body inspection at gateway* -- rejected because it adds latency, creates
  coupling to service schemas, and is fragile across API versions.
- *Gateway filtering of responses* -- rejected because it's inefficient (fetch
  then discard) and risks data leakage if filtering fails.

---

## 3. Match Criteria

**Decision:**

- **Scope matching:** specific value or wildcard (`*`) only.
- **Resource matching:** specific, wildcard, prefix (`abc-*`), suffix (`*-prod`),
  contains (`*test*`).
- **No regex support.**

**Why this design:**

- Scope matching is intentionally simple because scopes represent structural
  organizational boundaries (specific org-unit or all org-units). There's no
  need for pattern matching on scope names.
- Resource patterns cover the common naming conventions platforms use. Prefix
  and suffix matching handle namespaced resources (`ai-*`, `*-prod`), and
  contains handles embedded identifiers.
- Regex was intentionally deferred due to complexity (ReDoS risk, testing
  burden, compilation overhead). The simpler patterns are easier to reason
  about and audit. If they prove insufficient, regex can be added later
  without breaking existing configurations.

**Alternatives considered:**

- *Full regex support from day one* -- deferred. The risk-to-benefit ratio is
  unfavorable for the initial release. Re-evaluate based on real platform
  adoption feedback.

---

## 4. Performance Architecture

**Decision:** Zero database calls in the request path. Eventual consistency is
acceptable.

**Why this design:**

Auth-gateway sits in the critical path for **every** HTTP request in the
platform. Adding even a single database query per request would degrade
performance for all consuming services.

The acceptable trade-off: permission and role changes may take 3-10 seconds to
propagate. This window of eventual consistency is appropriate because permission
changes are infrequent compared to request volume.

**Key constraints:**

| Requirement | Target |
|-------------|--------|
| Full authorization check | < 5 microseconds |
| Allocations per request | Zero (target) |
| Database calls in request path | Zero (non-negotiable) |
| Change propagation delay | 3-10 seconds (acceptable) |

**How it works:**

- All authorization data (roles, permissions, routes) lives in **immutable
  in-memory snapshots**.
- Background reconcilers watch MongoDB change streams and rebuild snapshots
  asynchronously.
- New snapshots are swapped in atomically via pointer swap -- readers see
  either the old or new snapshot, never a partial state.
- The request path performs only in-memory lookups against the current snapshot.
  No locks are acquired for reads.

**Alternatives considered:**

- *Distributed cache (Redis)* -- deferred. Local in-memory cache is simpler,
  meets latency requirements, and change streams handle multi-instance
  consistency. Redis adds a network hop per authorization check.

---

## 5. Resource Identifier Extraction

**Decision:** The gateway will extract resource identifiers from URL path
parameters for constraint checking on GET, UPDATE, and DELETE operations.

> **Note:** This capability is not yet implemented. The current route loader
> in `pkg/gateway/routes.go` reads `Scopes` but has no concept of
> `resourceIdentifier`. This section documents the planned design so that
> implementers understand the reasoning when the route schema is extended
> (see FDP-001 and FDP-003 for implementation details).

**Why this design:**

- **Early rejection.** If a user's permissions are constrained to resources
  matching `abc-*` and they request `xyz-workflow`, the gateway can deny the
  request immediately without forwarding it to the backend.
- **Reduced backend load.** Unauthorized requests never reach the service.
- **Defense in depth.** The backend still validates independently; the gateway
  check is an additional layer.

**When it will apply:**

| Operation | Resource Identifier Location | Gateway Checks? |
|-----------|-----------------------------|-----------------|
| GET | URL path parameter | Yes |
| UPDATE | URL path parameter | Yes |
| DELETE | URL path parameter | Yes |
| LIST | Not in URL (query params/body) | No -- backend filters |
| CREATE | Request body | No -- backend validates |

This keeps the gateway's role clear: it checks what it can see (URL parameters)
and delegates what it can't (body content) to backends via constraint headers.
