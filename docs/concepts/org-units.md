# Org-Units

Org-units (Organization Units) provide soft-tenancy boundaries within a hard tenant. They let tenant administrators partition users and resources into logical groups without requiring separate Keycloak realms.

## Multi-Tenancy Hierarchy

```
Customer (Billing)
└── Tenant (Keycloak Realm = Hard Boundary)
    └── Org Unit (Soft Boundary)
        └── Users (with OU-specific roles)
```

A **tenant** maps to a Keycloak realm and forms a hard isolation boundary — data never crosses tenant boundaries. Within a tenant, **org-units** create soft boundaries that scope resources and control access without the overhead of additional realms.

## Key Characteristics

| Characteristic | Description |
|----------------|-------------|
| Scope | Exists within a single tenant |
| Membership | Users can belong to multiple org-units |
| Roles | Same user can have different roles per org-unit |
| Isolation | Resources are scoped to org-units |
| Hierarchy | Flat (no nesting) |

## Use Cases

### Team-Based Resource Isolation

```
Tenant: acme-corp
├── Org Unit: "platform-team" → infrastructure, pipelines
├── Org Unit: "ml-team" → models, experiments
└── Org Unit: "product-team" → workflows, integrations
```

### Environment Separation

```
Tenant: acme-corp
├── Org Unit: "development"
├── Org Unit: "staging"
└── Org Unit: "production" (restricted)
```

### Project-Based Access

```
Tenant: consulting-firm
├── Org Unit: "project-alpha"
└── Org Unit: "project-beta"
```

### Department Structure

```
Tenant: enterprise
├── Org Unit: "finance"
├── Org Unit: "hr"
└── Org Unit: "engineering"
```

## Roles Within Org-Units

Three built-in roles control what a user can do inside an org-unit:

| Role | Description | Allowed HTTP Methods |
|------|-------------|----------------------|
| `admin` | Full access to the org-unit | All methods (wildcard) |
| `auditor` | Read-only access | GET, HEAD only |
| `default` | Standard member | Subject to resource-level RBAC |

> **Note:** Custom roles with fine-grained permission definitions (resource matching, allow/deny actions) are defined in the proto schema but not yet implemented. See the `org-unit-role.proto` definition for the planned structure.

### Role Precedence

Tenant administrators (users with tenant-level admin rights) bypass org-unit role checks entirely. Within an org-unit, the authorization order is:

1. **Tenant admin** — full access, skips org-unit checks
2. **Org-unit admin** — full access within the org-unit
3. **Org-unit auditor** — read-only access (GET/HEAD)
4. **Org-unit default** — minimal access, requires resource-level RBAC

## Authorization Flow

```
Request with org-unit scope
        │
        ▼
┌─────────────────────────────────┐
│ 1. Match route                  │
│    Patricia tree URL matching   │
│    Extract: resource, verb, ou  │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ 2. Authenticate user            │
│    Validate JWT token           │
│    Extract: tenant, username    │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ 3. Check tenant admin           │
│    If tenant admin → allow      │
│    If user-specific route → allow│
└─────────────────────────────────┘
        │ (not tenant admin)
        ▼
┌─────────────────────────────────┐
│ 4. Org-unit role check          │
│    Lookup: OrgUnitUserKey       │
│      {tenant, username, ouId}   │
│    Validate role vs HTTP method │
│      admin  → allow all         │
│      auditor → GET/HEAD only    │
│      default → deny (needs RBAC)│
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ 5. Validate org-unit exists     │
│    Query org-unit by tenant     │
│    Not found → 404              │
└─────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────┐
│ 6. Forward to backend           │
│    X-Auth-Context includes OU   │
│    Access log recorded          │
└─────────────────────────────────┘
```

### Scoped vs Unscoped Routes

Routes are either **org-unit scoped** or **unscoped**:

- **Scoped routes** include `scopes: ["ou"]` in their route definition. The gateway extracts the `{ou}` path parameter and performs org-unit role checks before forwarding.
- **Unscoped routes** (like org-unit CRUD itself) operate at the tenant level and only require tenant-level authorization.

## API Reference

### Org-Unit Management (Tenant-Scoped)

These endpoints manage org-units themselves and operate at the tenant level.

| Operation | Method | Endpoint | Resource | Verb |
|-----------|--------|----------|----------|------|
| List | GET | `/api/mytenant/v1/ous` | org-unit | list |
| Create | POST | `/api/mytenant/v1/ou` | org-unit | create |
| Get | GET | `/api/mytenant/v1/ou/{id}` | org-unit | get |
| Update | PUT | `/api/mytenant/v1/ou/{id}` | org-unit | update |
| Delete | DELETE | `/api/mytenant/v1/ou/{id}` | org-unit | delete |
| Access Logs | GET | `/api/mytenant/v1/ou/{id}/access-logs` | org-unit | get-access-logs |

#### Create Org-Unit

```
POST /api/mytenant/v1/ou
Content-Type: application/json

{
  "name": "platform-team",
  "desc": "Platform engineering team resources"
}
```

Response:

```json
{
  "id": "generated-uuid",
  "name": "platform-team",
  "desc": "Platform engineering team resources",
  "created": 1707500000,
  "createdBy": "admin-user"
}
```

#### List Org-Units

```
GET /api/mytenant/v1/ous?offset=0&limit=20
```

Response:

```json
{
  "entries": [
    {
      "id": "ou-uuid-1",
      "name": "platform-team",
      "desc": "Platform engineering team resources",
      "created": 1707500000,
      "createdBy": "admin-user"
    }
  ],
  "total": 1
}
```

#### Get Access Logs

```
GET /api/mytenant/v1/ou/{id}/access-logs?start=1707400000&end=1707500000
```

Response:

```json
{
  "entries": [
    {
      "timestamp": 1707450000,
      "ou": "platform-team",
      "user": "jane",
      "ipAddr": "10.0.0.1",
      "method": "GET",
      "path": "/api/auth/v1/ou/platform-team/users",
      "status": 200,
      "userAgent": "curl/8.0",
      "tenant": "acme-corp"
    }
  ]
}
```

### Membership Management (Org-Unit Scoped)

These endpoints manage user membership within an org-unit. All routes are scoped to the `{ou}` path parameter.

| Operation | Method | Endpoint | Resource | Verb |
|-----------|--------|----------|----------|------|
| List Members | GET | `/api/auth/v1/ou/{ou}/users` | org-unit-user-role | list |
| Add Member | POST | `/api/auth/v1/ou/{ou}/user` | org-unit-user-role | add |
| Update Role | PUT | `/api/auth/v1/ou/{ou}/user/{user}` | org-unit-user-role | update |
| Remove Member | DELETE | `/api/auth/v1/ou/{ou}/user/{user}` | org-unit-user-role | delete |

#### Add User to Org-Unit

```
POST /api/auth/v1/ou/platform-team/user
Content-Type: application/json

{
  "user": "jane",
  "role": "admin"
}
```

Valid roles: `admin`, `default`, `auditor`. The server rejects any other value.

#### Update User Role

```
PUT /api/auth/v1/ou/platform-team/user/jane
Content-Type: application/json

{
  "role": "auditor"
}
```

### Role Management (Org-Unit Scoped)

These endpoints manage roles available within an org-unit.

| Operation | Method | Endpoint | Resource | Verb | Status |
|-----------|--------|----------|----------|------|--------|
| List Roles | GET | `/api/auth/v1/ou/{ou}/roles` | org-unit-role | list | Implemented |
| Create Custom Role | POST | `/api/auth/v1/ou/{ou}/role` | org-unit-role | create | Not yet implemented |
| Get Custom Role | GET | `/api/auth/v1/ou/{ou}/role/{name}` | org-unit-role | get | Not yet implemented |
| Update Custom Role | PUT | `/api/auth/v1/ou/{ou}/role/{name}` | org-unit-role | update | Not yet implemented |
| Delete Custom Role | DELETE | `/api/auth/v1/ou/{ou}/role/{name}` | org-unit-role | delete | Not yet implemented |

#### List Available Roles

```
GET /api/auth/v1/ou/platform-team/roles
```

Response:

```json
{
  "entries": [
    {
      "name": "default",
      "desc": "Standard user role to provide access to all the resources available in the Organization Unit",
      "builtIn": true
    },
    {
      "name": "admin",
      "desc": "Administrator role to provide access to everything in the Organization Unit including management of users and resources",
      "builtIn": true
    },
    {
      "name": "auditor",
      "desc": "Auditor role to provide read-only access to all the resources available in the Organization Unit",
      "builtIn": true
    }
  ],
  "total": 3
}
```

## Data Model

### Org-Unit Record

Stored in the `org-units` MongoDB collection.

| Field | Type | Description |
|-------|------|-------------|
| `_id.id` | string | UUID identifier |
| `name` | string | Display name |
| `desc` | string | Description |
| `created` | int64 | Unix timestamp of creation |
| `createdBy` | string | Username of creator |
| `tenant` | string | Owning tenant (Keycloak realm) |

### Org-Unit User Record

Stored in the `org-unit-users` MongoDB collection.

| Field | Type | Description |
|-------|------|-------------|
| `_id.tenant` | string | Tenant boundary |
| `_id.username` | string | User identifier |
| `_id.orgUnitId` | string | Org-unit identifier |
| `role` | string | One of: admin, default, auditor |
| `created` | int64 | Unix timestamp of membership creation |
| `createdBy` | string | Username of who added this member |

## Integration Guide for Consuming Services

### Extracting Org-Unit from Auth Context

Backend services behind the auth-gateway receive the `X-Auth-Context` header. When a request is org-unit scoped, extract the org-unit identifier from the request path or query parameter.

```go
// Backend service receives forwarded request with auth context
func handler(w http.ResponseWriter, r *http.Request) {
    authInfo := auth.FromRequest(r)

    tenant := authInfo.Realm
    orgUnit := r.URL.Query().Get("orgUnit") // Or from path param

    // Filter data by org-unit
    resources, _ := db.Query(`
        SELECT * FROM resources
        WHERE tenant_id = $1 AND org_unit_id = $2
    `, tenant, orgUnit)
}
```

### Storing Resources with Org-Unit Scope

When persisting resources that belong to an org-unit, include both the tenant and org-unit identifiers to maintain proper isolation.

```sql
-- Resources table with org-unit scoping
CREATE TABLE resources (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR NOT NULL,
    org_unit_id VARCHAR NOT NULL,
    name VARCHAR NOT NULL,
    -- ... other fields

    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- Index for efficient filtering
CREATE INDEX idx_resources_tenant_ou ON resources(tenant_id, org_unit_id);
```

### Registering Org-Unit Scoped Routes

Consuming services register their routes with the `scopes` field set to `["ou"]` to indicate that the gateway should perform org-unit role checks.

```yaml
# routes.yaml for consuming service
routes:
  - url: "/api/v1/org-units/{ou}/workflows"
    method: GET
    resource: "workflow"
    verb: "list"
    scopes: ["ou"]  # Gateway will extract {ou} and check membership
```

### Change Stream Integration

Org-unit collections support MongoDB change streams for real-time updates. See the [collection schemas documentation](../integration/collection-schemas.md) for watch event details.

**Org-Units collection** emits events on insert, update, and delete.

**Org-Unit Users collection** emits events on membership insert, role update, and membership delete.

## Best Practices

| Practice | Description |
|----------|-------------|
| **Naming** | Use lowercase, hyphenated names (e.g., `platform-team`) |
| **Granularity** | Don't create too many org-units; group logically |
| **Default Role** | Assign the `default` role for standard members; reserve `admin` for OU managers |
| **Cleanup** | Remove users from org-units when they leave teams |
| **Auditing** | Use the `auditor` role for compliance reviewers who need read-only access |
| **Tenant Admins** | Tenant admins bypass OU checks — use sparingly |

## Limitations

| Limitation | Workaround |
|------------|------------|
| No nested hierarchy | Use naming conventions (e.g., `eng-backend`, `eng-frontend`) |
| Single scope per route | Design APIs with single OU context per request |
| No cross-OU access | Assign the user to multiple org-units |
| Delete not yet implemented | Org-unit delete endpoint returns unimplemented |
| Custom roles not yet implemented | Use built-in roles (admin, default, auditor) |
