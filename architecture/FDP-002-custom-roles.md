# FDP-002: Custom Roles Implementation

## Metadata
- **ID**: FDP-002
- **Title**: Custom Role Management and Permission Evaluation
- **Epic**: EPIC-001 (Fine-Grained RBAC Enhancement)
- **Author**: Engineering Head
- **Created**: 2026-02-10
- **Status**: Draft
- **Reviewers**: TBD
- **Dependencies**: FDP-001 (Resource-Verb Authorization)

---

## 1. Overview

### 1.1 Problem

The proto definitions for custom roles exist (`org-unit-role.proto`) but all handlers return `Unimplemented`. Tenants cannot create roles beyond the three built-in options (admin, auditor, default).

### 1.2 Proposal

Implement custom role CRUD operations and integrate permission evaluation into the authorization flow established by FDP-001. Custom roles are **platform-specific** - each platform using auth-gateway defines roles matching their domain resources.

### 1.3 Value Proposition

| Without Custom Roles | With Custom Roles |
|---------------------|-------------------|
| 3 fixed roles for all use cases | Roles tailored to platform's domain |
| "default" role has no clear permissions | Roles define explicit capabilities |
| Platforms must implement own authz | Centralized permission management |
| Generic admin/auditor only | Domain-specific roles (workflow-operator, model-admin, etc.) |

### 1.3.1 Platform Context

Auth-gateway is a **reusable component** for platforms. Custom roles enable:

- **AI Platform**: model-viewer, model-deployer, inference-operator
- **Workflow Platform**: workflow-viewer, workflow-executor, workflow-admin
- **Data Platform**: dataset-reader, dataset-curator, pipeline-operator

Each platform defines roles against **their registered resources** (see FDP-003).

### 1.4 Critical Constraint: Zero Latency Impact

**Custom role evaluation MUST NOT add latency to the request path.** Per EPIC-001 architectural constraints:

| Requirement | Implementation |
|-------------|----------------|
| In-memory role cache | All role definitions are pre-loaded and cached in memory |
| Background population | Role cache is populated via MongoDB change streams in background goroutines |
| No DB queries in AuthZ | `resolveRole()` reads from cache, NEVER from database during request handling |
| Pre-compiled matchers | Resource/verb matchers are compiled at cache-load time |
| Eventual consistency | Role changes may take seconds to propagate - this is acceptable |

```
Request Path (ZERO DB CALLS):
  AuthZ → resolveRole(cache) → evaluatePermissions(in-memory) → Allow/Deny

Background Path (Async):
  MongoDB ChangeStream → Update Cache → Pre-compile Matchers
```

---

## 2. Current State

### 2.1 Proto Definition

```protobuf
// api/org-unit-role.proto
service OrgUnitRole {
    rpc ListOrgUnitRoles(ListOrgUnitRolesReq) returns (ListOrgUnitRolesResp);
    rpc CreateCustomRole(CreateCustomRoleReq) returns (OrgUnitRoleInfo);      // Stub
    rpc UpdateCustomRole(UpdateCustomRoleReq) returns (OrgUnitRoleInfo);      // Stub
    rpc GetCustomRole(GetCustomRoleReq) returns (OrgUnitRoleInfo);            // Stub
    rpc DeleteCustomRole(DeleteCustomRoleReq) returns (google.protobuf.Empty); // Stub
}

message RolePermission {
    string resource = 1;
    ResourceMatch match = 2;
    repeated string verbs = 3;
    RolePermissionActionDefs.Action action = 4;  // ALLOW, DENY, LOG
}
```

### 2.2 Current Handler

```go
// pkg/server/org-unit-role.go
func (s *Server) CreateCustomRole(ctx context.Context, req *pb.CreateCustomRoleReq) (*pb.OrgUnitRoleInfo, error) {
    return nil, status.Errorf(codes.Unimplemented, "Custom role creation not yet implemented")
}
```

---

## 3. Proposed Design

### 3.1 Custom Role Schema

```go
// pkg/table/custom-role.go

type CustomRoleKey struct {
    Tenant  string `bson:"tenant"`
    OrgUnit string `bson:"orgUnit"` // Empty string = tenant-wide role
    Name    string `bson:"name"`
}

type CustomRole struct {
    Key         CustomRoleKey    `bson:"_id"`
    DisplayName string           `bson:"displayName,omitempty"`
    Description string           `bson:"description,omitempty"`
    Permissions []RolePermission `bson:"permissions"`
    IsSystem    bool             `bson:"isSystem,omitempty"` // Cannot be deleted
    CreatedAt   int64            `bson:"createdAt"`
    CreatedBy   string           `bson:"createdBy"`
    UpdatedAt   int64            `bson:"updatedAt,omitempty"`
    UpdatedBy   string           `bson:"updatedBy,omitempty"`
}

type RolePermission struct {
    Resource      string         `bson:"resource"`                // Resource type from registry
    Verbs         []string       `bson:"verbs"`                   // Subset of available verbs
    Action        string         `bson:"action,omitempty"`        // "allow" (default), "deny"
    ScopeMatch    *ScopeMatch    `bson:"scopeMatch,omitempty"`    // Scope constraint
    ResourceMatch *ResourceMatch `bson:"resourceMatch,omitempty"` // Resource name constraint
}

// Match criteria for scope and resource
// Scope: specific or wildcard only
// Resource: specific, wildcard, prefix, suffix, contains (NO REGEX)
type ScopeMatch struct {
    Type  string `bson:"type"`            // "specific", "wildcard"
    Value string `bson:"value,omitempty"` // For specific: exact value
}

type ResourceMatch struct {
    Type  string `bson:"type"`            // "specific", "wildcard", "prefix", "suffix", "contains"
    Value string `bson:"value,omitempty"` // Pattern value (without wildcards)
}

// Compact pattern syntax: auto-detected from pattern string
// "*" → wildcard
// "abc-*" → prefix "abc-"
// "*-prod" → suffix "-prod"
// "*test*" → contains "test"
// "exact" → specific "exact"
```

### 3.2 MongoDB Collection

```javascript
// Collection: custom-roles
// Indexes:
db["custom-roles"].createIndex({"_id.tenant": 1, "_id.name": 1}, {unique: true})
db["custom-roles"].createIndex({"_id.tenant": 1, "_id.orgUnit": 1})

// Example document:
{
    "_id": {
        "tenant": "acme-corp",
        "orgUnit": "",  // Tenant-wide role
        "name": "workflow-operator"
    },
    "displayName": "Workflow Operator",
    "description": "Can view and execute workflows, but not create or delete",
    "permissions": [
        {
            "resource": "workflow",
            "verbs": ["list", "get", "execute"],
            "action": "allow"
        },
        {
            "resource": "workflow-run",
            "verbs": ["list", "get"],
            "action": "allow"
        }
    ],
    "isSystem": false,
    "createdAt": 1707580800,
    "createdBy": "admin@acme-corp.com"
}
```

### 3.3 Role Scoping

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ROLE SCOPING                                  │
│                                                                      │
│  Tenant: acme-corp                                                   │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Tenant-Wide Roles (orgUnit = "")                              │  │
│  │  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐  │  │
│  │  │ workflow-viewer │ │ workflow-operator│ │ model-admin     │  │  │
│  │  └─────────────────┘ └─────────────────┘ └─────────────────┘  │  │
│  │                                                                │  │
│  │  Can be assigned to users in ANY org-unit within tenant       │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Org-Unit Specific Roles                                       │  │
│  │                                                                │  │
│  │  OrgUnit: engineering                                          │  │
│  │  ┌─────────────────┐ ┌─────────────────┐                      │  │
│  │  │ deploy-operator │ │ infra-viewer    │                      │  │
│  │  └─────────────────┘ └─────────────────┘                      │  │
│  │                                                                │  │
│  │  OrgUnit: data-science                                         │  │
│  │  ┌─────────────────┐                                          │  │
│  │  │ experiment-runner│                                          │  │
│  │  └─────────────────┘                                          │  │
│  │                                                                │  │
│  │  Can only be assigned within their respective org-units       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4 Role Resolution Order

When evaluating permissions for a user in an org-unit. **CRITICAL: This function reads ONLY from in-memory cache, never from database.**

```go
// resolveRole looks up role from in-memory cache ONLY
// It NEVER queries the database - per EPIC-001 zero-latency constraint
func (p *PermissionChecker) resolveRole(tenant, orgUnit, roleName string) (*CompiledRole, error) {
    // 1. Check org-unit specific role (from cache)
    role, found := p.roleCache.Get(tenant, orgUnit, roleName)
    if found {
        return role, nil
    }

    // 2. Fall back to tenant-wide role (from cache)
    role, found = p.roleCache.Get(tenant, "", roleName)
    if found {
        return role, nil
    }

    // 3. Not in cache - do NOT fetch from DB
    // Fall back to built-in role evaluation
    return nil, errors.NotFound
}
```

---

## 4. API Implementation

### 4.1 CreateCustomRole

```go
func (s *Server) CreateCustomRole(ctx context.Context, req *pb.CreateCustomRoleReq) (*pb.OrgUnitRoleInfo, error) {
    authInfo := auth.AuthInfoFromContext(ctx)

    // 1. Validate caller has permission to create roles
    if !s.canManageRoles(authInfo, req.OrgUnit) {
        return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
    }

    // 2. Validate role name
    if err := validateRoleName(req.Name); err != nil {
        return nil, status.Errorf(codes.InvalidArgument, "invalid role name: %v", err)
    }

    // 3. Validate permissions reference valid resources
    if err := s.validatePermissions(ctx, authInfo.Realm, req.Permissions); err != nil {
        return nil, status.Errorf(codes.InvalidArgument, "invalid permissions: %v", err)
    }

    // 4. Check role doesn't already exist
    existing, _ := s.customRoles.Get(ctx, CustomRoleKey{
        Tenant:  authInfo.Realm,
        OrgUnit: req.OrgUnit,
        Name:    req.Name,
    })
    if existing != nil {
        return nil, status.Error(codes.AlreadyExists, "role already exists")
    }

    // 5. Create role
    role := &CustomRole{
        Key: CustomRoleKey{
            Tenant:  authInfo.Realm,
            OrgUnit: req.OrgUnit,
            Name:    req.Name,
        },
        DisplayName: req.DisplayName,
        Description: req.Description,
        Permissions: convertPermissions(req.Permissions),
        CreatedAt:   time.Now().Unix(),
        CreatedBy:   authInfo.UserName,
    }

    if err := s.customRoles.Create(ctx, role); err != nil {
        return nil, status.Errorf(codes.Internal, "failed to create role: %v", err)
    }

    return toProto(role), nil
}
```

### 4.2 Permission Validation

Permissions must reference resources that exist in the resource registry:

```go
func (s *Server) validatePermissions(ctx context.Context, tenant string, perms []*pb.RolePermission) error {
    resources := s.resourceMgr.GetResourcesDef(false) // Get available resources

    for _, perm := range perms {
        // Check resource exists
        availableVerbs, found := resources.Search(perm.Resource)
        if !found {
            return fmt.Errorf("unknown resource: %s", perm.Resource)
        }

        // Check verbs are valid for this resource
        for _, verb := range perm.Verbs {
            if !slices.Contains(availableVerbs, verb) && verb != "*" {
                return fmt.Errorf("invalid verb %q for resource %q (available: %v)",
                    verb, perm.Resource, availableVerbs)
            }
        }
    }

    return nil
}
```

### 4.3 ListOrgUnitRoles (Enhanced)

Return both built-in and custom roles:

```go
func (s *Server) ListOrgUnitRoles(ctx context.Context, req *pb.ListOrgUnitRolesReq) (*pb.ListOrgUnitRolesResp, error) {
    authInfo := auth.AuthInfoFromContext(ctx)

    roles := []*pb.OrgUnitRoleInfo{}

    // 1. Add built-in roles
    roles = append(roles, builtinRoles...)

    // 2. Add tenant-wide custom roles
    tenantRoles, _ := s.customRoles.FindMany(ctx, bson.M{
        "_id.tenant":  authInfo.Realm,
        "_id.orgUnit": "",
    }, 0, 0)
    for _, r := range tenantRoles {
        roles = append(roles, toProto(r))
    }

    // 3. Add org-unit specific custom roles (if orgUnit specified)
    if req.OrgUnit != "" {
        ouRoles, _ := s.customRoles.FindMany(ctx, bson.M{
            "_id.tenant":  authInfo.Realm,
            "_id.orgUnit": req.OrgUnit,
        }, 0, 0)
        for _, r := range ouRoles {
            roles = append(roles, toProto(r))
        }
    }

    return &pb.ListOrgUnitRolesResp{Roles: roles}, nil
}
```

---

## 5. Permission Evaluation

### 5.1 Integration with FDP-001

**All permission evaluation uses pre-compiled matchers from in-memory cache. No string parsing or regex compilation during request handling.**

```go
// pkg/gateway/permission.go (extension of FDP-001)

// checkCustomRolePermission evaluates permissions using ONLY in-memory data
// No database queries, no file I/O, no network calls
func (p *PermissionChecker) checkCustomRolePermission(
    tenant, orgUnit, roleName, resource, verb string,
) bool {
    // Resolve role from CACHE ONLY (not database)
    compiledRole, err := p.resolveRole(tenant, orgUnit, roleName)
    if err != nil {
        return false // Not in cache, fall back to built-in
    }

    // Evaluate using pre-compiled matchers (O(n) where n = number of permissions)
    return p.evaluateCompiledPermissions(compiledRole.permissionRules, resource, verb)
}

func (p *PermissionChecker) evaluatePermissions(
    perms []RolePermission,
    resource, verb string,
) bool {
    // First pass: Check for explicit DENY
    for _, perm := range perms {
        if perm.Action == "deny" && p.matchesPermission(perm, resource, verb) {
            return false // Denied
        }
    }

    // Second pass: Check for ALLOW
    for _, perm := range perms {
        if (perm.Action == "" || perm.Action == "allow") && p.matchesPermission(perm, resource, verb) {
            return true // Allowed
        }
    }

    return false // No matching permission
}

func (p *PermissionChecker) matchesPermission(perm RolePermission, resource, verb string) bool {
    // Match resource
    if !p.matchResource(perm.Resource, perm.Match, resource) {
        return false
    }

    // Match verb
    if !slices.Contains(perm.Verbs, verb) && !slices.Contains(perm.Verbs, "*") {
        return false
    }

    return true
}

func (p *PermissionChecker) matchResource(match *ResourceMatch, resource string) bool {
    if match == nil {
        return true // No constraint
    }

    switch match.Type {
    case "wildcard":
        return true
    case "specific":
        return match.Value == resource
    case "prefix":
        return strings.HasPrefix(resource, match.Value)
    case "suffix":
        return strings.HasSuffix(resource, match.Value)
    case "contains":
        return strings.Contains(resource, match.Value)
    default:
        return false
    }
}

func (p *PermissionChecker) matchScope(match *ScopeMatch, scope string) bool {
    if match == nil {
        return true // No constraint
    }

    switch match.Type {
    case "wildcard":
        return true
    case "specific":
        return match.Value == scope
    default:
        return false
    }
}

// NOTE: Regex matching is intentionally NOT supported.
// Re-evaluate if prefix/suffix/contains prove insufficient.
```

### 5.2 Deny Precedence

```
Permission Evaluation Order:
1. Check all DENY rules first
   → If any DENY matches: DENIED (stop)
2. Check all ALLOW rules
   → If any ALLOW matches: ALLOWED
3. No match: DENIED (default deny)
```

---

## 6. Caching Strategy

**Critical**: The cache is NOT a performance optimization - it is a **mandatory architectural requirement**. The request path MUST NOT query the database. All role lookups during AuthZ use this in-memory cache exclusively.

### 6.1 Role Definition Cache

```go
type RoleCache struct {
    cache sync.Map // key: "tenant:orgUnit:roleName" → *CompiledRole
}

// CompiledRole contains pre-compiled matchers for fast evaluation
type CompiledRole struct {
    role            *CustomRole
    permissionRules []*CompiledPermission  // Pre-compiled for fast matching
}

type CompiledPermission struct {
    resourceMatcher func(string) bool  // Pre-compiled matcher
    verbSet         map[string]bool    // Set for O(1) lookup
    action          string
}

// Get returns the cached role - NEVER queries database
// If role is not in cache, returns nil (request uses fallback behavior)
func (c *RoleCache) Get(tenant, orgUnit, name string) (*CompiledRole, bool) {
    key := fmt.Sprintf("%s:%s:%s", tenant, orgUnit, name)
    if v, ok := c.cache.Load(key); ok {
        return v.(*CompiledRole), true
    }
    // NOT FOUND IN CACHE - do NOT fetch from DB
    // Request will use built-in role fallback or deny
    return nil, false
}
```

### 6.2 Cache Population via Change Streams

The cache is populated and updated via MongoDB change streams running in a **background goroutine**. This is the ONLY path to update the cache - requests never trigger cache population.

```go
// WatchAndPopulate runs in background - NOT in request path
func (c *RoleCache) WatchAndPopulate(ctx context.Context, collection *mongo.Collection) {
    // Initial population on startup
    c.loadAllRoles(ctx, collection)

    // Watch for changes
    stream, _ := collection.Watch(ctx, mongo.Pipeline{})
    defer stream.Close(ctx)

    for stream.Next(ctx) {
        var event struct {
            OperationType string      `bson:"operationType"`
            FullDocument  *CustomRole `bson:"fullDocument"`
            DocumentKey   struct {
                ID CustomRoleKey `bson:"_id"`
            } `bson:"documentKey"`
        }
        stream.Decode(&event)

        key := fmt.Sprintf("%s:%s:%s",
            event.DocumentKey.ID.Tenant,
            event.DocumentKey.ID.OrgUnit,
            event.DocumentKey.ID.Name)

        switch event.OperationType {
        case "insert", "update", "replace":
            // Pre-compile and cache
            compiled := c.compileRole(event.FullDocument)
            c.cache.Store(key, compiled)
        case "delete":
            c.cache.Delete(key)
        }
    }
}

func (c *RoleCache) compileRole(role *CustomRole) *CompiledRole {
    compiled := &CompiledRole{role: role}
    for _, perm := range role.Permissions {
        compiled.permissionRules = append(compiled.permissionRules, &CompiledPermission{
            resourceMatcher: compileResourceMatcher(perm.Resource, perm.Match),
            verbSet:         toSet(perm.Verbs),
            action:          perm.Action,
        })
    }
    return compiled
}
```

**Behavior when role not in cache**: If a request references a custom role that isn't cached (e.g., just created, cache not yet updated), the authorization falls back to built-in role evaluation. This brief window of eventual consistency is acceptable - the alternative (synchronous DB query) is not.
```

---

## 7. Authorization for Role Management

### 7.1 Who Can Manage Roles

| Action | Tenant-Wide Roles | Org-Unit Roles |
|--------|-------------------|----------------|
| Create | Tenant admin | Tenant admin or OU admin |
| Update | Tenant admin | Tenant admin or OU admin |
| Delete | Tenant admin | Tenant admin or OU admin |
| View   | Any authenticated user | Any OU member |

### 7.2 Implementation

```go
func (s *Server) canManageRoles(authInfo *auth.AuthInfo, orgUnit string) bool {
    // Tenant admins can manage all roles
    if slices.Contains(authInfo.Roles, "admin") {
        return true
    }

    // For org-unit roles, check if user is OU admin
    if orgUnit != "" {
        ouUser, err := s.orgUnitUsers.Get(ctx, OrgUnitUserKey{
            Tenant:   authInfo.Realm,
            OrgUnit:  orgUnit,
            Username: authInfo.UserName,
        })
        if err == nil && ouUser.Role == "admin" {
            return true
        }
    }

    return false
}
```

---

## 8. Migration Path

### 8.1 Existing Role Assignments

Current `OrgUnitUser.Role` field stores role names as strings. This continues to work:
- Built-in roles: "admin", "auditor", "default"
- Custom roles: "workflow-operator", "model-admin", etc.

No migration needed for existing data.

### 8.2 Pre-defined Tenant Roles

Optionally seed commonly useful roles on tenant creation:

```go
func (s *Server) seedDefaultRoles(ctx context.Context, tenant string) error {
    defaultRoles := []*CustomRole{
        {
            Key: CustomRoleKey{Tenant: tenant, OrgUnit: "", Name: "viewer"},
            DisplayName: "Viewer",
            Description: "Read-only access to all resources",
            Permissions: []RolePermission{
                {Resource: "*", Verbs: []string{"list", "get"}, Action: "allow"},
            },
            IsSystem: true,
        },
        {
            Key: CustomRoleKey{Tenant: tenant, OrgUnit: "", Name: "operator"},
            DisplayName: "Operator",
            Description: "Can execute but not modify resources",
            Permissions: []RolePermission{
                {Resource: "*", Verbs: []string{"list", "get", "execute"}, Action: "allow"},
            },
            IsSystem: true,
        },
    }

    for _, role := range defaultRoles {
        s.customRoles.Create(ctx, role)
    }
    return nil
}
```

---

## 9. Implementation Tasks

| Task ID | Description | Effort | Dependencies |
|---------|-------------|--------|--------------|
| FDP-002-T1 | Create custom-roles MongoDB collection and table | S | None |
| FDP-002-T2 | Implement CreateCustomRole handler | M | T1 |
| FDP-002-T3 | Implement UpdateCustomRole handler | S | T1 |
| FDP-002-T4 | Implement GetCustomRole handler | XS | T1 |
| FDP-002-T5 | Implement DeleteCustomRole handler | S | T1 |
| FDP-002-T6 | Enhance ListOrgUnitRoles to include custom roles | S | T1 |
| FDP-002-T7 | Implement permission validation against resource registry | M | T2, FDP-001 |
| FDP-002-T8 | Integrate custom role evaluation in PermissionChecker | M | T7, FDP-001 |
| FDP-002-T9 | Implement role definition cache | M | T8 |
| FDP-002-T10 | Add role management authorization checks | S | T2-T5 |
| FDP-002-T11 | Write unit and integration tests | M | T8 |

---

## 10. Open Questions

| Question | Status | Answer |
|----------|--------|--------|
| Should we limit number of custom roles per tenant/org-unit? | PROPOSED | Yes, 100 per tenant (OP-006) |
| Should deleted roles be soft-deleted for audit? | PROPOSED | Yes, 90-day retention (OP-007) |
| Support role inheritance (role A includes role B)? | DEFERRED | Out of scope, consider future phase |
| Support regex matching for resources? | DEFERRED | No. Prefix/suffix/contains covers most cases (OP-019) |

## 10.1 Match Criteria Summary

**Scope Matching (Simple):**
| Type | Pattern | Matches |
|------|---------|---------|
| specific | `"engineering"` | Exact match only |
| wildcard | `"*"` | All scopes |

**Resource Matching (Flexible):**
| Type | Pattern | Matches |
|------|---------|---------|
| specific | `"my-workflow"` | Exact match only |
| wildcard | `"*"` | All resources |
| prefix | `"abc-*"` → `"abc-"` | Starts with `abc-` |
| suffix | `"*-prod"` → `"-prod"` | Ends with `-prod` |
| contains | `"*test*"` → `"test"` | Contains `test` |

**DEFERRED:** Regex matching - not implemented. Re-evaluate if patterns above prove insufficient.

---

## 11. References

- [FDP-001: Resource-Verb Authorization](./FDP-001-resource-verb-authorization.md)
- [Org Unit Role Proto](https://github.com/go-core-stack/auth-gateway/blob/main/api/org-unit-role.proto)
