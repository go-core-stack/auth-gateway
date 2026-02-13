# FDP-004: Built-in Role Permission Definitions

## Metadata
- **ID**: FDP-004
- **Title**: Explicit Permission Definitions for Built-in Roles
- **Epic**: EPIC-001 (Fine-Grained RBAC Enhancement)
- **Author**: Engineering Head
- **Created**: 2026-02-10
- **Status**: Draft
- **Reviewers**: TBD
- **Dependencies**: FDP-001 (Resource-Verb Authorization)

---

## 1. Overview

### 1.1 Problem

Built-in roles (admin, auditor, default) have hardcoded behavior in gateway code:

```go
// Current implementation (pkg/gateway/server.go:282-293)
func (s *gateway) performOrgUnitRoleCheck(authInfo, ou string, r *http.Request) bool {
    ouUser, err := s.ouUserTbl.Find(r.Context(), ouUserKey)
    if err != nil {
        return false
    }
    switch ouUser.Role {
    case "admin":
        return true  // Wildcard access to the org unit
    case "auditor":
        if r.Method == http.MethodGet || r.Method == http.MethodHead {
            return true  // Allow read-only access
        }
        return false
    }
    return false  // "default" role falls through to deny-all
}
```

**Current "default" role behavior**: The switch statement has no case for "default", so it falls through to `return false` at line 293. This means users assigned the "default" role have **no permissions whatsoever** - they cannot access any org-unit scoped resources.

This approach:
- Doesn't integrate with resource-verb authorization
- Makes "default" role useless (always denied at line 293)
- Cannot be customized per deployment
- Isn't visible to users/administrators

### 1.2 Proposal

Define built-in roles with explicit permissions that:
- Integrate with the permission evaluation system (FDP-001)
- Are configurable via YAML
- Can serve as templates for custom roles
- Are visible in the role listing API

### 1.3 Critical Constraint: Zero Latency Impact

**Built-in role evaluation MUST remain the fastest authorization path.** Per EPIC-001 architectural constraints:

| Requirement | Implementation |
|-------------|----------------|
| Startup compilation | Built-in roles are parsed and compiled at gateway startup |
| In-memory evaluation | `evaluateRole()` uses pre-compiled matchers, no I/O |
| Static during runtime | Built-in roles don't change without gateway restart |
| No config reload overhead | Unlike custom roles, these are compiled once at startup |

```
Startup Path:
  Gateway Start → Parse builtin-roles.yaml → Compile Matchers → Store In-Memory

Request Path (FASTEST PATH - NO CACHE LOOKUP):
  AuthZ → evaluateRole(compiled matchers) → Allow/Deny

Built-in roles are the BASELINE for performance. Custom role evaluation
(FDP-002) may have cache lookup overhead, but built-in roles do not.
```

---

## 2. Design

### 2.1 Built-in Role Configuration (Scope-Aware)

```yaml
# default.yaml (or /etc/auth-gateway/builtin-roles.yaml)

builtinRoles:
  # ============================================================
  # GLOBAL SCOPE ROLES (Root Tenancy Only)
  # NOTE: Empty/omitted scope = global (implicit)
  # ============================================================

  root-admin:
    displayName: "Super Administrator"
    description: "Full access to all global resources (root tenant only)"
    # scope: ""                        # Empty = global (implicit, omit in config)
    permissions:
      - resource: "*"
        # resourceScope: ""            # Empty = global resources
        verbs: ["*"]
        action: "allow"
      - resource: "*"
        resourceScope: "tenant"        # Can also manage tenant resources
        verbs: ["*"]
        action: "allow"

  # ============================================================
  # TENANT SCOPE ROLES
  # ============================================================

  tenant-admin:
    displayName: "Tenant Administrator"
    description: "Full access to all resources within the tenant"
    scope: "tenant"
    permissions:
      - resource: "*"
        resourceScope: "tenant"
        verbs: ["*"]
        action: "allow"
      - resource: "*"
        resourceScope: "org-unit"      # Can manage all org-units
        verbs: ["*"]
        action: "allow"

  # ============================================================
  # ORG-UNIT SCOPE ROLES
  # ============================================================

  admin:
    displayName: "Org-Unit Administrator"
    description: "Full access to all resources within the org-unit"
    scope: "org-unit"
    permissions:
      - resource: "*"
        resourceScope: "org-unit"
        verbs: ["*"]
        action: "allow"

  auditor:
    displayName: "Auditor"
    description: "Read-only access to all resources for compliance and review"
    scope: "org-unit"
    permissions:
      - resource: "*"
        resourceScope: "org-unit"
        verbs: ["list", "get", "export"]
        action: "allow"

  member:
    displayName: "Member"
    description: "Standard member with basic access"
    scope: "org-unit"
    permissions:
      - resource: "org-unit"
        verbs: ["get"]
        action: "allow"
      - resource: "*"
        resourceScope: "org-unit"
        verbs: ["list"]
        action: "allow"

  # Legacy alias for backward compatibility
  default:
    displayName: "Member"
    description: "Alias for 'member' role (deprecated)"
    scope: "org-unit"
    aliasOf: "member"                  # NEW: Role aliasing
```

### 2.1.1 Role Scope Hierarchy

| Role | Scope Config | Can Manage |
|------|--------------|------------|
| root-admin | `""` (empty/omitted) | Global + Tenant + Org-Unit resources |
| tenant-admin | `scope: "tenant"` | Tenant + Org-Unit resources (within tenant) |
| admin | `scope: "org-unit"` | Org-Unit resources (within specific org-unit) |
| auditor | `scope: "org-unit"` | Read-only access to org-unit resources |
| member | `scope: "org-unit"` | List access to org-unit resources |

**Convention**: Global scope is implicit (empty/omitted). Only `tenant` and `org-unit` are explicitly specified.

### 2.2 Schema

```go
// pkg/config/builtin_roles.go

type BuiltinRolesConfig struct {
    Roles map[string]BuiltinRoleConfig `yaml:"builtinRoles"`
}

type BuiltinRoleConfig struct {
    DisplayName string           `yaml:"displayName"`
    Description string           `yaml:"description"`
    Scope       string           `yaml:"scope,omitempty"`   // "" = global (implicit), "tenant", "org-unit"
    AliasOf     string           `yaml:"aliasOf,omitempty"` // For backward compatibility
    Permissions []PermissionDef  `yaml:"permissions"`
}

type PermissionDef struct {
    Resource      string   `yaml:"resource"`                // Resource type or "*"
    ResourceScope string   `yaml:"resourceScope,omitempty"` // "", "tenant", "org-unit"
    Verbs         []string `yaml:"verbs"`                   // Verb list or ["*"]
    Action        string   `yaml:"action"`                  // "allow" or "deny"

    // Match criteria for scope and resource constraints
    ScopeMatch    *ScopeMatch    `yaml:"scopeMatch,omitempty"`
    ResourceMatch *ResourceMatch `yaml:"resourceMatch,omitempty"`
}

// Scope matching: specific or wildcard only (simple)
type ScopeMatch struct {
    Type  string `yaml:"type"`            // "specific", "wildcard"
    Value string `yaml:"value,omitempty"` // For specific: exact value
}

// Resource matching: flexible patterns (NO REGEX)
type ResourceMatch struct {
    Type  string `yaml:"type"`            // "specific", "wildcard", "prefix", "suffix", "contains"
    Value string `yaml:"value,omitempty"` // Pattern value
}

// Compact pattern syntax supported in YAML:
// scope: "*"              → wildcard
// scope: "engineering"    → specific
// match: "*"              → wildcard
// match: "abc-*"          → prefix
// match: "*-prod"         → suffix
// match: "*test*"         → contains
// match: "exact-name"     → specific
```

### 2.3 Integration with Permission Checker

```go
// pkg/gateway/permission.go

type PermissionChecker struct {
    builtinRoles  map[string]*CompiledRole
    customRoles   *table.CustomRoleTable
    orgUnitUsers  *table.OrgUnitUserTable
    cache         *PermissionCache
}

type CompiledRole struct {
    Name        string
    DisplayName string
    Description string
    Permissions []*CompiledPermission
}

type CompiledPermission struct {
    ResourceMatcher func(string) bool
    VerbMatcher     func(string) bool
    Action          string // "allow" or "deny"
}

func NewPermissionChecker(cfg *config.Config, ...) *PermissionChecker {
    p := &PermissionChecker{
        builtinRoles: make(map[string]*CompiledRole),
        // ...
    }

    // Compile built-in roles from config
    for name, roleCfg := range cfg.BuiltinRoles.Roles {
        p.builtinRoles[name] = p.compileRole(name, &roleCfg)
    }

    return p
}

func (p *PermissionChecker) compileRole(name string, cfg *BuiltinRoleConfig) *CompiledRole {
    role := &CompiledRole{
        Name:        name,
        DisplayName: cfg.DisplayName,
        Description: cfg.Description,
    }

    for _, perm := range cfg.Permissions {
        compiled := &CompiledPermission{
            ResourceMatcher: p.createResourceMatcher(perm.Resource, perm.ResourceMatch),
            VerbMatcher:     p.createVerbMatcher(perm.Verbs),
            Action:          perm.Action,
        }
        role.Permissions = append(role.Permissions, compiled)
    }

    return role
}

func (p *PermissionChecker) createResourceMatcher(resource string, match *ResourceMatch) func(string) bool {
    if resource == "*" {
        return func(string) bool { return true }
    }

    if match == nil || match.Type == "" || match.Type == "specific" {
        return func(r string) bool { return r == resource }
    }

    switch match.Type {
    case "wildcard":
        return func(string) bool { return true }
    case "prefix":
        return func(r string) bool { return strings.HasPrefix(r, match.Value) }
    case "suffix":
        return func(r string) bool { return strings.HasSuffix(r, match.Value) }
    case "contains":
        return func(r string) bool { return strings.Contains(r, match.Value) }
    // NOTE: Regex matching is intentionally NOT supported.
    // Re-evaluate if prefix/suffix/contains prove insufficient.
    default:
        return func(r string) bool { return r == resource }
    }
}

func (p *PermissionChecker) createVerbMatcher(verbs []string) func(string) bool {
    if len(verbs) == 1 && verbs[0] == "*" {
        return func(string) bool { return true }
    }

    verbSet := make(map[string]bool)
    for _, v := range verbs {
        verbSet[v] = true
    }
    return func(v string) bool { return verbSet[v] }
}
```

### 2.4 Permission Evaluation

```go
func (p *PermissionChecker) CheckPermission(
    ctx context.Context,
    authInfo *auth.AuthInfo,
    orgUnit, resource, verb string,
) error {
    // Get user's role in this org-unit
    ouUser, err := p.orgUnitUsers.Get(ctx, OrgUnitUserKey{
        Tenant:   authInfo.Realm,
        OrgUnit:  orgUnit,
        Username: authInfo.UserName,
    })
    if err != nil {
        return errors.Forbidden
    }

    // Check if it's a built-in role
    if builtinRole, ok := p.builtinRoles[ouUser.Role]; ok {
        if p.evaluateRole(builtinRole, resource, verb) {
            return nil
        }
        return errors.Forbidden
    }

    // Check custom roles (FDP-002)
    return p.checkCustomRole(ctx, authInfo.Realm, orgUnit, ouUser.Role, resource, verb)
}

func (p *PermissionChecker) evaluateRole(role *CompiledRole, resource, verb string) bool {
    // First pass: Check for explicit DENY
    for _, perm := range role.Permissions {
        if perm.Action == "deny" {
            if perm.ResourceMatcher(resource) && perm.VerbMatcher(verb) {
                return false
            }
        }
    }

    // Second pass: Check for ALLOW
    for _, perm := range role.Permissions {
        if perm.Action == "allow" || perm.Action == "" {
            if perm.ResourceMatcher(resource) && perm.VerbMatcher(verb) {
                return true
            }
        }
    }

    return false // Default deny
}
```

---

## 3. Default Permission Sets

### 3.1 Admin Role

```yaml
admin:
  displayName: "Administrator"
  description: "Full access to all resources within the org-unit"
  permissions:
    - resource: "*"
      verbs: ["*"]
      action: "allow"
```

**Behavior**: Allow all resources, all verbs.

### 3.2 Auditor Role

```yaml
auditor:
  displayName: "Auditor"
  description: "Read-only access for compliance and review"
  permissions:
    - resource: "*"
      verbs: ["list", "get", "export"]
      action: "allow"
```

**Behavior**: Allow read operations on all resources.

### 3.3 Default (Member) Role

```yaml
default:
  displayName: "Member"
  description: "Standard member with basic access"
  permissions:
    # View org-unit info
    - resource: "org-unit"
      verbs: ["get"]
      action: "allow"
    # List resources
    - resource: "*"
      verbs: ["list"]
      action: "allow"
    # View own profile
    - resource: "user"
      verbs: ["get"]
      match:
        criteria: "self"  # Special: only own user
      action: "allow"
```

**Behavior**: Can list resources and view org-unit details.

---

## 4. Role Visibility in API

### 4.1 Enhanced ListOrgUnitRoles

```go
func (s *Server) ListOrgUnitRoles(ctx context.Context, req *pb.ListOrgUnitRolesReq) (*pb.ListOrgUnitRolesResp, error) {
    roles := []*pb.OrgUnitRoleInfo{}

    // Add built-in roles with full details
    for name, role := range s.permChecker.builtinRoles {
        roles = append(roles, &pb.OrgUnitRoleInfo{
            Name:        name,
            DisplayName: role.DisplayName,
            Description: role.Description,
            IsBuiltin:   true,
            Permissions: toProtoPermissions(role.Permissions),
        })
    }

    // Add custom roles...
    // (from FDP-002)

    return &pb.ListOrgUnitRolesResp{Roles: roles}, nil
}
```

### 4.2 Proto Update

```protobuf
message OrgUnitRoleInfo {
    string name = 1;
    string display_name = 2;
    string description = 3;
    bool is_builtin = 4;                     // NEW
    bool is_system = 5;                      // Cannot be deleted
    repeated RolePermission permissions = 6; // NEW: Show permissions
}
```

---

## 5. Customization Scenarios

### 5.1 Restrictive Default Role

Organization wants members to have no access by default:

```yaml
builtinRoles:
  default:
    displayName: "Member"
    description: "No default permissions - must be granted explicitly"
    permissions: []  # Empty = deny all
```

### 5.2 Expanded Auditor Role

Auditors need to run reports:

```yaml
builtinRoles:
  auditor:
    displayName: "Auditor"
    description: "Read-only access with reporting capabilities"
    permissions:
      - resource: "*"
        verbs: ["list", "get"]
        action: "allow"
      - resource: "report"
        verbs: ["list", "get", "generate"]
        action: "allow"
```

### 5.3 Admin with Restrictions

Admins cannot delete certain resources:

```yaml
builtinRoles:
  admin:
    displayName: "Administrator"
    description: "Full access except permanent deletions"
    permissions:
      - resource: "audit-log"
        verbs: ["delete"]
        action: "deny"  # Cannot delete audit logs
      - resource: "*"
        verbs: ["*"]
        action: "allow"
```

---

## 6. Validation

### 6.1 Startup Validation

```go
func (p *PermissionChecker) validateBuiltinRoles() error {
    required := []string{"admin", "auditor", "default"}

    for _, name := range required {
        if _, ok := p.builtinRoles[name]; !ok {
            return fmt.Errorf("missing required built-in role: %s", name)
        }
    }

    // Validate admin has full access
    adminRole := p.builtinRoles["admin"]
    if !p.evaluateRole(adminRole, "any-resource", "any-verb") {
        log.Warn("admin role does not have full access - this may be intentional")
    }

    return nil
}
```

### 6.2 Permission Syntax Validation

```go
func validatePermissionDef(perm *PermissionDef) error {
    if perm.Resource == "" {
        return errors.New("resource is required")
    }

    if len(perm.Verbs) == 0 {
        return errors.New("at least one verb is required")
    }

    if perm.Action != "" && perm.Action != "allow" && perm.Action != "deny" {
        return fmt.Errorf("invalid action: %s", perm.Action)
    }

    if perm.ScopeMatch != nil {
        validTypes := []string{"specific", "wildcard"}
        if !slices.Contains(validTypes, perm.ScopeMatch.Type) {
            return fmt.Errorf("invalid scope match type: %s", perm.ScopeMatch.Type)
        }
    }

    if perm.ResourceMatch != nil {
        validTypes := []string{"specific", "wildcard", "prefix", "suffix", "contains"}
        if !slices.Contains(validTypes, perm.ResourceMatch.Type) {
            return fmt.Errorf("invalid resource match type: %s (regex is not supported)", perm.ResourceMatch.Type)
        }
    }

    return nil
}
```

---

## 7. Migration

### 7.1 Backward Compatibility

If no `builtinRoles` configuration is provided, use hardcoded defaults that match current behavior:

```go
func defaultBuiltinRoles() map[string]*CompiledRole {
    return map[string]*CompiledRole{
        "admin": {
            Name: "admin",
            Permissions: []*CompiledPermission{
                {
                    ResourceMatcher: func(string) bool { return true },
                    VerbMatcher:     func(string) bool { return true },
                    Action:          "allow",
                },
            },
        },
        "auditor": {
            Name: "auditor",
            Permissions: []*CompiledPermission{
                {
                    ResourceMatcher: func(string) bool { return true },
                    VerbMatcher: func(v string) bool {
                        return v == "list" || v == "get"
                    },
                    Action: "allow",
                },
            },
        },
        "default": {
            Name:        "default",
            Permissions: []*CompiledPermission{}, // Empty = deny all
            // This matches current behavior where "default" role falls through
            // to return false in performOrgUnitRoleCheck (server.go:293)
        },
    }
}
```

---

## 8. Implementation Tasks

| Task ID | Description | Effort | Dependencies |
|---------|-------------|--------|--------------|
| FDP-004-T1 | Define BuiltinRolesConfig schema | S | None |
| FDP-004-T2 | Add builtinRoles section to default.yaml | XS | T1 |
| FDP-004-T3 | Implement role compilation | M | T1, FDP-001 |
| FDP-004-T4 | Integrate with PermissionChecker | M | T3, FDP-001 |
| FDP-004-T5 | Add validation at startup | S | T3 |
| FDP-004-T6 | Enhance ListOrgUnitRoles API | S | T3 |
| FDP-004-T7 | Add default fallback for missing config | S | T3 |
| FDP-004-T8 | Document customization options | M | T3 |
| FDP-004-T9 | Write unit tests | M | T4 |

---

## 9. Open Questions

| Question | Status | Answer |
|----------|--------|--------|
| Allow removing built-in roles entirely? | DECIDED | No - they're required as fallback |
| Support role inheritance (auditor extends default)? | DEFERRED | Future phase consideration |
| Per-tenant built-in role overrides? | DEFERRED | Consider for enterprise tier (OP-011) |
| Support regex matching in built-in roles? | DECIDED | No. Prefix/suffix/contains is sufficient (OP-019) |
| Support deny permissions? | DECIDED | Yes. Deny evaluated before allow (OP-005) |

## 9.1 Match Criteria for Built-in Roles

Built-in roles support the same match criteria as custom roles:

**Scope Matching:**
- `specific`: Exact org-unit match
- `wildcard`: All org-units (`"*"`)

**Resource Matching:**
- `specific`: Exact resource name
- `wildcard`: All resources (`"*"`)
- `prefix`: Starts with pattern (`"abc-*"`)
- `suffix`: Ends with pattern (`"*-prod"`)
- `contains`: Contains pattern (`"*test*"`)

**NOT SUPPORTED:** Regex matching (intentionally deferred).

---

## 10. References

- [FDP-001: Resource-Verb Authorization](./FDP-001-resource-verb-authorization.md)
- [FDP-002: Custom Roles](./FDP-002-custom-roles.md)
