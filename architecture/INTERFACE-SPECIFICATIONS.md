# RBAC Interface Specifications

## Overview

This document details the interface changes required to implement the Fine-Grained RBAC Enhancement epic. It covers:
1. API changes (new and updated endpoints)
2. Database schema changes
3. Configuration schema changes
4. Auth context headers (gateway-to-backend)

---

## 1. API Specifications

### 1.1 New APIs

#### 1.1.1 Custom Role Management

**Service**: `OrgUnitRole` (existing service, new implementations)

```protobuf
// api/org-unit-role.proto

service OrgUnitRole {
    // Existing - Enhanced
    rpc ListOrgUnitRoles(ListOrgUnitRolesReq) returns (ListOrgUnitRolesResp);

    // New Implementations (currently stubs)
    rpc CreateCustomRole(CreateCustomRoleReq) returns (CustomRoleInfo);
    rpc GetCustomRole(GetCustomRoleReq) returns (CustomRoleInfo);
    rpc UpdateCustomRole(UpdateCustomRoleReq) returns (CustomRoleInfo);
    rpc DeleteCustomRole(DeleteCustomRoleReq) returns (google.protobuf.Empty);

    // New APIs
    rpc ListCustomRoles(ListCustomRolesReq) returns (ListCustomRolesResp);
    rpc ValidatePermissions(ValidatePermissionsReq) returns (ValidatePermissionsResp);
}

// ============================================================
// Request/Response Messages
// ============================================================

message CreateCustomRoleReq {
    string org_unit = 1;              // Empty = tenant-wide role
    string name = 2;                   // Role name (unique within scope)
    string display_name = 3;
    string description = 4;
    repeated RolePermission permissions = 5;
}

message GetCustomRoleReq {
    string org_unit = 1;              // Empty = tenant-wide role
    string name = 2;
}

message UpdateCustomRoleReq {
    string org_unit = 1;
    string name = 2;
    string display_name = 3;
    string description = 4;
    repeated RolePermission permissions = 5;
}

message DeleteCustomRoleReq {
    string org_unit = 1;
    string name = 2;
}

message ListCustomRolesReq {
    string org_unit = 1;              // Empty = list tenant-wide roles
    bool include_tenant_roles = 2;    // Include tenant-wide roles when listing org-unit
}

message ListCustomRolesResp {
    repeated CustomRoleInfo roles = 1;
}

message ValidatePermissionsReq {
    repeated RolePermission permissions = 1;
}

message ValidatePermissionsResp {
    bool valid = 1;
    repeated ValidationError errors = 2;
}

message ValidationError {
    int32 index = 1;                  // Permission index
    string field = 2;                 // Field with error
    string message = 3;               // Error message
}

// ============================================================
// Core Messages
// ============================================================

message CustomRoleInfo {
    string tenant = 1;
    string org_unit = 2;              // Empty = tenant-wide
    string name = 3;
    string display_name = 4;
    string description = 5;
    repeated RolePermission permissions = 6;
    bool is_system = 7;               // Cannot be deleted
    int64 created_at = 8;
    string created_by = 9;
    int64 updated_at = 10;
    string updated_by = 11;
}

message RolePermission {
    string resource = 1;              // Resource name or "*"
    string resource_scope = 2;        // "" = global, "tenant", "org-unit"
    repeated string verbs = 3;        // Verb list or ["*"]
    RolePermissionAction action = 4;  // ALLOW or DENY
    ResourceMatch match = 5;          // Optional matching criteria
}

enum RolePermissionAction {
    DENY = 0;                         // Deny takes precedence over Allow
    ALLOW = 1;
    LOG = 2;                          // Allow access but log for audit
}

message ResourceMatch {
    MatchCriteria criteria = 1;
    string pattern = 2;
}

enum MatchCriteria {
    EXACT = 0;
    PREFIX = 1;
    SUFFIX = 2;
    CONTAINS = 3;
    // REGEX intentionally not supported. Re-evaluate if patterns above prove insufficient.
}
```

#### 1.1.2 Resource Registry API

**Service**: `ResourceRegistry` (new service)

```protobuf
// api/resource-registry.proto

service ResourceRegistry {
    // List all registered resources
    rpc ListResources(ListResourcesReq) returns (ListResourcesResp);

    // Get resource definition
    rpc GetResource(GetResourceReq) returns (ResourceInfo);

    // List resources by scope
    rpc ListResourcesByScope(ListResourcesByScopeReq) returns (ListResourcesResp);
}

message ListResourcesReq {
    bool include_root_resources = 1;  // Include global resources (root tenant only)
}

message ListResourcesResp {
    repeated ResourceInfo resources = 1;
}

message GetResourceReq {
    string name = 1;
}

message ListResourcesByScopeReq {
    string scope = 1;                 // "" = global, "tenant", "org-unit"
}

message ResourceInfo {
    string name = 1;
    string display_name = 2;
    string description = 3;
    string category = 4;
    string scope = 5;                 // "" = global, "tenant", "org-unit"
    string default_access = 6;        // "root-admin", "tenant-admin", or empty
    repeated string verbs = 7;
    string source = 8;                // Route source (e.g., "ai-gateway", "auth-gateway")
}
```

#### 1.1.3 Permission Check API (Internal)

**Service**: `PermissionChecker` (new internal service)

```protobuf
// api/internal/permission.proto

service PermissionChecker {
    // Check if user has permission (for debugging/testing)
    rpc CheckPermission(CheckPermissionReq) returns (CheckPermissionResp);

    // Get effective permissions for user in org-unit
    rpc GetEffectivePermissions(GetEffectivePermissionsReq) returns (GetEffectivePermissionsResp);
}

message CheckPermissionReq {
    string tenant = 1;
    string username = 2;
    string org_unit = 3;
    string resource = 4;
    string verb = 5;
}

message CheckPermissionResp {
    bool allowed = 1;
    string reason = 2;                // "builtin_role", "custom_role", "tenant_admin", "denied"
    string role = 3;                  // Role that granted/denied access
}

message GetEffectivePermissionsReq {
    string tenant = 1;
    string username = 2;
    string org_unit = 3;
}

message GetEffectivePermissionsResp {
    string role = 1;
    bool is_tenant_admin = 2;
    repeated EffectivePermission permissions = 3;
}

message EffectivePermission {
    string resource = 1;
    repeated string allowed_verbs = 2;
    repeated string denied_verbs = 3;
    string source = 4;                // "builtin" or "custom"
}
```

### 1.2 Updated APIs

#### 1.2.1 ListOrgUnitRoles (Enhanced)

```protobuf
// Existing message - Enhanced
message ListOrgUnitRolesReq {
    string org_unit = 1;
    bool exclude_builtin = 2;         // NEW: Exclude built-in roles (default false = include all)
    bool exclude_custom = 3;          // NEW: Exclude custom roles (default false = include all)
    bool include_tenant_roles = 4;    // NEW: Include tenant-wide custom roles
}

message ListOrgUnitRolesResp {
    repeated OrgUnitRoleInfo roles = 1;
}

// Enhanced response
message OrgUnitRoleInfo {
    string name = 1;
    string display_name = 2;
    string description = 3;
    bool is_builtin = 4;              // NEW: true for admin/auditor/member
    bool is_system = 5;               // NEW: Cannot be deleted
    string scope = 6;                 // NEW: "" = global, "tenant", "org-unit"
    repeated RolePermission permissions = 7;  // NEW: Show permissions
}
```

#### 1.2.2 Route Registration (Internal)

```protobuf
// api/internal/route.proto

message RouteInfo {
    string url = 1;
    string method = 2;
    string endpoint = 3;

    // Existing fields
    bool is_public = 4;
    bool is_root = 5;
    bool is_user_specific = 6;

    // Enhanced fields
    string group = 7;
    string resource = 8;              // Resource name
    string verb = 9;                  // Action verb
    ScopeDefinition scope = 10;       // Structured scope definition
    ResourceIdentifier resource_identifier = 11; // For constraint matching in URL
    string source = 12;               // "auth-gateway", "ai-gateway", etc.
}

message ScopeDefinition {
    string type = 1;                  // "", "tenant", "org-unit"
    string path_param = 2;           // URL param: "ou"
    int32 path_position = 3;         // Position in URL (0-indexed)
}

message ResourceIdentifier {
    string path_param = 1;           // "name", "id"
    int32 path_position = 2;         // Position in URL (0-indexed)
    string field = 3;               // Constraint field (default: "name")
}
```

---

## 2. Database Schema

### 2.1 Routes Collection (Updated)

**Collection**: `routes`

```javascript
// Existing schema with additions
{
    "_id": {
        "url": "/api/v1/workflows/{ou}/{id}",
        "method": 1                    // enum: GET=1, POST=2, PUT=3, DELETE=4, etc.
    },
    "endpoint": "http://workflow-service:8080",

    // Access control flags
    "isPublic": false,
    "isRoot": false,
    "isUserSpecific": false,

    // RBAC fields (existing but now enforced)
    "group": "workflow",
    "resource": "workflow",
    "verb": "get",

    // Structured scope definition (replaces scopes []string)
    "scope": {
        "type": "org-unit",
        "pathParam": "ou",
        "pathPosition": 3
    },

    // Resource identifier (for constraint matching on GET/UPDATE/DELETE)
    "resourceIdentifier": {
        "pathParam": "id",
        "pathPosition": 4,
        "field": "name"
    },

    // NEW: Source tracking
    "source": "workflow-service",      // NEW: Origin of route registration

    // NEW: Timestamps for config-loaded routes
    "createdAt": ISODate("2026-02-10T00:00:00Z"),
    "updatedAt": ISODate("2026-02-10T00:00:00Z")
}

// Indexes
db.routes.createIndex({"_id.url": 1, "_id.method": 1}, {unique: true})
db.routes.createIndex({"resource": 1})
db.routes.createIndex({"scope.type": 1})
db.routes.createIndex({"source": 1})
```

### 2.2 Resources Collection (New)

**Collection**: `resources`

```javascript
// Resource registry compiled from routes
{
    "_id": "workflow",                 // Resource name
    "displayName": "Workflow",
    "description": "Workflow definitions and executions",
    "category": "automation",
    "scope": "org-unit",               // "" = global, "tenant", "org-unit"
    "defaultAccess": "",               // "root-admin", "tenant-admin", or empty
    "verbs": ["list", "get", "create", "update", "delete", "execute"],
    "source": "workflow-service",
    "updatedAt": ISODate("2026-02-10T00:00:00Z")
}

// Indexes
db.resources.createIndex({"scope": 1})
db.resources.createIndex({"source": 1})
db.resources.createIndex({"category": 1})
```

### 2.3 Custom Roles Collection (New)

**Collection**: `custom-roles`

```javascript
{
    "_id": {
        "tenant": "acme-corp",
        "orgUnit": "",                 // Empty = tenant-wide role
        "name": "workflow-operator"
    },
    "displayName": "Workflow Operator",
    "description": "Can view and execute workflows, but not create or delete",
    "permissions": [
        {
            "resource": "workflow",
            "resourceScope": "org-unit",
            "verbs": ["list", "get", "execute"],
            "action": "allow"
        },
        {
            "resource": "workflow-run",
            "resourceScope": "org-unit",
            "verbs": ["list", "get"],
            "action": "allow"
        }
    ],
    "isSystem": false,
    "createdAt": ISODate("2026-02-10T00:00:00Z"),
    "createdBy": "admin@acme-corp.com",
    "updatedAt": ISODate("2026-02-10T00:00:00Z"),
    "updatedBy": "admin@acme-corp.com",

    // Soft delete support
    "deletedAt": null,
    "deletedBy": null
}

// Indexes
db["custom-roles"].createIndex({"_id.tenant": 1, "_id.name": 1}, {unique: true})
db["custom-roles"].createIndex({"_id.tenant": 1, "_id.orgUnit": 1})
db["custom-roles"].createIndex({"deletedAt": 1})  // For cleanup queries
```

### 2.4 Org Unit Users Collection (Existing - No Changes)

**Collection**: `org-unit-users`

```javascript
// Existing schema - no changes needed
// Role field now supports custom role names
{
    "_id": {
        "tenant": "acme-corp",
        "orgUnit": "engineering",
        "username": "john.doe"
    },
    "role": "workflow-operator",       // Can be built-in or custom role name
    "createdAt": ISODate("2026-02-10T00:00:00Z"),
    "createdBy": "admin@acme-corp.com"
}
```

### 2.5 Schema Migration

```javascript
// Migration: Add source field to existing routes
db.routes.updateMany(
    { "source": { $exists: false } },
    { $set: { "source": "auth-gateway" } }
)

// Migration: Create resources collection from routes
db.routes.aggregate([
    { $match: { "resource": { $ne: "" } } },
    { $group: {
        _id: "$resource",
        verbs: { $addToSet: "$verb" },
        source: { $first: "$source" }
    }},
    { $project: {
        _id: 1,
        displayName: "$_id",
        description: "",
        category: "",
        scope: "org-unit",             // Default scope for existing resources
        defaultAccess: "",
        verbs: 1,
        source: 1,
        updatedAt: new Date()
    }},
    { $out: "resources" }
])
```

---

## 3. Configuration Schema

### 3.1 Main Configuration (default.yaml)

```yaml
# default.yaml - Auth Gateway Configuration

# ============================================================
# Existing Configuration (unchanged)
# ============================================================

configDB:
  uri: "mongodb://localhost:27017/auth-gateway"

keycloak:
  endpoint: "http://localhost:8080"

swagger:
  dir: "/opt/swagger"

cors:
  enabled: true

rateLimits:
  enabled: true
  defaultRPS: 200
  burstSize: 200
  cleanup:
    interval: 5m
    maxIdle: 10m

# ============================================================
# NEW: Authorization Configuration
# ============================================================

authorization:
  # Feature flags for gradual rollout
  enableResourceVerbCheck: true       # Enable resource-verb authorization
  dryRun: false                       # Log but don't enforce (for testing)
  logDeniedRequests: true             # Log denied authorization attempts

  # Cache settings
  cache:
    enabled: true
    ttl: 5m                           # Permission cache TTL
    maxSize: 10000                    # Max cached entries

  # Eventual consistency settings
  reconciliation:
    debounceInterval: 3s              # Debounce change stream events
    maxPropagationDelay: 10s          # Max acceptable delay

# ============================================================
# NEW: Route Configuration
# ============================================================

routes:
  # Files or directories to load
  files:
    - "/etc/auth-gateway/routes.d/*.yaml"
    - "./routes/*.yaml"               # For development

  # File watcher for hot reload
  watchEnabled: false                 # Enable in environments that need it
  watchInterval: 30s

  # Validation
  strictMode: true                    # Fail on invalid routes

# ============================================================
# NEW: Built-in Roles Configuration
# ============================================================

builtinRoles:
  # Global scope roles (root tenant only)
  root-admin:
    displayName: "Super Administrator"
    description: "Full access to all global resources"
    # scope: ""                       # Empty = global (implicit)
    permissions:
      - resource: "*"
        # resourceScope: ""           # Empty = global (implicit)
        verbs: ["*"]
        action: "allow"
      - resource: "*"
        resourceScope: "tenant"
        verbs: ["*"]
        action: "allow"
      - resource: "*"
        resourceScope: "org-unit"
        verbs: ["*"]
        action: "allow"

  # Tenant scope roles
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
        resourceScope: "org-unit"
        verbs: ["*"]
        action: "allow"

  # Org-unit scope roles
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
    description: "Read-only access for compliance and review"
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

  # Backward compatibility alias
  default:
    aliasOf: "member"

# ============================================================
# NEW: Role Mapping (Keycloak to Auth-Gateway)
# ============================================================

roleMapping:
  # Map Keycloak realm roles to auth-gateway roles
  keycloakRoles:
    admin: "tenant-admin"             # Keycloak 'admin' → tenant-admin
    # Add custom mappings as needed

# ============================================================
# NEW: Custom Roles Limits
# ============================================================

customRoles:
  maxPerTenant: 100                   # Maximum custom roles per tenant
  maxPermissionsPerRole: 50           # Maximum permissions per role
  softDeleteRetentionDays: 90         # Days to retain soft-deleted roles
```

### 3.2 Route Configuration Schema (routes.d/*.yaml)

```yaml
# /etc/auth-gateway/routes.d/ai-gateway.yaml

# Metadata
source: "ai-gateway"
version: "1.0.0"
description: "AI Gateway routes for model and provider management"

# Backend defaults
defaults:
  endpoint: "http://ai-gateway:8080"
  group: "ai"

# Resource definitions
resources:
  # Global scope (empty/omitted scope)
  - name: "provider"
    displayName: "AI Provider"
    description: "AI service providers (OpenAI, Anthropic, etc.)"
    category: "ai"
    # scope: ""                       # Empty = global (implicit)
    defaultAccess: "root-admin"
    verbs: ["list", "get", "create", "update", "delete", "test"]

  # Tenant scope
  - name: "model-config"
    displayName: "Model Configuration"
    description: "Tenant-level model configurations"
    category: "ai"
    scope: "tenant"
    defaultAccess: "tenant-admin"
    verbs: ["list", "get", "create", "update", "delete"]

  # Org-unit scope
  - name: "model"
    displayName: "AI Model"
    description: "LLM and embedding models"
    category: "ai"
    scope: "org-unit"
    verbs: ["list", "get", "create", "update", "delete", "invoke"]

  - name: "inference"
    displayName: "Inference Request"
    description: "Model inference requests"
    category: "ai"
    scope: "org-unit"
    verbs: ["create", "get", "list"]

# Route definitions
routes:
  # ============================================================
  # Global routes (root tenant only)
  # ============================================================
  - url: "/api/ai/v1/providers"
    method: GET
    resource: "provider"
    verb: "list"
    isRoot: true
    scope:
      type: "tenant"

  - url: "/api/ai/v1/providers"
    method: POST
    resource: "provider"
    verb: "create"
    isRoot: true
    scope:
      type: "tenant"

  - url: "/api/ai/v1/providers/{id}"
    method: GET
    resource: "provider"
    verb: "get"
    isRoot: true
    scope:
      type: "tenant"

  - url: "/api/ai/v1/providers/{id}"
    method: PUT
    resource: "provider"
    verb: "update"
    isRoot: true
    scope:
      type: "tenant"

  - url: "/api/ai/v1/providers/{id}"
    method: DELETE
    resource: "provider"
    verb: "delete"
    isRoot: true
    scope:
      type: "tenant"

  # ============================================================
  # Tenant routes
  # ============================================================
  - url: "/api/ai/v1/config/models"
    method: GET
    resource: "model-config"
    verb: "list"
    scope:
      type: "tenant"

  - url: "/api/ai/v1/config/models"
    method: POST
    resource: "model-config"
    verb: "create"
    scope:
      type: "tenant"

  # ============================================================
  # Org-unit routes
  # ============================================================
  - url: "/api/ai/v1/orgs/{ou}/models"
    method: GET
    resource: "model"
    verb: "list"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4

  - url: "/api/ai/v1/orgs/{ou}/models"
    method: POST
    resource: "model"
    verb: "create"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4

  - url: "/api/ai/v1/orgs/{ou}/models/{id}"
    method: GET
    resource: "model"
    verb: "get"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4
    resourceIdentifier:
      pathParam: "id"
      pathPosition: 6
      field: "name"

  - url: "/api/ai/v1/orgs/{ou}/models/{id}"
    method: PUT
    resource: "model"
    verb: "update"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4
    resourceIdentifier:
      pathParam: "id"
      pathPosition: 6

  - url: "/api/ai/v1/orgs/{ou}/models/{id}"
    method: DELETE
    resource: "model"
    verb: "delete"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4
    resourceIdentifier:
      pathParam: "id"
      pathPosition: 6

  - url: "/api/ai/v1/orgs/{ou}/models/{id}/invoke"
    method: POST
    resource: "model"
    verb: "invoke"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4
    resourceIdentifier:
      pathParam: "id"
      pathPosition: 6

  # ============================================================
  # Public routes
  # ============================================================
  - url: "/api/ai/v1/health"
    method: GET
    isPublic: true
```

### 3.3 Configuration Go Structs

```go
// pkg/config/config.go

package config

import "time"

// BaseConfig - Main configuration structure
type BaseConfig struct {
    ConfigDB        *MongoDB              `yaml:"configDB,omitempty"`
    Swagger         Swagger               `yaml:"swagger,omitempty"`
    Keycloak        *Keycloak             `yaml:"keycloak,omitempty"`
    Cors            CorsConfig            `yaml:"cors,omitempty"`
    RateLimits      RateLimitsConfig      `yaml:"rateLimits"`

    // NEW: RBAC Configuration
    Authorization   AuthorizationConfig   `yaml:"authorization"`
    Routes          RoutesConfig          `yaml:"routes"`
    BuiltinRoles    BuiltinRolesConfig    `yaml:"builtinRoles"`
    RoleMapping     RoleMappingConfig     `yaml:"roleMapping"`
    CustomRoles     CustomRolesConfig     `yaml:"customRoles"`
}

// AuthorizationConfig - Authorization settings
type AuthorizationConfig struct {
    EnableResourceVerbCheck bool              `yaml:"enableResourceVerbCheck"`
    DryRun                  bool              `yaml:"dryRun"`
    LogDeniedRequests       bool              `yaml:"logDeniedRequests"`
    Cache                   CacheConfig       `yaml:"cache"`
    Reconciliation          ReconcileConfig   `yaml:"reconciliation"`
}

type CacheConfig struct {
    Enabled bool          `yaml:"enabled"`
    TTL     time.Duration `yaml:"ttl"`
    MaxSize int           `yaml:"maxSize"`
}

type ReconcileConfig struct {
    DebounceInterval      time.Duration `yaml:"debounceInterval"`
    MaxPropagationDelay   time.Duration `yaml:"maxPropagationDelay"`
}

// RoutesConfig - Route loading configuration
type RoutesConfig struct {
    Files         []string      `yaml:"files,omitempty"`
    WatchEnabled  bool          `yaml:"watchEnabled,omitempty"`
    WatchInterval time.Duration `yaml:"watchInterval,omitempty"`
    StrictMode    bool          `yaml:"strictMode,omitempty"`
}

// BuiltinRolesConfig - Built-in role definitions
type BuiltinRolesConfig struct {
    Roles map[string]BuiltinRoleConfig `yaml:"builtinRoles,inline"`
}

type BuiltinRoleConfig struct {
    DisplayName string          `yaml:"displayName"`
    Description string          `yaml:"description"`
    Scope       string          `yaml:"scope,omitempty"`   // "" = global
    AliasOf     string          `yaml:"aliasOf,omitempty"`
    Permissions []PermissionDef `yaml:"permissions,omitempty"`
}

type PermissionDef struct {
    Resource      string         `yaml:"resource"`
    ResourceScope string         `yaml:"resourceScope,omitempty"` // "" = global
    Verbs         []string       `yaml:"verbs"`
    Action        string         `yaml:"action,omitempty"` // "allow" or "deny"
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
    Value string `yaml:"value,omitempty"` // Pattern value (without wildcards)
}

// RoleMappingConfig - Keycloak to auth-gateway role mapping
type RoleMappingConfig struct {
    KeycloakRoles map[string]string `yaml:"keycloakRoles"`
}

// CustomRolesConfig - Custom role limits
type CustomRolesConfig struct {
    MaxPerTenant            int `yaml:"maxPerTenant"`
    MaxPermissionsPerRole   int `yaml:"maxPermissionsPerRole"`
    SoftDeleteRetentionDays int `yaml:"softDeleteRetentionDays"`
}

// RouteConfig - Route file configuration (routes.d/*.yaml)
type RouteConfig struct {
    Source      string          `yaml:"source"`
    Version     string          `yaml:"version"`
    Description string          `yaml:"description,omitempty"`
    Defaults    RouteDefaults   `yaml:"defaults,omitempty"`
    Resources   []ResourceDef   `yaml:"resources,omitempty"`
    Routes      []RouteEntry    `yaml:"routes"`
}

type RouteDefaults struct {
    Endpoint string `yaml:"endpoint"`
    Group    string `yaml:"group"`
}

type ResourceDef struct {
    Name          string   `yaml:"name"`
    DisplayName   string   `yaml:"displayName,omitempty"`
    Description   string   `yaml:"description,omitempty"`
    Category      string   `yaml:"category,omitempty"`
    Scope         string   `yaml:"scope,omitempty"`         // "" = global
    DefaultAccess string   `yaml:"defaultAccess,omitempty"`
    Verbs         []string `yaml:"verbs"`
}

type RouteEntry struct {
    URL      string `yaml:"url"`
    Method   string `yaml:"method"`
    Endpoint string `yaml:"endpoint,omitempty"`

    // Authentication flags (orthogonal to scope)
    IsPublic bool `yaml:"isPublic,omitempty"` // No authentication required
    IsRoot   bool `yaml:"isRoot,omitempty"`   // Root tenancy only

    // RBAC
    Group    string `yaml:"group,omitempty"`
    Resource string `yaml:"resource,omitempty"`
    Verb     string `yaml:"verb,omitempty"`

    // Structured scope definition (replaces Scopes []string)
    Scope ScopeDefinition `yaml:"scope,omitempty"`

    // Resource identifier extraction (for constraint matching in URL)
    ResourceIdentifier *ResourceIdentifier `yaml:"resourceIdentifier,omitempty"`
}

type ScopeDefinition struct {
    Type         string `yaml:"type"`                    // "", "tenant", "org-unit"
    PathParam    string `yaml:"pathParam,omitempty"`     // URL param: "ou"
    PathPosition int    `yaml:"pathPosition,omitempty"`  // Position in URL (0-indexed)
}

type ResourceIdentifier struct {
    PathParam    string `yaml:"pathParam"`              // "name", "id"
    PathPosition int    `yaml:"pathPosition"`           // Position in URL (0-indexed)
    Field        string `yaml:"field,omitempty"`        // Constraint field (default: "name")
}
```

---

## 4. Auth Context Headers (Gateway → Backend)

### 4.1 Design Principle

The gateway does NOT inspect request bodies. Authorization context is passed to backend services via HTTP headers for enforcement. This keeps the gateway simple and enables efficient filtering at the database level.

### 4.2 X-Auth-* Header Specifications

| Header | Description | Example | When Set |
|--------|-------------|---------|----------|
| `X-Auth-Tenant` | Tenant ID (from JWT realm) | `acme-corp` | Always (authenticated requests) |
| `X-Auth-User` | Authenticated username | `john.doe` | Always (authenticated requests) |
| `X-Auth-Is-Root` | Whether user is from root tenancy | `true` | Always (authenticated requests) |
| `X-Auth-OrgUnit` | Org-unit from URL path | `engineering` | When `scope.type == org-unit` |
| `X-Auth-Role` | User's role in current org-unit | `admin` | When `scope.type == org-unit` |
| `X-Auth-Allowed-Verbs` | Comma-separated verbs user can perform on this resource | `list,get,create,update` | When resource is defined |
| `X-Auth-Constraints` | JSON-encoded field constraints for this resource | `{"name":{"prefix":"abc-"},"type":{"values":["etl","ml"]}}` | When user has constrained permissions |

### 4.3 Header Details

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

### 4.4 Backend Constraint Usage

Backends use the `X-Auth-Constraints` header to enforce fine-grained access control:

| Operation | Gateway Check | Backend Enforcement |
|-----------|---------------|---------------------|
| LIST | Passes constraints via header | Filter query at DB level |
| CREATE | No body inspection | Validate request body fields against constraints |
| GET | Check URL param against constraints | Defense-in-depth verification |
| UPDATE | Check URL param against constraints | Defense-in-depth verification |
| DELETE | Check URL param against constraints | Defense-in-depth verification |

### 4.5 Implementation

```go
func (g *gateway) setAuthHeaders(r *http.Request, authInfo *auth.AuthInfo, scopeCtx *ScopeContext, perms *PermissionResult) {
    // Identity headers (always set)
    r.Header.Set("X-Auth-Tenant", authInfo.Realm)
    r.Header.Set("X-Auth-User", authInfo.UserName)
    r.Header.Set("X-Auth-Is-Root", strconv.FormatBool(authInfo.IsRoot))

    // Scope context headers (when org-unit scoped)
    if scopeCtx != nil && scopeCtx.OrgUnit != "" {
        r.Header.Set("X-Auth-OrgUnit", scopeCtx.OrgUnit)
        r.Header.Set("X-Auth-Role", scopeCtx.Role)
    }

    // Permission headers
    if perms != nil {
        if len(perms.AllowedVerbs) > 0 {
            r.Header.Set("X-Auth-Allowed-Verbs", strings.Join(perms.AllowedVerbs, ","))
        }
        if perms.HasConstraints() {
            constraintsJSON, _ := json.Marshal(perms.Constraints)
            r.Header.Set("X-Auth-Constraints", string(constraintsJSON))
        }
    }
}
```

---

## 5. Summary of Changes

### 5.1 API Changes

| Type | Service | Method | Description |
|------|---------|--------|-------------|
| New | OrgUnitRole | CreateCustomRole | Create custom role |
| New | OrgUnitRole | GetCustomRole | Get custom role details |
| New | OrgUnitRole | UpdateCustomRole | Update custom role |
| New | OrgUnitRole | DeleteCustomRole | Delete custom role |
| New | OrgUnitRole | ListCustomRoles | List custom roles |
| New | OrgUnitRole | ValidatePermissions | Validate permission definitions |
| Updated | OrgUnitRole | ListOrgUnitRoles | Enhanced with filters and permissions |
| New | ResourceRegistry | ListResources | List registered resources |
| New | ResourceRegistry | GetResource | Get resource details |
| New | ResourceRegistry | ListResourcesByScope | List resources by scope |
| New | PermissionChecker | CheckPermission | Check permission (internal) |
| New | PermissionChecker | GetEffectivePermissions | Get user's effective permissions |

### 5.2 Database Changes

| Collection | Change | Description |
|------------|--------|-------------|
| routes | Updated | Added `source` field |
| resources | New | Resource registry compiled from routes |
| custom-roles | New | Custom role definitions |
| org-unit-users | No change | Role field now supports custom role names |

### 5.3 Configuration Changes

| Section | Change | Description |
|---------|--------|-------------|
| authorization | New | Resource-verb authorization settings |
| routes | New | Route file loading configuration |
| builtinRoles | New | Built-in role definitions |
| roleMapping | New | Keycloak to auth-gateway role mapping |
| customRoles | New | Custom role limits and settings |

---

## 6. References

- [FDP-001: Resource-Verb Authorization](./FDP-001-resource-verb-authorization.md)
- [FDP-002: Custom Roles](./FDP-002-custom-roles.md)
- [FDP-003: Config Route Registration](./FDP-003-config-route-registration.md)
- [FDP-004: Built-in Role Permissions](./FDP-004-builtin-role-permissions.md)
