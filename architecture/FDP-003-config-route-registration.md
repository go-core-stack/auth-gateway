# FDP-003: Configuration-Based Route Registration

## Metadata
- **ID**: FDP-003
- **Title**: External Service Route Registration via Configuration
- **Epic**: EPIC-001 (Fine-Grained RBAC Enhancement)
- **Author**: Engineering Head
- **Created**: 2026-02-10
- **Status**: Draft
- **Reviewers**: TBD

---

## 1. Overview

### 1.1 Problem

Currently, routes are registered via protobuf annotations and code generation. Consuming services that:
- Don't use protobuf
- Don't want to integrate protoc plugins
- Need to register routes dynamically

...have no way to participate in auth-gateway's resource registry and RBAC.

### 1.2 Proposal

Enable route registration via YAML configuration files loaded at auth-gateway startup, with optional runtime reload.

### 1.3 Benefits

| Current (Proto Only) | With Config Registration |
|---------------------|--------------------------|
| Requires protoc toolchain | Simple YAML files |
| Compile-time only | Load-time configuration |
| Tight coupling to auth-gateway build | Decoupled deployment |
| One source of routes | Multiple sources supported |

### 1.4 Critical Constraint: Zero Latency Impact

**Route loading MUST NOT affect request handling performance.** Per EPIC-001 architectural constraints:

| Requirement | Implementation |
|-------------|----------------|
| Startup loading | Routes loaded from config files at gateway startup |
| Background reload | File watcher triggers async reload, NOT during request handling |
| In-memory routing | `matchRoute()` uses in-memory patricia trie - no file/DB access |
| Eventual consistency | Config file changes may take seconds to propagate - acceptable |

```
Startup Path:
  Gateway Start → Load YAML Files → Upsert to MongoDB → Reconcile → Populate In-Memory Trie

Request Path (ZERO FILE I/O):
  HTTP Request → matchRoute(in-memory trie) → Route Data → Proxy

Background Path (Optional):
  File Watcher → Detect Change → Async Reload → Trigger Reconciliation
```

Route configuration is inherently load-time. Hot-reloading is a convenience feature for operational flexibility, not a requirement for request handling.

---

## 2. Design

### 2.1 Configuration Structure

```yaml
# /etc/auth-gateway/routes.d/ai-gateway.yaml

# Metadata about the route source
source: "ai-gateway"
version: "1.0.0"
description: "AI Gateway routes for model and provider management"

# Backend defaults (can be overridden per-route)
defaults:
  endpoint: "http://ai-gateway:8080"
  group: "ai"

# Resource definitions with scope and access control
resources:
  # Global scope - managed by root tenant only
  # NOTE: scope is omitted (empty) which means "global"
  - name: "provider"
    displayName: "AI Provider"
    description: "AI service providers (OpenAI, Anthropic, etc.)"
    category: "ai"
    # scope: ""                        # Empty/omitted = global (implicit)
    defaultAccess: "root-admin"        # Who can access by default
    verbs: ["list", "get", "create", "update", "delete", "test"]

  # Tenant scope - managed by tenant admins
  - name: "model-config"
    displayName: "Model Configuration"
    description: "Tenant-level model configurations"
    category: "ai"
    scope: "tenant"                    # Explicit: Tenant-level resource
    defaultAccess: "tenant-admin"      # Tenant admins can manage
    verbs: ["list", "get", "create", "update", "delete"]

  # Org-unit scope - managed by org-unit roles
  - name: "model"
    displayName: "AI Model"
    description: "LLM and embedding models"
    category: "ai"
    scope: "org-unit"                  # Explicit: Org-unit scoped
    verbs: ["list", "get", "create", "update", "delete", "invoke"]

# Route definitions
routes:
  # ════════════════════════════════════════════════════════════════
  # ORG-UNIT SCOPED ROUTES
  # ════════════════════════════════════════════════════════════════

  # LIST - No resource identifier (backend filters using constraints)
  - url: "/api/ai/v1/ou/{ou}/models"
    method: GET
    resource: "model"
    verb: "list"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4

  # CREATE - Resource name in body (backend validates using constraints)
  - url: "/api/ai/v1/ou/{ou}/models"
    method: POST
    resource: "model"
    verb: "create"
    scope:
      type: "org-unit"
      pathParam: "ou"
      pathPosition: 4

  # GET - Resource identifier in URL (gateway can check constraints)
  - url: "/api/ai/v1/ou/{ou}/models/{id}"
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

  # UPDATE - Resource identifier in URL
  - url: "/api/ai/v1/ou/{ou}/models/{id}"
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

  # DELETE - Resource identifier in URL
  - url: "/api/ai/v1/ou/{ou}/models/{id}"
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

  # EXECUTE action on specific model
  - url: "/api/ai/v1/ou/{ou}/models/{id}/invoke"
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

  # ════════════════════════════════════════════════════════════════
  # ROOT TENANCY + TENANT SCOPE (Admin Portal)
  # ════════════════════════════════════════════════════════════════

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

  # ════════════════════════════════════════════════════════════════
  # PUBLIC ROUTES (No Authentication)
  # ════════════════════════════════════════════════════════════════

  - url: "/api/ai/v1/health"
    method: GET
    isPublic: true
```

### 2.2 Route Schema

```go
// pkg/config/routes.go

type RouteConfig struct {
    Source      string            `yaml:"source"`
    Version     string            `yaml:"version"`
    Description string            `yaml:"description,omitempty"`
    Defaults    RouteDefaults     `yaml:"defaults,omitempty"`
    Resources   []ResourceDef     `yaml:"resources,omitempty"`
    Routes      []RouteEntry      `yaml:"routes"`
}

type RouteDefaults struct {
    Endpoint string `yaml:"endpoint"`
    Group    string `yaml:"group"`
}

type ResourceDef struct {
    Name        string   `yaml:"name"`
    DisplayName string   `yaml:"displayName,omitempty"`
    Description string   `yaml:"description,omitempty"`
    Category    string   `yaml:"category,omitempty"`
    Verbs       []string `yaml:"verbs"`

    // Scope definition
    // "" (empty) = unscoped (user-specific, authentication only)
    // "tenant" = tenant-scoped (global within tenant)
    // "org-unit" = org-unit scoped
    Scope         ScopeConfig `yaml:"scope,omitempty"`
    DefaultAccess string      `yaml:"defaultAccess,omitempty"` // "root-admin", "tenant-admin", or empty
}

type ScopeConfig struct {
    Type      string `yaml:"type"`                // "", "tenant", "org-unit"
    PathParam string `yaml:"pathParam,omitempty"` // URL param name: "ou", "tenant"
}

// Scope type constants
const (
    ScopeTypeUnscoped = ""         // Authentication only, no scope authZ
    ScopeTypeTenant   = "tenant"   // Tenant-scoped (global within tenant)
    ScopeTypeOrgUnit  = "org-unit" // Org-unit scoped
)

type RouteEntry struct {
    URL      string `yaml:"url"`
    Method   string `yaml:"method"`
    Endpoint string `yaml:"endpoint,omitempty"` // Override default

    // AUTHENTICATION FLAGS (Orthogonal to Scope)
    IsPublic bool `yaml:"isPublic,omitempty"` // No authentication required
    IsRoot   bool `yaml:"isRoot,omitempty"`   // Root tenancy only

    // RBAC
    Group    string `yaml:"group,omitempty"` // Override default
    Resource string `yaml:"resource,omitempty"`
    Verb     string `yaml:"verb,omitempty"`

    // SCOPE DEFINITION (structured, replaces Scopes []string)
    Scope ScopeDefinition `yaml:"scope,omitempty"`

    // RESOURCE IDENTIFIER (for constraint matching on GET/UPDATE/DELETE)
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

### 2.3 Configuration Loading

```go
// pkg/config/config.go

type Config struct {
    // ... existing fields

    // Route configuration
    Routes RoutesConfig `yaml:"routes"`
}

type RoutesConfig struct {
    // Files or directories to load
    Files []string `yaml:"files,omitempty"` // e.g., ["/etc/auth-gateway/routes.d/*.yaml"]

    // Watch for changes and reload
    WatchEnabled  bool          `yaml:"watchEnabled,omitempty"`
    WatchInterval time.Duration `yaml:"watchInterval,omitempty"` // Default: 30s

    // Validation
    StrictMode bool `yaml:"strictMode,omitempty"` // Fail on invalid routes
}
```

### 2.4 Default Configuration

```yaml
# default.yaml
routes:
  files:
    - "/etc/auth-gateway/routes.d/*.yaml"
    - "./routes/*.yaml"  # For development
  watchEnabled: false    # Enable in environments that need it
  watchInterval: 30s
  strictMode: true       # Fail fast on invalid routes
```

---

## 3. Implementation

### 3.0 Existing Patterns to Leverage

**RouteTable from go-core-stack/auth**: Routes are stored and retrieved via `route.RouteTable` from the `github.com/go-core-stack/auth/route` package. The config loader must use this same table:

```go
import "github.com/go-core-stack/auth/route"

routes, err := route.GetRouteTable()
```

**Reconciler Pattern (`pkg/gateway/routes.go`)**: The gateway already uses a reconciler pattern for route population:

```go
// pkg/gateway/server.go:73-90
type gatewayReconciler struct {
    reconciler.Controller
    mu sync.Mutex
    gw *gateway
}

func (r *gatewayReconciler) Reconcile(k any) (*reconciler.Result, error) {
    // Debounced route refresh
    go func() {
        time.Sleep(10 * time.Second)
        populateRoutes(r.gw.routes)
    }()
    return &reconciler.Result{}, nil
}
```

The config loader should integrate with this reconciliation mechanism to trigger in-memory cache updates when routes are loaded or modified.

### 3.1 Route Loader

```go
// pkg/routes/loader.go

type RouteLoader struct {
    routeTable   *route.RouteTable
    resourceMgr  *roledef.ResourceManager
    config       *config.RoutesConfig
    loadedFiles  map[string]time.Time // Track file modification times
    mu           sync.Mutex
}

func NewRouteLoader(cfg *config.RoutesConfig, rt *route.RouteTable, rm *roledef.ResourceManager) *RouteLoader {
    return &RouteLoader{
        routeTable:  rt,
        resourceMgr: rm,
        config:      cfg,
        loadedFiles: make(map[string]time.Time),
    }
}

func (l *RouteLoader) LoadAll(ctx context.Context) error {
    l.mu.Lock()
    defer l.mu.Unlock()

    for _, pattern := range l.config.Files {
        files, err := filepath.Glob(pattern)
        if err != nil {
            return fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
        }

        for _, file := range files {
            if err := l.loadFile(ctx, file); err != nil {
                if l.config.StrictMode {
                    return fmt.Errorf("failed to load %s: %w", file, err)
                }
                log.Printf("Warning: failed to load %s: %v", file, err)
            }
        }
    }

    // Trigger reconciliation to update in-memory route cache
    // This integrates with the existing gatewayReconciler pattern
    // which calls populateRoutes() after a debounce period
    l.routeTable.TriggerReconcile("config-loader")

    // Also trigger resource definition recompilation for API exposure
    l.resourceMgr.Refresh()

    return nil
}

func (l *RouteLoader) loadFile(ctx context.Context, path string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }

    var cfg RouteConfig
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return fmt.Errorf("invalid YAML: %w", err)
    }

    // Validate configuration
    if err := l.validate(&cfg); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    // Upsert routes to database
    for _, r := range cfg.Routes {
        route := l.toRoute(&cfg, &r)
        if err := l.routeTable.Upsert(ctx, route); err != nil {
            return fmt.Errorf("failed to upsert route %s %s: %w", r.Method, r.URL, err)
        }
    }

    // Track file
    info, _ := os.Stat(path)
    l.loadedFiles[path] = info.ModTime()

    log.Printf("Loaded %d routes from %s (source: %s)", len(cfg.Routes), path, cfg.Source)
    return nil
}
```

### 3.2 Route Conversion

```go
func (l *RouteLoader) toRoute(cfg *RouteConfig, entry *RouteEntry) *route.Route {
    // Apply defaults
    endpoint := entry.Endpoint
    if endpoint == "" {
        endpoint = cfg.Defaults.Endpoint
    }

    group := entry.Group
    if group == "" {
        group = cfg.Defaults.Group
    }

    method := l.parseMethod(entry.Method)

    return &route.Route{
        Key: &route.Key{
            Url:    entry.URL,
            Method: method,
        },
        Endpoint:           endpoint,
        IsPublic:           entry.IsPublic,
        IsRoot:             entry.IsRoot,
        Group:              group,
        Resource:           entry.Resource,
        Verb:               entry.Verb,
        Scope:              entry.Scope,              // Structured scope definition
        ResourceIdentifier: entry.ResourceIdentifier, // For constraint matching
        Source:              cfg.Source,
    }
}
```

### 3.3 Validation

```go
func (l *RouteLoader) validate(cfg *RouteConfig) error {
    if cfg.Source == "" {
        return errors.New("source is required")
    }

    // Build resource verb map for validation
    resourceVerbs := make(map[string][]string)
    for _, res := range cfg.Resources {
        resourceVerbs[res.Name] = res.Verbs
    }

    for i, r := range cfg.Routes {
        // Validate URL
        if r.URL == "" {
            return fmt.Errorf("route[%d]: url is required", i)
        }

        // Validate method
        if r.Method == "" {
            return fmt.Errorf("route[%d]: method is required", i)
        }

        // Validate resource/verb if specified
        if r.Resource != "" {
            verbs, ok := resourceVerbs[r.Resource]
            if !ok {
                return fmt.Errorf("route[%d]: unknown resource %q", i, r.Resource)
            }

            if r.Verb != "" && !slices.Contains(verbs, r.Verb) {
                return fmt.Errorf("route[%d]: invalid verb %q for resource %q", i, r.Verb, r.Resource)
            }
        }
    }

    return nil
}
```

### 3.4 File Watcher (Optional)

```go
func (l *RouteLoader) StartWatcher(ctx context.Context) {
    if !l.config.WatchEnabled {
        return
    }

    interval := l.config.WatchInterval
    if interval == 0 {
        interval = 30 * time.Second
    }

    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            l.checkForChanges(ctx)
        }
    }
}

func (l *RouteLoader) checkForChanges(ctx context.Context) {
    l.mu.Lock()
    defer l.mu.Unlock()

    for path, lastMod := range l.loadedFiles {
        info, err := os.Stat(path)
        if err != nil {
            log.Printf("Warning: cannot stat %s: %v", path, err)
            continue
        }

        if info.ModTime().After(lastMod) {
            log.Printf("Detected change in %s, reloading...", path)
            if err := l.loadFile(ctx, path); err != nil {
                log.Printf("Error reloading %s: %v", path, err)
            }
        }
    }
}
```

---

## 4. Route Table Schema Extension

### 4.1 Add Source Field

```go
// go-core-stack/auth/route/route.go

type Route struct {
    Key      *Key   `bson:"key,omitempty"`
    Endpoint string `bson:"endpoint,omitempty"`

    // Authentication flags (orthogonal to scope)
    IsPublic bool `bson:"isPublic,omitempty"`  // No authentication required
    IsRoot   bool `bson:"isRoot,omitempty"`    // Root tenancy only (admin portal APIs)

    // RBAC
    Resource string `bson:"resource,omitempty"` // e.g., "workflow"
    Verb     string `bson:"verb,omitempty"`     // e.g., "execute"

    // Structured scope definition (replaces Scopes []string)
    Scope ScopeDefinition `bson:"scope,omitempty"`

    // Resource identifier extraction (for constraint matching in URL)
    ResourceIdentifier *ResourceIdentifier `bson:"resourceIdentifier,omitempty"`

    // Metadata
    Group  string `bson:"group,omitempty"`  // Service group
    Source string `bson:"source,omitempty"` // Origin: "auth-gateway", "config", etc.
}
```

### 4.2 Source Values

| Source | Description |
|--------|-------------|
| `"auth-gateway"` | Routes from auth-gateway's own proto definitions |
| `"<service-name>"` | Routes from external service config files |
| `"config"` | Generic config-loaded routes |

---

## 5. Startup Integration

### 5.1 Main Initialization

```go
// main.go

func main() {
    cfg := config.Load()

    // Initialize MongoDB and route table
    routeTable, _ := route.LocateRouteTable(mongoClient)

    // Initialize resource manager
    resourceMgr := roledef.NewResourceManager()

    // Load proto-generated routes (existing)
    loadProtoRoutes(routeTable)

    // NEW: Load config-based routes
    routeLoader := routes.NewRouteLoader(&cfg.Routes, routeTable, resourceMgr)
    if err := routeLoader.LoadAll(ctx); err != nil {
        log.Fatalf("Failed to load routes: %v", err)
    }

    // Start file watcher if enabled
    go routeLoader.StartWatcher(ctx)

    // Start gateway
    startGateway(cfg, routeTable, resourceMgr)
}
```

---

## 6. Deployment Patterns

### 6.1 ConfigMap (Kubernetes)

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-gateway-routes
data:
  ai-gateway.yaml: |
    source: "ai-gateway"
    defaults:
      endpoint: "http://ai-gateway:8080"
    routes:
      - url: "/api/ai/v1/models"
        method: GET
        resource: "model"
        verb: "list"
        scope:
          type: "org-unit"
          pathParam: "ou"
          pathPosition: 4
```

```yaml
# deployment.yaml
spec:
  containers:
    - name: auth-gateway
      volumeMounts:
        - name: routes
          mountPath: /etc/auth-gateway/routes.d
  volumes:
    - name: routes
      configMap:
        name: auth-gateway-routes
```

### 6.2 Sidecar Pattern

Services can provide their routes via a sidecar container that writes YAML to a shared volume.

### 6.3 Init Container

```yaml
initContainers:
  - name: fetch-routes
    image: busybox
    command:
      - sh
      - -c
      - |
        wget -O /routes/ai-gateway.yaml http://ai-gateway:8080/routes.yaml
    volumeMounts:
      - name: routes
        mountPath: /routes
```

---

## 7. Observability

### 7.1 Metrics

```go
var (
    routesLoaded = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "authgw_routes_loaded_total",
            Help: "Number of routes loaded by source",
        },
        []string{"source"},
    )

    routeLoadErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "authgw_route_load_errors_total",
            Help: "Number of route loading errors",
        },
        []string{"file"},
    )
)
```

### 7.2 Health Check

```go
// Include in health endpoint
func (l *RouteLoader) HealthCheck() map[string]interface{} {
    return map[string]interface{}{
        "loadedFiles":  len(l.loadedFiles),
        "watchEnabled": l.config.WatchEnabled,
        "sources":      l.getSources(),
    }
}
```

---

## 8. Implementation Tasks

| Task ID | Description | Effort | Dependencies |
|---------|-------------|--------|--------------|
| FDP-003-T1 | Define RouteConfig YAML schema | S | None |
| FDP-003-T2 | Add Source field to route.Route | XS | go-core-stack/auth |
| FDP-003-T3 | Implement RouteLoader | M | T1, T2 |
| FDP-003-T4 | Implement route validation | S | T3 |
| FDP-003-T5 | Integrate loader into startup | S | T3 |
| FDP-003-T6 | Implement file watcher | S | T3 |
| FDP-003-T7 | Add configuration options | S | T3 |
| FDP-003-T8 | Add metrics and health check | S | T3 |
| FDP-003-T9 | Write documentation | M | T3 |
| FDP-003-T10 | Write unit and integration tests | M | T3 |

---

## 9. Security Considerations

| Concern | Mitigation |
|---------|------------|
| Malicious route injection | Restrict file permissions; validate all routes |
| Endpoint override attacks | Validate endpoints against allowlist |
| Resource exhaustion | Limit number of routes per source |
| File path traversal | Validate file paths before loading |

---

## 10. Open Questions

| Question | Status | Answer |
|----------|--------|--------|
| Should we support remote route fetching (HTTP)? | Open | Consider for Phase 2 |
| Rate limit route reloads? | Open | Debounce in watcher |
| Support route deletion when file removed? | Open | Yes, track by source |

---

## 11. References

- [Route Table Schema](https://github.com/go-core-stack/auth/blob/main/route/route.go)
- [FDP-001: Resource-Verb Authorization](./FDP-001-resource-verb-authorization.md)
