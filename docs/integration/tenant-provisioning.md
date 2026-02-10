# Tenant Provisioning Integration Guide

This guide documents the asynchronous tenant provisioning flow in auth-gateway, including the reconciler pattern, status fields to monitor, and recommended approaches for detecting provisioning completion.

## Overview

Tenant creation in auth-gateway is **asynchronous**. The `CreateTenant` gRPC API returns immediately, and Keycloak realm provisioning happens in the background via a reconciler controller.

```
┌──────────┐    CreateTenant     ┌───────────────┐    Returns immediately
│  Client  │ ──────────────────▶ │ Auth-Gateway  │ ──────────────────────▶ Empty response
│          │                     │ (inserts to   │
└──────────┘                     │  MongoDB)     │
                                 └───────┬───────┘
                                         │
                                         │  Background
                                         ▼
                                 ┌───────────────┐     ┌──────────────────┐
                                 │ SetupReconciler│────▶│ Create Keycloak  │
                                 │ (watches       │     │ realm            │
                                 │  tenants table)│     └────────┬─────────┘
                                 └───────────────┘              │
                                                                ▼
                                                       ┌──────────────────┐
                                                       │ Create auth      │
                                                       │ client + protocol│
                                                       │ mappers          │
                                                       └────────┬─────────┘
                                                                │
                                                                ▼
                                                       ┌──────────────────┐
                                                       │ Update status    │
                                                       │ fields in MongoDB│
                                                       └──────────────────┘
```

The reconciler (`SetupReconciler`) is registered on the tenants table and triggers automatically when a tenant entry is created or updated. On failure, it retries every 5 seconds.

## Status Fields

Provisioning progress is tracked via status fields on the `TenantEntry` struct:

```go
type TenantEntry struct {
    Config      *TenantConfig            `bson:"config,omitempty"`
    KCStatus    *TenantKCStatus          `bson:"kcStatus,omitempty"`
    AuthClient  *TenantAuthClientStatus  `bson:"authClient,omitempty"`
    RoleStatus  *TenantRoleStatus        `bson:"roleStatus,omitempty"`
    AdminStatus *TenantAdminStatus       `bson:"adminStatus,omitempty"`
}

type TenantKCStatus struct {
    UpdateTime int64  `bson:"updateTime,omitempty"`  // Unix timestamp when realm was created
    RealmName  string `bson:"realmName,omitempty"`   // Keycloak realm name
}

type TenantAuthClientStatus struct {
    UpdateTime int64  `bson:"updateTime,omitempty"`  // Unix timestamp when client was configured
    ClientId   string `bson:"clientID,omitempty"`    // Keycloak client ID (e.g., "controller")
}

type TenantRoleStatus struct {
    UpdateTime int64 `bson:"updateTime,omitempty"`   // Unix timestamp when roles were synced
}

type TenantAdminStatus struct {
    UpdateTime int64  `bson:"updateTime,omitempty"`  // Unix timestamp when admin was created
    Admin      string `bson:"admin,omitempty"`       // Default admin user ID
}
```

| Field | Non-Zero Meaning | Required for Auth |
|-------|------------------|-------------------|
| `kcStatus.updateTime` | Keycloak realm exists | Yes |
| `authClient.updateTime` | Auth client with protocol mappers configured | Yes |
| `roleStatus.updateTime` | Realm roles synced | No (optional) |
| `adminStatus.updateTime` | Default admin user created | No (optional) |

## Provisioning States

| State | Condition | User Can Login? |
|-------|-----------|-----------------|
| **Pending** | `kcStatus == null` or `kcStatus.updateTime == 0` | No |
| **Provisioning** | `kcStatus.updateTime > 0` but `authClient == null` or `authClient.updateTime == 0` | No |
| **Ready** | `kcStatus.updateTime > 0` AND `authClient.updateTime > 0` | Yes |
| **Fully Provisioned** | All four status timestamps non-zero | Yes |

A tenant is **ready for authentication** once both the Keycloak realm (`kcStatus`) and the auth client (`authClient`) have been configured. The `roleStatus` and `adminStatus` fields track additional provisioning steps that are not required for basic authentication.

## Change Stream Approach (Recommended)

**Change streams are the preferred method** for detecting tenant provisioning completion. They provide real-time notifications without polling overhead.

### Using Auth-Gateway Table Package (Go Services)

For Go-based services, import auth-gateway's table package directly for type-safe access (see the [Change Stream Integration Guide](change-streams.md) for setup details).

```go
import (
    "github.com/go-core-stack/auth-gateway/pkg/table"
    "github.com/go-core-stack/core/db"
)

func WaitForTenantReady(ctx context.Context, tenantName string) error {
    ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
    defer cancel()

    tbl, err := table.GetTenantTable()
    if err != nil {
        return err
    }

    // Watch for authClient status updates on this specific tenant
    pipeline := mongo.Pipeline{
        {{Key: "$match", Value: bson.M{
            "operationType": "update",
            "documentKey._id.name": tenantName,
            "updateDescription.updatedFields.authClient.updateTime": bson.M{"$exists": true},
        }}},
    }

    stream, err := tbl.Watch(ctx, pipeline)
    if err != nil {
        return err
    }
    defer stream.Close(ctx)

    // Check if already provisioned before waiting
    key := &table.TenantKey{Name: tenantName}
    entry, err := tbl.Find(ctx, key)
    if err == nil && entry.AuthClient != nil && entry.AuthClient.UpdateTime > 0 {
        return nil // Already ready
    }

    // Wait for provisioning event
    if stream.Next(ctx) {
        return nil // Provisioning complete
    }

    if ctx.Err() == context.DeadlineExceeded {
        return errors.New("tenant provisioning timeout")
    }
    return stream.Err()
}
```

### Direct MongoDB Change Stream (Non-Go Services)

```python
# Python example
def wait_for_tenant_ready(db, tenant_name, timeout_seconds=120):
    pipeline = [
        {"$match": {
            "operationType": "update",
            "documentKey._id.name": tenant_name,
            "updateDescription.updatedFields.authClient.updateTime": {"$exists": True}
        }}
    ]

    # Check if already ready
    tenant = db.tenants.find_one({"_id.name": tenant_name})
    if tenant and tenant.get("authClient", {}).get("updateTime"):
        return True

    # Watch for change
    with db.tenants.watch(pipeline, max_await_time_ms=timeout_seconds * 1000) as stream:
        for change in stream:
            return True  # Provisioning complete

    raise TimeoutError("Tenant provisioning timeout")
```

## Polling Approach (Fallback)

Use polling only when change streams are not available (e.g., MongoDB standalone mode without replica set).

```go
func WaitForTenantReadyPolling(ctx context.Context, tenantName string) error {
    const (
        pollInterval = 2 * time.Second
        maxWait      = 120 * time.Second
    )

    tbl, err := table.GetTenantTable()
    if err != nil {
        return err
    }

    deadline := time.Now().Add(maxWait)
    key := &table.TenantKey{Name: tenantName}

    for time.Now().Before(deadline) {
        entry, err := tbl.Find(ctx, key)
        if err != nil {
            return err
        }

        if entry.KCStatus != nil &&
            entry.KCStatus.UpdateTime > 0 &&
            entry.AuthClient != nil &&
            entry.AuthClient.UpdateTime > 0 {
            return nil // Ready
        }

        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(pollInterval):
            continue
        }
    }

    return errors.New("tenant provisioning timeout")
}
```

## Typical Provisioning Times

| Environment | Typical Duration | Notes |
|-------------|------------------|-------|
| Development | 5-15 seconds | Local Keycloak, fast |
| Staging | 15-45 seconds | Shared Keycloak |
| Production | 30-90 seconds | Depends on Keycloak load |

**Recommendation**: Use a 120-second timeout with change streams, or 2-second polling intervals as a fallback.

## Failure Handling

The reconciler retries failed provisioning steps every 5 seconds automatically:

```go
// From SetupReconciler.Reconcile
if err != nil {
    return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
}
```

If provisioning consistently fails, check:

1. Keycloak connectivity from auth-gateway
2. Keycloak admin credentials configuration
3. Realm name conflicts (realm may already exist in Keycloak)
4. Auth-gateway logs for specific error messages

## UI Integration Example

```javascript
// Onboarding flow
async function createWorkspace(name) {
    // 1. Create tenant
    await authGateway.createTenant({ name });

    // 2. Show provisioning UI
    showProvisioningSpinner("Setting up your workspace...");

    // 3. Poll for ready (frontend uses REST polling)
    const maxAttempts = 60; // 2 minutes at 2s intervals
    for (let i = 0; i < maxAttempts; i++) {
        const tenant = await authGateway.getTenant(name);

        if (tenant.authClient?.updateTime > 0) {
            hideProvisioningSpinner();
            redirectToDashboard();
            return;
        }

        await sleep(2000);
    }

    showError("Workspace setup is taking longer than expected. Please try again.");
}
```

## Code References

- `pkg/server/tenant.go` - CreateTenant and GetTenant gRPC handlers
- `pkg/controller/tenant/setup.go` - SetupReconciler (realm + auth client provisioning)
- `pkg/table/tenant.go` - TenantEntry, TenantKCStatus, TenantAuthClientStatus structs

## Related

- [Change Stream Integration Guide](change-streams.md) - MongoDB change stream patterns
- [Collection Schemas](collection-schemas.md) - Tenants collection schema details
