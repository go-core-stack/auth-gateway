# MongoDB Change Stream Integration Guide

This guide documents how consuming services can use MongoDB change streams to monitor auth-gateway events in real-time. Change streams are the recommended pattern for internal platform services instead of webhooks or polling.

## Overview

Change streams provide several advantages for integrating with auth-gateway:

- **Real-time notifications** without polling overhead
- **Built-in resume capability** via resume tokens for crash recovery
- **No additional auth-gateway infrastructure** needed -- consumers connect directly to MongoDB
- **Consumer-side filtering** via aggregation pipelines for efficiency
- **Guaranteed ordering** of events per collection

## Prerequisites

- **MongoDB replica set** (required for change streams; standalone mode does not support them)
- **Read access** to the `auth-gateway` MongoDB database
- **Go MongoDB driver** (`go.mongodb.org/mongo-driver`) or equivalent driver for your language

## Go Clients: Use Auth-Gateway Table Package (Recommended)

For Go-based services, the recommended approach is to import auth-gateway's table package directly. This provides type-safe access to auth-gateway collections with consistent schema definitions, so you don't need to redefine BSON structures.

```go
import (
    "github.com/go-core-stack/auth-gateway/pkg/table"
    "github.com/go-core-stack/core/db"
)

func SetupAuthGatewayTables(ctx context.Context, mongoURI string) error {
    // Initialize MongoDB connection
    client, err := db.NewClient(ctx, mongoURI)
    if err != nil {
        return err
    }

    // Locate tables using auth-gateway's singleton pattern.
    // Each table is initialized once and cached at the package level.
    userTable, err := table.LocateUserTable(client)
    if err != nil {
        return err
    }

    tenantTable, err := table.LocateTenantTable(client)
    if err != nil {
        return err
    }

    apiKeyTable, err := table.LocateApiKeyTable(client)
    if err != nil {
        return err
    }

    // Tables are now ready for queries and change stream watching.
    // Use the underlying collection for Watch() calls.
    _ = userTable
    _ = tenantTable
    _ = apiKeyTable
    return nil
}
```

### Built-in Event Logger

Auth-gateway uses `db.NewEventLogger` from the `go-core-stack/core` package to watch change streams. This is already used in production for the `org-units` and `org-unit-users` collections:

```go
import "github.com/go-core-stack/core/db"

// Start a change stream event logger on a table's collection.
// This is the same pattern used internally by auth-gateway in main.go.
func StartWatching(col db.StoreCollection) error {
    logger := db.NewEventLogger[table.UserKey, table.UserEntry](col, nil)
    return logger.Start(context.Background())
}
```

## Non-Go Clients: Direct MongoDB Connection

For non-Go services, connect to the `auth-gateway` database directly and use your driver's change stream API.

### Python

```python
from pymongo import MongoClient

client = MongoClient("mongodb://...")
db = client["auth-gateway"]

# Watch the users collection
with db.users.watch() as stream:
    for change in stream:
        print(change)
```

### Node.js

```javascript
const { MongoClient } = require("mongodb");

const client = await MongoClient.connect("mongodb://...");
const db = client.db("auth-gateway");

const stream = db.collection("users").watch();
stream.on("change", (change) => {
  console.log(change);
});
```

## Common Watch Patterns

The following patterns use the standard MongoDB Go driver directly. Collection names are defined in `pkg/table/const.go`:

| Collection | Constant | Purpose |
|------------|----------|---------|
| `users` | `UserCollectionName` | User accounts |
| `tenants` | `TenantsCollectionName` | Tenant/realm records |
| `api-keys` | `ApiKeyCollectionName` | API key records |
| `org-units` | `OrgUnitCollectionName` | Organizational units |
| `org-unit-users` | `OrgUnitUserCollectionName` | OU membership |

### Watch for User Disable Events

Detect when a user is disabled or enabled. The `disabled` field on `UserEntry` is a `*bool`.

```go
func WatchUserDisabled(ctx context.Context, db *mongo.Database, tenantID string) error {
    pipeline := mongo.Pipeline{
        {{Key: "$match", Value: bson.M{
            "operationType": "update",
            "updateDescription.updatedFields.disabled": bson.M{"$exists": true},
        }}},
    }

    opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
    stream, err := db.Collection("users").Watch(ctx, pipeline, opts)
    if err != nil {
        return err
    }
    defer stream.Close(ctx)

    for stream.Next(ctx) {
        var event struct {
            FullDocument struct {
                Key      table.UserKey `bson:"key"`
                Disabled *bool         `bson:"disabled"`
            } `bson:"fullDocument"`
        }
        if err := stream.Decode(&event); err != nil {
            log.Printf("decode error: %v", err)
            continue
        }

        doc := event.FullDocument
        if doc.Key.Tenant == tenantID {
            if doc.Disabled != nil && *doc.Disabled {
                log.Printf("User disabled: %s/%s", doc.Key.Tenant, doc.Key.Username)
            } else {
                log.Printf("User enabled: %s/%s", doc.Key.Tenant, doc.Key.Username)
            }
        }
    }
    return stream.Err()
}
```

### Watch for API Key Changes

Detect when API keys are disabled, updated, or deleted. The key identifier is `ApiKeyId` with a single `Id` field.

```go
func WatchAPIKeyChanges(ctx context.Context, db *mongo.Database, tenantID string) error {
    pipeline := mongo.Pipeline{
        {{Key: "$match", Value: bson.M{
            "operationType": bson.M{"$in": []string{"update", "delete"}},
        }}},
    }

    opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
    stream, err := db.Collection("api-keys").Watch(ctx, pipeline, opts)
    if err != nil {
        return err
    }
    defer stream.Close(ctx)

    for stream.Next(ctx) {
        var event struct {
            OperationType string `bson:"operationType"`
            FullDocument  struct {
                UserInfo *table.ApiKeyUserInfo `bson:"userInfo"`
                Config   *table.ApiKeyConfig   `bson:"config"`
            } `bson:"fullDocument"`
        }
        if err := stream.Decode(&event); err != nil {
            continue
        }

        doc := event.FullDocument
        if doc.UserInfo != nil && doc.UserInfo.Tenant == tenantID {
            switch event.OperationType {
            case "delete":
                log.Printf("API key deleted for user: %s", doc.UserInfo.Username)
            case "update":
                if doc.Config != nil && doc.Config.IsDisabled != nil && *doc.Config.IsDisabled {
                    log.Printf("API key disabled for user: %s", doc.UserInfo.Username)
                }
            }
        }
    }
    return stream.Err()
}
```

### Watch for Tenant Provisioning Status

Detect when a tenant's Keycloak realm is provisioned. The `TenantKCStatus.UpdateTime` field is set to a non-zero value when provisioning completes.

```go
func WatchTenantProvisioning(ctx context.Context, db *mongo.Database) error {
    pipeline := mongo.Pipeline{
        {{Key: "$match", Value: bson.M{
            "operationType": "update",
            "updateDescription.updatedFields.kcStatus": bson.M{"$exists": true},
        }}},
    }

    opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
    stream, err := db.Collection("tenants").Watch(ctx, pipeline, opts)
    if err != nil {
        return err
    }
    defer stream.Close(ctx)

    for stream.Next(ctx) {
        var event struct {
            FullDocument struct {
                Config   *table.TenantConfig   `bson:"config"`
                KCStatus *table.TenantKCStatus  `bson:"kcStatus"`
            } `bson:"fullDocument"`
        }
        if err := stream.Decode(&event); err != nil {
            continue
        }

        doc := event.FullDocument
        if doc.KCStatus != nil && doc.KCStatus.UpdateTime > 0 {
            name := ""
            if doc.Config != nil {
                name = doc.Config.DispName
            }
            log.Printf("Tenant provisioned: %s (realm: %s)", name, doc.KCStatus.RealmName)
        }
    }
    return stream.Err()
}
```

### Watch for Org Unit Membership Changes

Detect when users are added to or removed from organizational units.

```go
func WatchOrgUnitMembership(ctx context.Context, db *mongo.Database, tenantID string) error {
    pipeline := mongo.Pipeline{
        {{Key: "$match", Value: bson.M{
            "operationType": bson.M{"$in": []string{"insert", "delete"}},
        }}},
    }

    opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
    stream, err := db.Collection("org-unit-users").Watch(ctx, pipeline, opts)
    if err != nil {
        return err
    }
    defer stream.Close(ctx)

    for stream.Next(ctx) {
        var event struct {
            OperationType string `bson:"operationType"`
            FullDocument  struct {
                Key  *table.OrgUnitUserKey `bson:"key"`
                Role string                `bson:"role"`
            } `bson:"fullDocument"`
        }
        if err := stream.Decode(&event); err != nil {
            continue
        }

        doc := event.FullDocument
        if doc.Key != nil && doc.Key.Tenant == tenantID {
            switch event.OperationType {
            case "insert":
                log.Printf("User %s added to org unit %s with role %s",
                    doc.Key.Username, doc.Key.OrgUnitId, doc.Role)
            case "delete":
                log.Printf("User %s removed from org unit %s",
                    doc.Key.Username, doc.Key.OrgUnitId)
            }
        }
    }
    return stream.Err()
}
```

## Resume Token Handling

Resume tokens allow a change stream to pick up where it left off after a disconnection or crash. This is critical for production deployments to avoid missing events.

```go
type ChangeStreamWatcher struct {
    resumeToken bson.Raw
    tokenStore  TokenStore // Persist to Redis, file, or another MongoDB collection
}

// TokenStore is an interface for persisting resume tokens.
type TokenStore interface {
    Save(ctx context.Context, collectionName string, token bson.Raw) error
    Load(ctx context.Context, collectionName string) (bson.Raw, error)
}

func (w *ChangeStreamWatcher) Watch(ctx context.Context, coll *mongo.Collection, pipeline mongo.Pipeline) error {
    opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)

    // Resume from last known position if available
    if w.resumeToken != nil {
        opts.SetResumeAfter(w.resumeToken)
    }

    stream, err := coll.Watch(ctx, pipeline, opts)
    if err != nil {
        return err
    }
    defer stream.Close(ctx)

    for stream.Next(ctx) {
        // Capture the resume token before processing
        w.resumeToken = stream.ResumeToken()

        // Process the event
        var event bson.M
        if err := stream.Decode(&event); err != nil {
            log.Printf("decode error: %v", err)
            continue
        }

        if err := w.handleEvent(event); err != nil {
            log.Printf("handle error: %v", err)
            // Decide whether to continue or stop based on error type
        }

        // Persist token periodically or after each event
        if err := w.tokenStore.Save(ctx, coll.Name(), w.resumeToken); err != nil {
            log.Printf("failed to persist resume token: %v", err)
        }
    }

    return stream.Err()
}

func (w *ChangeStreamWatcher) handleEvent(event bson.M) error {
    // Application-specific event handling
    return nil
}
```

### Resume Token Best Practices

- **Persist after processing**: Save the resume token after successfully processing each event to get at-least-once delivery semantics.
- **Persist before processing**: Save the token before processing if you prefer at-most-once delivery (acceptable for non-critical events like logging).
- **Use a durable store**: Redis or a dedicated MongoDB collection works well for token storage.

## Error Handling and Reconnection

### Transient Errors

The MongoDB driver automatically retries transient errors (network blips, primary elections) when a resume token is available. For cases where you need explicit reconnection:

```go
func WatchWithReconnect(ctx context.Context, coll *mongo.Collection, pipeline mongo.Pipeline) error {
    var resumeToken bson.Raw

    for {
        opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
        if resumeToken != nil {
            opts.SetResumeAfter(resumeToken)
        }

        stream, err := coll.Watch(ctx, pipeline, opts)
        if err != nil {
            // Check if context was cancelled
            if ctx.Err() != nil {
                return ctx.Err()
            }
            log.Printf("watch error, retrying in 5s: %v", err)
            select {
            case <-ctx.Done():
                return ctx.Err()
            case <-time.After(5 * time.Second):
                continue
            }
        }

        for stream.Next(ctx) {
            resumeToken = stream.ResumeToken()
            // Process event...
        }

        stream.Close(ctx)

        if ctx.Err() != nil {
            return ctx.Err()
        }

        log.Printf("stream ended, reconnecting in 1s...")
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(1 * time.Second):
        }
    }
}
```

### Invalidate Events

An invalidate event signals that the change stream is no longer valid (e.g., collection dropped or renamed). When this happens, you must start a new change stream without a resume token:

```go
for stream.Next(ctx) {
    var event struct {
        OperationType string `bson:"operationType"`
    }
    if err := stream.Decode(&event); err != nil {
        continue
    }

    if event.OperationType == "invalidate" {
        log.Println("change stream invalidated, restarting from current time")
        resumeToken = nil // Discard the resume token
        break            // Reconnect loop will restart the stream
    }

    resumeToken = stream.ResumeToken()
    // Process normal events...
}
```

## Performance Considerations

- **Use specific pipelines**: Filter events in the aggregation pipeline (server-side) rather than in application code. This reduces network traffic and CPU usage.
- **Separate watchers per collection**: Run independent change streams for each collection you need to monitor. This isolates failures and allows independent scaling.
- **Monitor oplog size**: Change streams rely on the MongoDB oplog. For high-volume deployments, ensure the oplog window is large enough to cover your longest expected downtime. A 24-hour oplog window is a reasonable starting point.
- **Batch token persistence**: In high-throughput scenarios, persist resume tokens every N events or every T seconds rather than after every event.
- **Use `SetFullDocument(options.UpdateLookup)`**: Only when you need the full document after an update. Omit it if you only need the changed fields (`updateDescription.updatedFields`).

## Related Documentation

- [AUTHGW-0008: Collection Schemas](collection-schemas.md) -- detailed schema reference for each collection
