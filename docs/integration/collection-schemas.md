# Collection Schema Reference

This document describes the MongoDB collection schemas used by auth-gateway. Consuming services need to understand these schemas when subscribing to [change streams](change-streams.md) or querying collections directly.

All collections reside in the `auth-gateway` database.

## Collections Overview

| Collection | Purpose | Key Events |
|------------|---------|------------|
| `tenants` | Tenant/realm records | Provisioning complete, status change |
| `users` | User accounts | Disabled, deleted, role changed |
| `api-keys` | API key records | Disabled, expired, deleted |
| `org-units` | Organizational units | Created, deleted |
| `org-unit-users` | OU membership | Member added/removed, role changed |

> **Note on document structure:** auth-gateway uses the `go-core-stack/core/table` package. Each document has a `_id` field mapped from the struct's key type. Entry fields are stored at the document root alongside `_id`.

## Tenants Collection

### Schema

```go
// Key — stored as _id in MongoDB
type TenantKey struct {
    Name string `bson:"name,omitempty"` // Tenant identifier (also Keycloak realm name)
}

type TenantEntry struct {
    Type       AccountType             `bson:"type,omitempty"`       // 0=Unknown, 1=Company, 2=Personal
    Config     *TenantConfig           `bson:"config,omitempty"`     // Tenant configuration
    KCStatus   *TenantKCStatus         `bson:"kcStatus,omitempty"`   // Keycloak realm status
    RoleStatus *TenantRoleStatus       `bson:"roleStatus,omitempty"` // Role sync status
    AdminStatus *TenantAdminStatus     `bson:"adminStatus,omitempty"`// Admin user status
    AuthClient *TenantAuthClientStatus `bson:"authClient,omitempty"` // Auth client status
}

type TenantConfig struct {
    DispName     string           `bson:"dispName,omitempty"`     // Display name
    Desc         string           `bson:"desc,omitempty"`         // Description
    Addr         *Address         `bson:"addr,omitempty"`         // Registered address
    Contact      *Contact         `bson:"contact,omitempty"`      // Billing contact
    DefaultAdmin *UserCredentials `bson:"defaultAdmin,omitempty"` // Default admin credentials (encrypted)
    Info         *TaxInfo         `bson:"info,omitempty"`         // Tax information
    IsRoot       bool             `bson:"isRoot,omitempty"`       // Root tenant flag
}

type TenantKCStatus struct {
    UpdateTime int64  `bson:"updateTime,omitempty"` // Realm provisioned timestamp
    RealmName  string `bson:"realmName,omitempty"`  // Keycloak realm name
}

type TenantAuthClientStatus struct {
    UpdateTime int64  `bson:"updateTime,omitempty"` // Auth client created timestamp
    ClientId   string `bson:"clientID,omitempty"`   // Keycloak client ID
}

type TenantRoleStatus struct {
    UpdateTime int64 `bson:"updateTime,omitempty"` // Roles synced timestamp
}

type TenantAdminStatus struct {
    UpdateTime int64  `bson:"updateTime,omitempty"` // Admin created timestamp
    Admin      string `bson:"admin,omitempty"`      // Default admin user ID
}
```

### Key Fields to Watch

| Field | Event Meaning |
|-------|---------------|
| `kcStatus.updateTime` | Non-zero = Keycloak realm provisioned |
| `authClient.updateTime` | Non-zero = Auth client configured |
| `adminStatus.updateTime` | Non-zero = Default admin created |
| `roleStatus.updateTime` | Non-zero = Roles synced |

All four status timestamps being non-zero indicates tenant provisioning is complete.

### Example: Watch for Provisioning Complete

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "operationType": "update",
        "updateDescription.updatedFields.kcStatus.updateTime": bson.M{"$exists": true},
    }}},
}
```

### Example: Watch for All Provisioning Steps

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "operationType": "update",
        "$or": []bson.M{
            {"updateDescription.updatedFields.kcStatus.updateTime": bson.M{"$exists": true}},
            {"updateDescription.updatedFields.authClient.updateTime": bson.M{"$exists": true}},
            {"updateDescription.updatedFields.adminStatus.updateTime": bson.M{"$exists": true}},
            {"updateDescription.updatedFields.roleStatus.updateTime": bson.M{"$exists": true}},
        },
    }}},
}
```

## Users Collection

### Schema

```go
// Key — stored as _id in MongoDB
type UserKey struct {
    Tenant   string `bson:"tenant,omitempty"`   // Tenant identifier
    Username string `bson:"username,omitempty"` // Username
}

type UserEntry struct {
    Key        *UserKey            `bson:"key,omitempty"`        // Reference back to key
    Created    int64               `bson:"created,omitempty"`    // Creation timestamp
    Updated    int64               `bson:"updated,omitempty"`    // Last update timestamp
    LastAccess int64               `bson:"lastAccess,omitempty"` // Last access timestamp
    Info       *UserInfo           `bson:"info,omitempty"`       // User profile info
    Password   *UserTempPassword   `bson:"password,omitempty"`   // Temp password (encrypted)
    Disabled   *bool               `bson:"disabled,omitempty"`   // User disabled flag
    Deleted    *bool               `bson:"deleted,omitempty"`    // User soft-deleted flag
    KCStatus   *UserKeycloakStatus `bson:"kcStatus,omitempty"`   // Keycloak sync status
    RealmRoles *[]string           `bson:"realmRoles,omitempty"` // Assigned realm roles
}

type UserInfo struct {
    FirstName string `bson:"firstName,omitempty"`
    LastName  string `bson:"lastName,omitempty"`
    Email     string `bson:"email,omitempty"`
}

type UserKeycloakStatus struct {
    Updated  int64 `bson:"updated,omitempty"`  // KC sync timestamp
    Disabled *bool `bson:"disabled,omitempty"` // KC-side disabled state
}
```

### Key Fields to Watch

| Field | Event Meaning |
|-------|---------------|
| `disabled` | `true` = User disabled, `false` = User enabled |
| `deleted` | `true` = User soft-deleted |
| `realmRoles` | Role assignment changed |
| `kcStatus.disabled` | Keycloak-side disabled state |
| (delete event) | User permanently deleted |

### Example: Watch for User State Changes

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "$or": []bson.M{
            {"operationType": "delete"},
            {
                "operationType": "update",
                "updateDescription.updatedFields.disabled": bson.M{"$exists": true},
            },
        },
        "documentKey._id.tenant": tenantID,
    }}},
}
```

### Example: Watch for Role Changes

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "operationType":          "update",
        "documentKey._id.tenant": tenantID,
        "updateDescription.updatedFields.realmRoles": bson.M{"$exists": true},
    }}},
}
```

## API Keys Collection

### Schema

```go
// Key — stored as _id in MongoDB
type ApiKeyId struct {
    Id string `bson:"id,omitempty"` // API Key ID (public identifier)
}

type ApiKeyEntry struct {
    Key      ApiKeyId       `bson:"key"`                // Reference back to key
    Secret   *ApiKeySecret  `bson:"secret,omitempty"`   // Encrypted HMAC secret
    UserInfo *ApiKeyUserInfo `bson:"userInfo,omitempty"` // Owning user
    Created  int64          `bson:"created,omitempty"`  // Creation timestamp
    LastUsed int64          `bson:"lastUsed,omitempty"` // Last used timestamp
    Config   *ApiKeyConfig  `bson:"config,omitempty"`   // Key configuration
}

type ApiKeyUserInfo struct {
    Tenant   string `bson:"tenant,omitempty"`   // Tenant the user belongs to
    Username string `bson:"username,omitempty"` // Username who owns the key
}

type ApiKeyConfig struct {
    Name       string `bson:"name,omitempty"`       // Display name
    ExpireAt   int64  `bson:"expireAt,omitempty"`   // Expiration timestamp (0 = no expiry)
    IsDisabled *bool  `bson:"isDisabled,omitempty"` // Disabled flag
}
```

### Key Fields to Watch

| Field | Event Meaning |
|-------|---------------|
| `config.isDisabled` | `true` = Key disabled |
| `config.expireAt` | Expiration timestamp (check against current time) |
| (delete event) | Key permanently deleted |

### Example: Watch for API Key Revocation

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "$or": []bson.M{
            {"operationType": "delete"},
            {
                "operationType": "update",
                "updateDescription.updatedFields.config.isDisabled": true,
            },
        },
        "documentKey._id.id": keyID,
    }}},
}
```

### Example: Watch for API Key Changes by Tenant

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "operationType": bson.M{"$in": []string{"update", "delete"}},
        "fullDocument.userInfo.tenant": tenantID,
    }}},
}
opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
```

## Org Units Collection

### Schema

```go
// Key — stored as _id in MongoDB
type OrgUnitKey struct {
    ID string `bson:"id,omitempty"` // Org unit identifier
}

type OrgUnitEntry struct {
    Key       *OrgUnitKey `bson:"key,omitempty"`       // Reference back to key
    Name      string      `bson:"name,omitempty"`      // Display name
    Desc      string      `bson:"desc,omitempty"`      // Description
    Created   int64       `bson:"created,omitempty"`   // Creation timestamp
    CreatedBy string      `bson:"createdBy,omitempty"` // Creator username
    Tenant    string      `bson:"tenant,omitempty"`    // Owning tenant
}
```

### Key Fields to Watch

| Field | Event Meaning |
|-------|---------------|
| (insert event) | New org unit created |
| (delete event) | Org unit deleted |
| `name` | Org unit renamed |

### Example: Watch for Org Unit Changes

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "operationType": bson.M{"$in": []string{"insert", "update", "delete"}},
        "fullDocument.tenant": tenantID,
    }}},
}
opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
```

## Org Unit Users Collection

### Schema

```go
// Key — stored as _id in MongoDB
type OrgUnitUserKey struct {
    Tenant    string `bson:"tenant,omitempty"`    // Tenant identifier
    Username  string `bson:"username,omitempty"`  // Username
    OrgUnitId string `bson:"orgUnitId,omitempty"` // Org unit identifier
}

type OrgUnitUser struct {
    Key       *OrgUnitUserKey `bson:"key,omitempty"`       // Reference back to key
    Created   int64           `bson:"created,omitempty"`   // Creation timestamp
    CreatedBy string          `bson:"createdBy,omitempty"` // Creator username
    Role      string          `bson:"role,omitempty"`      // Role: "admin", "auditor", "default"
}
```

### Key Fields to Watch

| Field | Event Meaning |
|-------|---------------|
| (insert event) | Member added to org unit |
| (delete event) | Member removed from org unit |
| `role` | Member role changed |

### Example: Watch for Membership Changes

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "operationType": bson.M{"$in": []string{"insert", "update", "delete"}},
        "documentKey._id.tenant": tenantID,
    }}},
}
```

### Example: Watch for Role Changes in an Org Unit

```go
pipeline := mongo.Pipeline{
    {{Key: "$match", Value: bson.M{
        "operationType": "update",
        "documentKey._id.orgUnitId": orgUnitID,
        "updateDescription.updatedFields.role": bson.M{"$exists": true},
    }}},
}
```

## Index Reference

These indexes exist for query optimization. Change stream pipelines that filter on indexed fields benefit from better performance.

```javascript
// tenants — keyed by name
db.tenants.getIndexes()
// Primary: { "_id.name": 1 }

// users — keyed by tenant + username
db.users.getIndexes()
// Primary: { "_id.tenant": 1, "_id.username": 1 }
// Secondary: { "key.tenant": 1, "info.email": 1 }

// api-keys — keyed by key ID
db["api-keys"].getIndexes()
// Primary: { "_id.id": 1 }
// Secondary: { "userInfo.tenant": 1, "userInfo.username": 1 }

// org-units — keyed by ID
db["org-units"].getIndexes()
// Primary: { "_id.id": 1 }
// Secondary: { "tenant": 1 }

// org-unit-users — keyed by tenant + username + orgUnitId
db["org-unit-users"].getIndexes()
// Primary: { "_id.tenant": 1, "_id.username": 1, "_id.orgUnitId": 1 }
// Secondary: { "key.orgUnitId": 1 }
```

## Related

- [Change Stream Patterns](change-streams.md) — How to set up and consume change streams
