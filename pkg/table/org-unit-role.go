// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Suryanshu Gupta <suryanshu.gupta@kluisz.ai>

package table

import (
	"context"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
	"go.mongodb.org/mongo-driver/bson"
)

var orgUnitRoleTable *OrgUnitRoleTable

// OrgUnitRoleKey defines the key structure for roles
type OrgUnitRoleKey struct {
	// Tenant name this role belongs to
	Tenant string `bson:"tenant,omitempty"`
	// Org unit ID this role is scoped to
	OrgUnitId string `bson:"orgUnitId,omitempty"`
	// Role name, unique within the org unit
	Name string `bson:"name,omitempty"`
}

// ResourceMatchCriteria defines allowed values for resource matching criteria
type ResourceMatchCriteria string

const (
	ResourceMatchCriteriaAny    ResourceMatchCriteria = "any"
	ResourceMatchCriteriaExact  ResourceMatchCriteria = "exact"
	ResourceMatchCriteriaPrefix ResourceMatchCriteria = "prefix"
	ResourceMatchCriteriaSuffix ResourceMatchCriteria = "suffix"
	ResourceMatchCriteriaRegex  ResourceMatchCriteria = "regex"
)

// ResourceMatch defines matching criteria for resource-based permissions
type ResourceMatch struct {
	// Matching criteria type
	Criteria ResourceMatchCriteria `bson:"criteria,omitempty"`
	// The matching key/pattern based on criteria
	Key string `bson:"key,omitempty"`
}

// RolePermissionAction defines allowed values for role permission actions
type RolePermissionAction string

const (
	RolePermissionActionDeny  RolePermissionAction = "Deny"
	RolePermissionActionAllow RolePermissionAction = "Allow"
	RolePermissionActionLog   RolePermissionAction = "Log"
)

// RolePermission defines individual permission for a resource
type RolePermission struct {
	// Resource name the permission applies to
	Resource string `bson:"resource,omitempty"`
	// Resource matching criteria (optional, defaults to wildcard with key="*")
	Match *ResourceMatch `bson:"match,omitempty"`
	// List of allowed verbs/actions for this resource (supports "*" for all verbs)
	Verbs []string `bson:"verbs,omitempty"`
	// Action type: Allow or Deny (Deny takes precedence over Allow)
	Action RolePermissionAction `bson:"action,omitempty"`
}

// OrgUnitRole defines a role within an organization unit
type OrgUnitRole struct {
	// Role key
	Key *OrgUnitRoleKey `bson:"key,omitempty"`
	// Description explaining the purpose of this role
	Description string `bson:"description,omitempty"`
	// List of permissions granted by this role
	Permissions []*RolePermission `bson:"permissions,omitempty"`
	// Created timestamp
	Created int64 `bson:"created,omitempty"`
	// User who created this role
	CreatedBy string `bson:"createdBy,omitempty"`
	// Last updated timestamp
	Updated int64 `bson:"updated,omitempty"`
	// User who last updated this role
	UpdatedBy string `bson:"updatedBy,omitempty"`
	// Whether this role has been soft-deleted
	IsDeleted *bool `bson:"isDeleted,omitempty"`
}

// OrgUnitRoleTable manages roles for organization units
type OrgUnitRoleTable struct {
	table.Table[OrgUnitRoleKey, OrgUnitRole]
	col db.StoreCollection
}

// GetByOrgUnit retrieves all roles for a specific organization unit
func (t *OrgUnitRoleTable) GetByOrgUnit(ctx context.Context, tenant, orgUnitId string, offset, limit int32) ([]*OrgUnitRole, error) {
	filter := bson.M{
		"key.tenant":    tenant,
		"key.orgUnitId": orgUnitId,
		"isDeleted":     bson.M{"$ne": true}, // Exclude deleted roles
	}

	list, err := t.FindMany(ctx, filter, offset, limit)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// CountByOrgUnit counts active roles for a specific organization unit
func (t *OrgUnitRoleTable) CountByOrgUnit(ctx context.Context, tenant, orgUnitId string) (int32, error) {
	filter := bson.M{
		"key.tenant":    tenant,
		"key.orgUnitId": orgUnitId,
		"isDeleted":     bson.M{"$ne": true}, // Exclude deleted roles
	}
	count, err := t.col.Count(ctx, filter)
	return int32(count), err
}

// GetByTenant retrieves all roles for a tenant across all org units
func (t *OrgUnitRoleTable) GetByTenant(ctx context.Context, tenant string, offset, limit int32) ([]*OrgUnitRole, error) {
	filter := bson.M{
		"key.tenant": tenant,
		"isDeleted":  bson.M{"$ne": true}, // Exclude deleted roles
	}

	list, err := t.FindMany(ctx, filter, offset, limit)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// GetOrgUnitRoleTable returns the global role table instance
func GetOrgUnitRoleTable() (*OrgUnitRoleTable, error) {
	if orgUnitRoleTable != nil {
		return orgUnitRoleTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "org unit role table not found")
}

// LocateOrgUnitRoleTable initializes and returns the role table
func LocateOrgUnitRoleTable(client db.StoreClient) (*OrgUnitRoleTable, error) {
	if orgUnitRoleTable != nil {
		return orgUnitRoleTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, OrgUnitRoleCollectionName)
	tbl := &OrgUnitRoleTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	orgUnitRoleTable = tbl

	return orgUnitRoleTable, nil
}
