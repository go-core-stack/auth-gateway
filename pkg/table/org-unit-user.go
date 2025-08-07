// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"context"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
	"go.mongodb.org/mongo-driver/bson"
)

var orgUnitUserTable *OrgUnitUserTable

type OrgUnitUserKey struct {
	// tenant name
	Tenant string `bson:"tenant,omitempty"`
	// user name
	Username string `bson:"username,omitempty"`
	// Org unit id
	OrgUnitId string `bson:"orgUnitId,omitempty"`
}

type OrgUnitUser struct {
	// org unit user key
	Key *OrgUnitUserKey `bson:"key,omitempty"`
	// created timestamp
	Created int64 `bson:"created,omitempty"`
	// created by
	CreatedBy string `bson:"createdBy,omitempty"`
	// Role assigned to the user in the org unit
	Role string `bson:"role,omitempty"`
}

type OrgUnitUserTable struct {
	table.Table[OrgUnitUserKey, OrgUnitUser]
	col db.StoreCollection
}

func (t *OrgUnitUserTable) GetByOrgUnitId(ctx context.Context, orgUnitId string, offset, limit int32) ([]*OrgUnitUser, error) {
	filter := bson.M{
		"key.orgUnitId": orgUnitId,
	}
	// TODO: Handle offset and limit
	list, err := t.FindMany(ctx, filter, offset, limit)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (t *OrgUnitUserTable) CountByOrgUnitId(ctx context.Context, orgUnitId string) (int32, error) {
	filter := bson.M{
		"key.orgUnitId": orgUnitId,
	}
	count, err := t.col.Count(ctx, filter)
	return int32(count), err
}

// GetByTenantUsernameAndOrgUnitId retrieves all org unit roles for a specific user within a tenant
// This method is used to check if a user has specific roles (like Admin or Auditor)
// in a org unit they belong to within their tenant. This is a step for us to implement RBAC
// beyond tenant-level.
func (t *OrgUnitUserTable) GetByTenantUsernameAndOrgUnitId(ctx context.Context, tenant, username, orgUnitId string) (*OrgUnitUser, error) {
	key := &OrgUnitUserKey{
		Tenant:    tenant,
		Username:  username,
		OrgUnitId: orgUnitId,
	}

	// Expecting only one match: one user in one org unit
	user, err := t.Find(ctx, key)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func GetOrgUnitUserTable() (*OrgUnitUserTable, error) {
	if orgUnitUserTable != nil {
		return orgUnitUserTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "users table not found")
}

func LocateOrgUnitUserTable(client db.StoreClient) (*OrgUnitUserTable, error) {
	if orgUnitUserTable != nil {
		return orgUnitUserTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, OrgUnitUserCollectionName)

	tbl := &OrgUnitUserTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	orgUnitUserTable = tbl

	return orgUnitUserTable, nil
}
