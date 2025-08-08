// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
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

func (t *OrgUnitUserTable) GetByUser(ctx context.Context, tenant, user string) ([]*OrgUnitUser, error) {
	filter := bson.M{
		"key.tenant":   tenant,
		"key.username": user,
	}

	list, err := t.FindMany(ctx, filter, 0, 0)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (t *OrgUnitUserTable) GetByOrgUnitId(ctx context.Context, orgUnitId string, offset, limit int32) ([]*OrgUnitUser, error) {
	filter := bson.M{
		"key.orgUnitId": orgUnitId,
	}

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

func (t *OrgUnitUserTable) StartEventLogger() error {
	logger := db.NewEventLogger[OrgUnitUserKey, OrgUnitUser](t.col, nil)
	return logger.Start(context.Background())
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
