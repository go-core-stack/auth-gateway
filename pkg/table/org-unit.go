// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
)

var ouTable *OrgUnitTable

type OrgUnitKey struct {
	// id as a key for the tenant
	ID string `bson:"id,omitempty"`
}

type OrgUnitEntry struct {
	// Org Unit Key
	Key *OrgUnitKey `bson:"key,omitempty"`

	// display name of the Org unit
	Name string `bson:"name,omitempty"`

	// description for the Org unit
	Desc string `bson:"desc,omitempty"`

	// Created timestamp
	Created int64 `bson:"created,omitempty"`

	// created by
	CreatedBy string `bson:"createdBy,omitempty"`

	// Tenant this OU belongs to
	Tenant string `bson:"tenant,omitempty"`

	// Deleted is the unix timestamp when the OU was soft-deleted.
	// Zero value means the OU is active; omitted from MongoDB documents
	// when zero.
	Deleted int64 `bson:"deleted,omitempty"`
}

type OrgUnitTable struct {
	table.Table[OrgUnitKey, OrgUnitEntry]
	col db.StoreCollection
}

type tenantFilter struct {
	// Tenant to which Org Unit belongs
	Tenant string `bson:"tenant,omitempty"`

	// Org Unit ID if provided
	OuId string `bson:"key.id,omitempty"`
}

func (t *OrgUnitTable) FindByTenant(ctx context.Context, tenant, ouId string) ([]*OrgUnitEntry, error) {
	filter := &tenantFilter{
		Tenant: tenant,
		OuId:   ouId,
	}

	return t.FindMany(ctx, filter, 0, 0)
}

// ReconcilerGetAllKeys returns keys for all soft-deleted org-unit entries
// (deleted > 0). This overrides the generic Table.ReconcilerGetAllKeys to
// ensure the reconciler only bootstraps entries that are pending hard-delete.
func (t *OrgUnitTable) ReconcilerGetAllKeys() []any {
	type keyOnly struct {
		Key OrgUnitKey `bson:"_id,omitempty"`
	}

	filter := bson.M{"deleted": bson.M{"$gt": 0}}

	list := []keyOnly{}
	err := t.col.FindMany(context.Background(), filter, &list)
	if err != nil {
		log.Panicf("orgunit: failed to fetch deleted keys: %s", err)
	}

	keys := make([]any, 0, len(list))
	for _, k := range list {
		keys = append(keys, &k.Key)
	}
	return keys
}

func (t *OrgUnitTable) StartEventLogger() error {
	logger := db.NewEventLogger[OrgUnitKey, OrgUnitEntry](t.col, nil)
	return logger.Start(context.Background())
}

func GetOrgUnitTable() (*OrgUnitTable, error) {
	if ouTable != nil {
		return ouTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "org unit table not found")
}

func LocateOrgUnitTable(client db.StoreClient) (*OrgUnitTable, error) {
	if ouTable != nil {
		return ouTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, OrgUnitCollectionName)
	tbl := &OrgUnitTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	ouTable = tbl

	return ouTable, nil
}
