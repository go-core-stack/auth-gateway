// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"context"

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

	return t.FindMany(ctx, filter)
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
