// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
)

var userPreferenceTable *UserPreferenceTable

type UserPreferenceEntry struct {
	Key       *UserKey `bson:"key,omitempty"`
	DefaultOU *string  `bson:"defaultOU,omitempty"`
}

type UserPreferenceTable struct {
	table.Table[UserKey, UserPreferenceEntry]
	col db.StoreCollection
}

func GetUserPreferenceTable() (*UserPreferenceTable, error) {
	if userPreferenceTable != nil {
		return userPreferenceTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "user preference table not found")
}

func LocateUserPreferenceTable(client db.StoreClient) (*UserPreferenceTable, error) {
	if userPreferenceTable != nil {
		return userPreferenceTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, UserCollectionName)

	tbl := &UserPreferenceTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	userPreferenceTable = tbl

	return userPreferenceTable, nil
}
