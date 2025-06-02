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

var userTable *UserTable

type UserKey struct {
	Tenant   string `bson:"tenant,omitempty"`
	Username string `bson:"username,omitempty"`
}

type UserInfo struct {
	FirstName string `bson:"firstName,omitempty"`
	LastName  string `bson:"lastName,omitempty"`
	Email     string `bson:"email,omitempty"`
}

type UserTempPassword struct {
	Value string `bson:"val,omitempty"`
}

func (s *UserTempPassword) MarshalBSON() ([]byte, error) {
	type UserTempPasswordAlias UserTempPassword
	encoded, _ := encryptor.EncryptString(s.Value)
	raw := &UserTempPasswordAlias{
		Value: encoded,
	}
	return bson.Marshal(raw)
}

func (s *UserTempPassword) UnmarshalBSON(data []byte) error {
	type UserTempPasswordAlias UserTempPassword
	raw := &UserTempPasswordAlias{}
	err := bson.Unmarshal(data, raw)
	if err != nil {
		return err
	}
	s.Value, _ = encryptor.DecryptString(raw.Value)
	return nil
}

type UserKeycloakStatus struct {
	Updated  int64 `bson:"updated,omitempty"`
	Disabled *bool `bson:"disabled,omitempty"`
}

type UserEntry struct {
	Key        *UserKey            `bson:"key,omitempty"`
	Created    int64               `bson:"created,omitempty"`
	Updated    int64               `bson:"updated,omitempty"`
	LastAccess int64               `bson:"lastAccess,omitempty"`
	Info       *UserInfo           `bson:"info,omitempty"`
	Password   *UserTempPassword   `bson:"password,omitempty"`
	Disabled   *bool               `bson:"disabled,omitempty"`
	Deleted    *bool               `bson:"deleted,omitempty"`
	KCStatus   *UserKeycloakStatus `bson:"kcStatus,omitempty"`
}

type UserTable struct {
	table.Table[UserKey, UserEntry]
	col db.StoreCollection
}

func (t *UserTable) GetByTenant(ctx context.Context, tenant string, offset, limit int64) ([]*UserEntry, error) {
	filter := bson.M{
		"key.tenant": tenant,
	}
	// TODO: Handle offset and limit
	list, err := t.FindMany(ctx, filter)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (t *UserTable) CountByTenant(ctx context.Context, tenant string) (int64, error) {
	filter := bson.M{
		"key.tenant": tenant,
	}
	return t.col.Count(ctx, filter)
}

func GetUserTable() (*UserTable, error) {
	if userTable != nil {
		return userTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "users table not found")
}

func LocateUserTable(client db.StoreClient) (*UserTable, error) {
	if userTable != nil {
		return userTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, UserCollectionName)

	tbl := &UserTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	userTable = tbl

	return userTable, nil
}
