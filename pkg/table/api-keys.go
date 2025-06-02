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

var apiKeyTable *ApiKeyTable

// ApiKeyId is the key for the API Key table.
type ApiKeyId struct {
	// API Key ID
	Id string `bson:"id,omitempty"`
}

type ApiKeyUserInfo struct {
	// Tenant to which user belongs
	Tenant string `bson:"tenant,omitempty"`

	// Username of the user who owns the API key
	Username string `bson:"username,omitempty"`
}

type ApiKeyConfig struct {
	// name of the api key, used for display purposes
	Name string `bson:"name,omitempty"`

	// ExpireAt is the timestamp when the API key will expire.
	ExpireAt int64 `bson:"expireAt,omitempty"`

	// IsDisabled indicates whether the API key is disabled.
	IsDisabled *bool `bson:"isDisabled,omitempty"`

	// eventually can contain more fields
	// like permissions, scopes, etc.
}

type ApiKeySecret struct {
	Value string `bson:"value,omitempty"`
}

func (s *ApiKeySecret) MarshalBSON() ([]byte, error) {
	type ApiKeySecretAlias ApiKeySecret
	encoded, _ := encryptor.EncryptString(s.Value)
	raw := &ApiKeySecretAlias{
		Value: encoded,
	}
	return bson.Marshal(raw)
}

func (s *ApiKeySecret) UnmarshalBSON(data []byte) error {
	type ApiKeySecretAlias ApiKeySecret
	raw := &ApiKeySecretAlias{}
	err := bson.Unmarshal(data, raw)
	if err != nil {
		return err
	}
	s.Value, _ = encryptor.DecryptString(raw.Value)
	return nil
}

type ApiKeyEntry struct {
	// ID of the API Key
	Key ApiKeyId `bson:"key"`

	// Secret is the actual secret key used for authentication.
	// It is typically a long random string that is
	// generated when the API key is created.
	// It should be kept secret and not exposed to the public.
	// It is used to authenticate the API key when making requests.
	Secret *ApiKeySecret `bson:"secret,omitempty"`

	// userinfo corresponding to this key,
	// if this field is nil, typically the key will
	// be considered invalid and no access will be
	// granted upon its usage
	UserInfo *ApiKeyUserInfo `bson:"userInfo,omitempty"`

	// created timestamp
	Created int64 `bson:"created,omitempty"`

	// last used timestamp
	LastUsed int64 `bson:"lastUsed,omitempty"`

	// config for the API key
	Config *ApiKeyConfig `bson:"config,omitempty"`
}

type ApiKeyTable struct {
	table.Table[ApiKeyId, ApiKeyEntry]
	col db.StoreCollection
}

type userFilter struct {
	// Tenant to which user belongs
	Tenant string `bson:"userInfo.tenant,omitempty"`

	// Username of the user who owns the API key
	Username string `bson:"userInfo.username,omitempty"`
}

func (t *ApiKeyTable) FindByUser(ctx context.Context, info *ApiKeyUserInfo) ([]*ApiKeyEntry, error) {
	filter := &userFilter{
		Tenant:   info.Tenant,
		Username: info.Username,
	}

	return t.FindMany(ctx, filter)
}

type userIdFilter struct {
	// Api Key Id
	Id string `bson:"key.id,omitempty"`

	// Tenant to which user belongs
	Tenant string `bson:"userInfo.tenant,omitempty"`

	// Username of the user who owns the API key
	Username string `bson:"userInfo.username,omitempty"`
}

func (t *ApiKeyTable) FindIdByUser(ctx context.Context, id string, info *ApiKeyUserInfo) (*ApiKeyEntry, error) {
	filter := &userIdFilter{
		Id:       id,
		Tenant:   info.Tenant,
		Username: info.Username,
	}

	list, err := t.FindMany(ctx, filter)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, errors.Wrapf(errors.NotFound, "Api Key not found")
	}
	return list[0], nil
}

func (t *ApiKeyTable) DeleteIdByUser(ctx context.Context, id string, info *ApiKeyUserInfo) error {
	filter := &userIdFilter{
		Id:       id,
		Tenant:   info.Tenant,
		Username: info.Username,
	}

	count, err := t.DeleteByFilter(ctx, filter)
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.Wrapf(errors.NotFound, "Api Key not found")
	}

	return nil
}

func GetApiKeyTable() (*ApiKeyTable, error) {
	if apiKeyTable != nil {
		return apiKeyTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "api-key table not found")
}

func LocateApiKeyTable(client db.StoreClient) (*ApiKeyTable, error) {
	if apiKeyTable != nil {
		return apiKeyTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, ApiKeyCollectionName)

	tbl := &ApiKeyTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	apiKeyTable = tbl

	return apiKeyTable, nil
}
