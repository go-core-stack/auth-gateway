// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
)

var tenantTable *TenantTable

type TenantKey struct {
	// Name as a key for the tenant
	Name string `bson:"name,omitempty"`
}

type TenantConfig struct {
	// Display name for the tenant
	DispName string `bson:"dispName,omitempty"`

	// Descriptive text for the tenant
	Desc string `bson:"desc,omitempty"`

	// Registered Address of the tenant
	Addr *Address `bson:"addr,omitempty"`

	// Billing Contact for the tenant
	Contact *Contact `bson:"contact,omitempty"`

	// User ID of Default Admin for the tenant
	DefaultAdmin *UserCredentials `bson:"defaultAdmin,omitempty"`

	// additional tenant information, requirement based on
	// local laws
	Info *TaxInfo `bson:"info,omitempty"`

	// is this tenant root tenant
	IsRoot bool `bson:"isRoot,omitempty"`
}

type TenantKCStatus struct {
	// time when last updated
	UpdateTime int64 `bson:"updateTime,omitempty"`

	// realm name which is configured in Keycloak
	RealmName string `bson:"realmName,omitempty"`
}

type TenantAuthClientStatus struct {
	// time when last updated
	UpdateTime int64 `bson:"updateTime,omitempty"`

	// Client ID which is configured in Keycloak
	ClientId string `bson:"clientID,omitempty"`
}

type TenantRoleStatus struct {
	// time when last updated
	UpdateTime int64 `bson:"updateTime,omitempty"`
}

type TenantAdminStatus struct {
	// time when last updated
	UpdateTime int64 `bson:"updateTime,omitempty"`

	// ID of the Default Tenant Admin
	Admin string `bson:"admin,omitempty"`
}

type TenantEntry struct {
	// Tenant Type Company / Personal
	Type AccountType `bson:"type,omitempty"`

	// Configuration provided for the tenant
	Config *TenantConfig `bson:"config,omitempty"`

	// keycloak Status - as per the setup manager
	KCStatus *TenantKCStatus `bson:"kcStatus,omitempty"`

	// Roles status - as per roles manager
	RoleStatus *TenantRoleStatus `bson:"roleStatus,omitempty"`

	// admin status
	AdminStatus *TenantAdminStatus `bson:"adminStatus,omitempty"`

	// auth client status
	AuthClient *TenantAuthClientStatus `bson:"authClient,omitempty"`
}

type TenantTable struct {
	table.Table[TenantKey, TenantEntry]
	col db.StoreCollection
}

func GetTenantTable() (*TenantTable, error) {
	if tenantTable != nil {
		return tenantTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "tenant table not found")
}

func LocateTenantTable(client db.StoreClient) (*TenantTable, error) {
	if tenantTable != nil {
		return tenantTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, TenantsCollectionName)
	tbl := &TenantTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	tenantTable = tbl

	return tenantTable, nil
}
