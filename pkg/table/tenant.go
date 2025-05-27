// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"go.mongodb.org/mongo-driver/bson"

	"github.com/Prabhjot-Sethi/core/db"
	"github.com/Prabhjot-Sethi/core/errors"
	"github.com/Prabhjot-Sethi/core/table"
	"github.com/Prabhjot-Sethi/core/utils"
)

var tenantTable *TenantTable
var encryptor utils.IOEncryptor

type TenantKey struct {
	// Name as a key for the tenant
	Name string `bson:"name,omitempty"`
}

type AccountType int32

const (
	UnknownAccount AccountType = iota
	CompanyAccount
	PersonalAccount
)

type Address struct {
	// Postal Code
	PostalCode string `bson:"postalCode,omitempty"`

	// Country Code
	Country string `bson:"country,omitempty"`

	// State / Province / Region / County
	State string `bson:"state,omitempty"`

	// City
	City string `bson:"city,omitempty"`

	// Address Line 1
	Addr1 string `bson:"addr1,omitempty"`

	// Address Line 2
	Addr2 string `bson:"addr2,omitempty"`

	// Address Line 3
	Addr3 string `bson:"addr3,omitempty"`

	// Name for which the address is
	Name string `bson:"name,omitempty"`
}

type TenantContact struct {
	// Contact Person - relevant only if address type is company
	Name string `bson:"contact,omitempty"`

	// Phone number
	Phone string `bson:"phone,omitempty"`

	// email address
	Email string `bson:"email,omitempty"`
}

type TenantInfo struct {
	// Tax ID, typically GST No / VAT Number / ABN / EIN number
	TaxID string `bson:"taxId,omitempty"`

	// Personal Tax ID, typicall PAN, Social security number etc.
	PTaxID string `bson:"pTaxId,omitempty"`
}

type UserCredentials struct {
	// User Id - username or email id using which user would login
	UserID string `bson:"userID,omitempty"`

	// Password - first time password for the user
	// this will be stored by cryptographically encoding
	Password string `bson:"password,omitempty"`
}

func (c *UserCredentials) MarshalBSON() ([]byte, error) {
	type UserCredentialsAlias UserCredentials
	pass, _ := encryptor.EncryptString(c.Password)
	raw := &UserCredentialsAlias{
		UserID:   c.UserID,
		Password: pass,
	}
	return bson.Marshal(raw)
}

func (c *UserCredentials) UnmarshalBSON(data []byte) error {
	type UserCredentialsAlias UserCredentials
	raw := &UserCredentialsAlias{}
	err := bson.Unmarshal(data, raw)
	if err != nil {
		return err
	}
	c.UserID = raw.UserID
	c.Password, _ = encryptor.DecryptString(raw.Password)
	return nil
}

type TenantConfig struct {
	// Display name for the tenant
	DispName string `bson:"dispName,omitempty"`

	// Descriptive text for the tenant
	Desc string `bson:"desc,omitempty"`

	// Registered Address of the tenant
	Addr *Address `bson:"addr,omitempty"`

	// Billing Contact for the tenant
	Contact *TenantContact `bson:"contact,omitempty"`

	// User ID of Default Admin for the tenant
	DefaultAdmin *UserCredentials `bson:"defaultAdmin,omitempty"`

	// additional tenant information, requirement based on
	// local laws
	Info *TenantInfo `bson:"info,omitempty"`

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

	var err error
	if encryptor == nil {
		encryptor, err = utils.InitializeEncryptor("TenantTable", "mydummykey")
		if err != nil {
			return nil, err
		}
	}

	col := client.GetCollection(AuthDatabaseName, TenantsCollectionName)

	tbl := &TenantTable{
		col: col,
	}

	err = tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	tenantTable = tbl

	return tenantTable, nil
}
