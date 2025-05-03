package table

import "github.com/Prabhjot-Sethi/core/db"

var tenantTable *TenantTable

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
	Admin string `bson:"admin,omitempty"`

	// additional tenant information, requirement based on
	// local laws
	Info *TenantInfo `bson:"info,omitempty"`
}

type TenantEntry struct {
	// Tenant Type Company / Personal
	Type AccountType `bson:"type,omitempty"`

	// Configuration provided for the tenant
	Config *TenantConfig `bson:"config,omitempty"`
}

type TenantTable struct {
	db.StoreCollectionTable[*TenantKey, *TenantEntry]
	col db.StoreCollection
}

func LocateTenantTable(client db.StoreClient) (*TenantTable, error) {
	if tenantTable != nil {
		return tenantTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, TenantsCollectionName)

	tenantTable := &TenantTable{
		StoreCollectionTable: db.StoreCollectionTable[*TenantKey, *TenantEntry]{
			Col: col,
		},
		col: col,
	}

	return tenantTable, nil
}
