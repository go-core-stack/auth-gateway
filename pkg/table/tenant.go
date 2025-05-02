package table

import "github.com/Prabhjot-Sethi/core/db"

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
}

type TenantEntry struct {
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
