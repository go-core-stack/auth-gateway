package table

import "github.com/Prabhjot-Sethi/core/db"

var tenantTable *TenantTable

type TenantKey struct {
	Name string `bson:"name,omitempty"`
}

type TenantEntry struct {
	Desc string `bson:"desc,omitempty"`
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
