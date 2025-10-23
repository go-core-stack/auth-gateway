// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
)

var customerTable *CustomerTable

type CustomerKey struct {
	// Name or customer id as a key for the customer information
	Id string `bson:"id,omitempty"`
}

type CustomerConfig struct {
	// Customer Display Name
	Name string `bson:"name,omitempty"`

	// Descriptive text for the tenant
	Desc string `bson:"desc,omitempty"`

	// Registered Address of the customer
	Addr *Address `bson:"addr,omitempty"`

	// Billing Contact for the customer
	Contact *Contact `bson:"contact,omitempty"`

	// User ID of Default Admin for the customer
	DefaultAdmin *UserCredentials `bson:"defaultAdmin,omitempty"`

	// additional customer additional bill information,
	// requirement based on local laws
	Info *TaxInfo `bson:"taxInfo,omitempty"`
}

type CustomerEntry struct {
	// Customer Key
	Key CustomerKey `bson:"key,omitempty"`

	// Customer Type Company / Personal
	Type AccountType `bson:"type,omitempty"`

	// Customer Tenancy Type Dedicated / Shared
	Tenancy TenancyType `bson:"tenancy,omitempty"`

	// Tenant Name associated with the customer
	Tenant string `bson:"tenant,omitempty"`

	// is this customer is root customer
	IsRoot bool `bson:"isRoot,omitempty"`

	// Configuration provided for the customer
	Config CustomerConfig `bson:"config,omitempty"`

	// created by
	CreatedBy string `bson:"createdBy,omitempty"`

	// created at timestamp
	Created int64 `bson:"created,omitempty"`

	// updated at timestamp
	Updated int64 `bson:"updated,omitempty"`
}

type CustomerTable struct {
	table.Table[CustomerKey, CustomerEntry]
	col db.StoreCollection
}

func GetCustomerTable() (*CustomerTable, error) {
	if customerTable != nil {
		return customerTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "tenant table not found")
}

func LocateCustomerTable(client db.StoreClient) (*CustomerTable, error) {
	if customerTable != nil {
		return customerTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, TenantsCollectionName)
	tbl := &CustomerTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	customerTable = tbl

	return customerTable, nil
}
