// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
)

type Email struct {
	Id string `bson:"id,omitempty"`
}

type EmailVerificationEntry struct {
	Key       *Email `bson:"key,omitempty"`
	FirstName string `bson:"firstName,omitempty"`
	LastName  string `bson:"lastName,omitempty"`
	Otp       string `bson:"otp,omitempty"`
	Created   int64  `bson:"created,omitempty"`
}

type EmailVerificationTable struct {
	table.Table[Email, EmailVerificationEntry]
	col db.StoreCollection
}

var emailVerificationTable *EmailVerificationTable

func GetEmailVerificationTable() (*EmailVerificationTable, error) {
	if emailVerificationTable != nil {
		return emailVerificationTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "users table not found")
}

func LocateEmailVerificationTable(client db.StoreClient) (*EmailVerificationTable, error) {
	if emailVerificationTable != nil {
		return emailVerificationTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, EmailVerificationCollectionName)

	tbl := &EmailVerificationTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	emailVerificationTable = tbl

	return emailVerificationTable, nil
}
