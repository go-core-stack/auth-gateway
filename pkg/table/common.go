// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import "go.mongodb.org/mongo-driver/bson"

type AccountType int32

const (
	UnknownAccount AccountType = iota
	CompanyAccount
	PersonalAccount
)

type TenancyType int32

const (
	DedicatedTenancy TenancyType = iota
	SharedTenancy
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

type Contact struct {
	// Contact Person - relevant only if address type is company
	Name string `bson:"contact,omitempty"`

	// Phone number
	Phone string `bson:"phone,omitempty"`

	// email address
	Email string `bson:"email,omitempty"`
}

type TaxInfo struct {
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
