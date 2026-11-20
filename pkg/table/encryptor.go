// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"os"

	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"
)

const (
	// Environment variable for encryptor key
	EncryptorKeyEnvVar = "ENCRYPTOR_KEY"

	// encryptorProvider names this package's encryptor in go-core-stack/core,
	// which registers each provider once per process
	encryptorProvider = "AuthTableInfra"
)

var (
	encryptor utils.IOEncryptor

	// encryptorErr holds why the encryptor could not be set up. It is
	// kept rather than raised in init, so that packages importing this
	// one still load in tests; the process checks it before any table
	// is used (CheckEncryptor).
	encryptorErr error
)

func init() {
	encryptor, encryptorErr = newEncryptor(encryptorProvider, os.LookupEnv)
}

// newEncryptor builds the encryptor for the stored secrets from
// ENCRYPTOR_KEY, registered under provider. There is no built-in
// fallback: a key written in the source would protect nothing, so an
// unset or invalid key is an error.
func newEncryptor(provider string, lookup func(string) (string, bool)) (utils.IOEncryptor, error) {
	key, ok := lookup(EncryptorKeyEnvVar)
	if !ok {
		return nil, errors.Wrapf(errors.InvalidArgument, "%s is not set", EncryptorKeyEnvVar)
	}
	enc, err := utils.InitializeEncryptor(provider, key)
	if err != nil {
		return nil, errors.WrapErrf(errors.InvalidArgument, err, "%s is not a usable key", EncryptorKeyEnvVar)
	}
	return enc, nil
}

// CheckEncryptor reports why the stored secrets cannot be encrypted, or
// nil when they can. The process calls it before using any table and
// refuses to start on an error.
func CheckEncryptor() error {
	return encryptorErr
}
