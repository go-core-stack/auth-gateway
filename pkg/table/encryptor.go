// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"log"
	"os"

	"github.com/go-core-stack/core/utils"
)

const (
	// Environment variable for encryptor key
	EncryptorKeyEnvVar = "ENCRYPTOR_KEY"

	// default value for encryptor key if not provided
	// as part of environment
	DefaultEncryptorKey = "MySuperSecretKey"
)

var encryptor utils.IOEncryptor

func init() {
	var err error
	key, ok := os.LookupEnv(EncryptorKeyEnvVar)
	if !ok {
		log.Printf("Warning: Encryptor Key not configured, switching to default key")
		key = DefaultEncryptorKey
	}
	encryptor, err = utils.InitializeEncryptor("AuthTableInfra", key)
	if err != nil {
		log.Panicf("Failed to initialize encryptor: %s", err)
	}

}
