// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"log"

	"github.com/go-core-stack/core/utils"
)

var encryptor utils.IOEncryptor

func init() {
	var err error
	encryptor, err = utils.InitializeEncryptor("AuthTableInfra", "mydummykey")
	if err != nil {
		log.Panicf("Failed to initialize encryptor: %s", err)
	}

}
