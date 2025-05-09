// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package keycloak

import (
	"net/http"
	"os"

	"github.com/Nerzal/gocloak/v13"
)

const (
	// Environment variable for keycloak admin username
	keycloakAdminEnv = "KEYCLOAK_ADMIN"

	// default keycloak admin username
	defaultKeycloakAdminUser = "admin"

	// Environment vailable for keycloak admin password
	keycloakPassEnv = "KEYCLOAK_PASSWORD"

	// default keycloak admin password
	defaultKeycloakAdminPassword = "password"
)

// gets Keycloak admin username from the environment variable
func getKeycloakUsername() string {
	val, found := os.LookupEnv(keycloakAdminEnv)
	if !found {
		// return default value if not found
		return defaultKeycloakAdminUser
	}
	return val
}

// gets Keycloak admin password from the environment variable
func getKeycloakPassword() string {
	val, found := os.LookupEnv(keycloakPassEnv)
	if !found {
		// return default value if not found
		return defaultKeycloakAdminPassword
	}
	return val
}

func IsConflictError(err error) bool {
	if apiErr, ok := err.(*gocloak.APIError); ok {
		if apiErr.Code == http.StatusConflict {
			return true
		}
	}
	return false
}
