// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package keycloak

import "os"

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

func getKeycloakUsername() string {
	val, found := os.LookupEnv(keycloakAdminEnv)
	if !found {
		// return default value if not found
		return defaultKeycloakAdminUser
	}
	return val
}

func getKeyclaokPassword() string {
	val, found := os.LookupEnv(keycloakPassEnv)
	if !found {
		// return default value if not found
		return defaultKeycloakAdminPassword
	}
	return val
}
