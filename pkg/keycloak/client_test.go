// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package keycloak

import (
	"context"
	"testing"
	"time"
)

func Test_KeyCloakConnection(t *testing.T) {
	// ensure setting up lower expiry time for testing purpose
	tokenExpirySafeGuard = 60

	client, err := New("http://localhost:8080")
	if err != nil {
		t.Errorf("failed to create a keycloak client with provided config: %s", err)
		return
	}
	firsttoken, err := client.GetAccessToken()
	if err != nil {
		t.Errorf("failed to the get the relevant token for the client: %s", err)
		return
	}

	time.Sleep(3 * time.Second)
	lastToken, err := client.GetAccessToken()
	if err != nil {
		t.Errorf("failed to the get the relevant token for the client: %s", err)
		return
	}

	if firsttoken == lastToken {
		t.Errorf("failed to verify the token refresh")
	}

	err = client.Logout(context.Background())
	if err != nil {
		t.Errorf("failed to logout the existing session with keycloak: %s", err)
		return
	}
}
