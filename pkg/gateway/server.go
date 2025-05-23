// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"fmt"
	"log"
	"net/http"

	common "github.com/Prabhjot-Sethi/core/auth"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/auth"
)

type gateway struct {
	http.Handler
	server http.Handler
}

func (s *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authInfo, err := auth.AuthenticateRequest(r, "")
	if err != nil {
		log.Printf("failed to authenticate incoming request: %s", err)
		http.Error(w, fmt.Sprintf("Authentication failed: %s", err), http.StatusUnauthorized)
		return
	}
	// Add Auth info for the backend server
	err = common.SetAuthInfoHeader(r, authInfo)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process auth information: %s", err), http.StatusInternalServerError)
		return
	}
	s.server.ServeHTTP(w, r)
}

// Create a new Auth Gateway server, wrapped around
// locally hosted insecure server
func New(insecure http.Handler) http.Handler {
	return &gateway{
		server: insecure,
	}
}
