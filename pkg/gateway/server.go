// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"fmt"
	"log"
	"net/http"

	"github.com/go-core-stack/auth/hash"

	common "github.com/Prabhjot-Sethi/core/auth"
	"github.com/Prabhjot-Sethi/core/errors"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/auth"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

type gateway struct {
	http.Handler
	server    http.Handler
	validator hash.Validator
	apiKeys   *table.ApiKeyTable
}

func (s *gateway) AuthenticateRequest(r *http.Request) (*common.AuthInfo, error) {
	var authInfo *common.AuthInfo
	keyId := s.validator.GetKeyId(r)
	// check if an API key is used
	if keyId != "" {
		key := &table.ApiKeyId{
			Id: keyId,
		}
		entry, err := s.apiKeys.Find(r.Context(), key)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.Wrapf(errors.Unauthorized, "Invalid Api Key")
			}
			return nil, errors.Wrapf(errors.Unauthorized, "Failed to perform auth at the moment")
		}
		if entry.UserInfo == nil {
			return nil, errors.Wrapf(errors.Unauthorized, "user not available")
		}
		_, err = s.validator.Validate(r, entry.Secret.Value)
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "Invalid Signature")
		}
		// TODO(prabhjot) check if user is disabled
		authInfo = &common.AuthInfo{
			Realm:    entry.UserInfo.Tenant,
			UserName: entry.UserInfo.Username,
		}
	} else {
		var err error
		authInfo, err = auth.AuthenticateRequest(r, "")
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "failed to authenticate incoming request: %s", err)
		}
	}

	// Add Auth info for the backend server
	err := common.SetAuthInfoHeader(r, authInfo)
	if err != nil {
		return nil, errors.Wrapf(errors.Unauthorized, "Failed to process auth information: %s", err)
	}
	return authInfo, nil
}

func (s *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, err := s.AuthenticateRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %s", err), http.StatusUnauthorized)
		return
	}
	s.server.ServeHTTP(w, r)
}

// Create a new Auth Gateway server, wrapped around
// locally hosted insecure server
func New(insecure http.Handler) http.Handler {
	apiKeys, err := table.GetApiKeyTable()
	if err != nil {
		log.Panicf("unable to get api keys table: %s", err)
	}
	return &gateway{
		server:    insecure,
		validator: hash.NewValidator(300), // Allow an API request to be valid for 5 mins, to handle offer if any
		apiKeys:   apiKeys,
	}
}
