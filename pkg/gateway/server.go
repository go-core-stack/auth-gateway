// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-core-stack/auth/hash"

	common "github.com/Prabhjot-Sethi/core/auth"
	"github.com/Prabhjot-Sethi/core/errors"
	"github.com/Prabhjot-Sethi/core/utils"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/auth"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
)

type gateway struct {
	http.Handler
	server    http.Handler
	validator hash.Validator
	apiKeys   *table.ApiKeyTable
	userTbl   *table.UserTable
}

func (s *gateway) AuthenticateRequest(r *http.Request) (*common.AuthInfo, error) {
	var authInfo *common.AuthInfo
	var user *table.UserEntry
	var err error
	now := time.Now().Unix()
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
		if entry.Config.ExpireAt != 0 && entry.Config.ExpireAt < now {
			return nil, errors.Wrapf(errors.Unauthorized, "Api Key is %s expired", keyId)
		}
		_, err = s.validator.Validate(r, entry.Secret.Value)
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "Invalid Signature")
		}

		uKey := &table.UserKey{
			Tenant:   entry.UserInfo.Tenant,
			Username: entry.UserInfo.Username,
		}
		user, err = s.userTbl.Find(r.Context(), uKey)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.Wrapf(errors.Unauthorized, "User %s not found in tenant %s", entry.UserInfo.Username, entry.UserInfo.Tenant)
			}
			log.Printf("Failed to find user %s in tenant %s: %s", entry.UserInfo.Username, entry.UserInfo.Tenant, err)
			return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
		}

		authInfo = &common.AuthInfo{
			Realm:     user.Key.Tenant,
			UserName:  user.Key.Username,
			Email:     user.Info.Email,
			FirstName: user.Info.FirstName,
			LastName:  user.Info.LastName,
			FullName:  user.Info.FirstName + " " + user.Info.LastName,
		}

		// trigger an update to lastUsed timestamp for ApiKey
		if entry.LastUsed == 0 || (entry.LastUsed+60) <= now {
			update := &table.ApiKeyEntry{
				Key: table.ApiKeyId{
					Id: keyId,
				},
				LastUsed: now,
			}
			err = s.apiKeys.Update(r.Context(), &update.Key, update)
			if err != nil {
				log.Printf("Failed to update last access for user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
			}
		}
	} else {
		var err error
		authInfo, err = auth.AuthenticateRequest(r, "")
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "failed to authenticate incoming request: %s", err)
		}

		uKey := &table.UserKey{
			Tenant:   authInfo.Realm,
			Username: authInfo.UserName,
		}
		user, err = s.userTbl.Find(r.Context(), uKey)
		if err != nil {
			if !errors.IsNotFound(err) {
				log.Printf("Failed to find user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
				return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
			}
			// locate a new user entry, to handle SSO created users
			update := &table.UserEntry{
				Key: &table.UserKey{
					Tenant:   authInfo.Realm,
					Username: authInfo.UserName,
				},
				Created: now,
				Updated: now,
				Info: &table.UserInfo{
					Email:     authInfo.Email,
					FirstName: authInfo.FirstName,
					LastName:  authInfo.LastName,
				},
			}
			err := s.userTbl.Locate(r.Context(), update.Key, update)
			if err != nil {
				log.Printf("Failed to locate user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
				return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
			}
			user = update
		}

		// trigger an update to lastAccess timestamp
		if user.LastAccess == 0 || (user.LastAccess+60) <= now {
			update := &table.UserEntry{
				Key: &table.UserKey{
					Tenant:   authInfo.Realm,
					Username: authInfo.UserName,
				},
				LastAccess: now,
			}
			err = s.userTbl.Update(r.Context(), update.Key, update)
			if err != nil {
				log.Printf("Failed to update last access for user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
			}
		}
	}

	if utils.PBool(user.Disabled) {
		return nil, errors.Wrapf(errors.Unauthorized, "User %s is disabled in tenant %s", authInfo.UserName, authInfo.Realm)
	}

	// Add Auth info for the backend server
	err = common.SetAuthInfoHeader(r, authInfo)
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

	userTbl, err := table.GetUserTable()
	if err != nil {
		log.Panicf("unable to get user table: %s", err)
	}
	return &gateway{
		server:    insecure,
		validator: hash.NewValidator(300), // Allow an API request to be valid for 5 mins, to handle offer if any
		apiKeys:   apiKeys,
		userTbl:   userTbl,
	}
}
