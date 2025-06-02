// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/core/errors"
)

// returns realm information from the token, without performing
// the token validation. since the validation will be required
// to be vetted against a keycloak url which is realm specific
// get the details to perform the validation
func getRealmFromToken(token string) (string, error) {
	// jwt token consists of 3 parts separated by dot
	// part 1: Header - including information of Algorithm and Token Type
	// part 2: Token Payload
	// part 3: Signature - for validating the provided token
	tParts := strings.Split(token, ".")
	if len(tParts) != 3 {
		return "", errors.Wrapf(errors.InvalidArgument, "Invalid JWT Token")
	}

	// here we are only interested in the payload, and we would be
	// skipping the validation
	// perform base64 decode on the payload to get json message
	jsonData, err := base64.RawURLEncoding.DecodeString(tParts[1])
	if err != nil {
		return "", errors.Wrapf(errors.InvalidArgument, "Invalid JWT Token: %s", err)
	}

	info := &struct {
		Realm string `json:"realm,omitempty"`
	}{}
	err = json.Unmarshal(jsonData, info)
	if err != nil {
		return "", errors.Wrapf(errors.InvalidArgument, "Realm Info Get failed: %s", err)
	}

	return info.Realm, nil
}

// Authenticate the bearer token provided in the individual API
// request sent over to the controller
func AuthenticateToken(token string) (*common.AuthInfo, error) {
	realm, err := getRealmFromToken(token)
	if err != nil {
		return nil, err
	}

	verifier := authMgr.getVerifier(realm)
	if verifier == nil {
		verifier = authMgr.locateVerifier(realm)
	}

	return verifier.decode(token)
}

// Authenticate from the http Request handle directly
// Note: this step needs to happen before upgrading
// from http to websocket or any other protocol, allowing
// parsing of the provided headers.
//
// Auth Token typically is sent as part of the Authorization Header, but
// for websocket kind of connection it is typically not a supported
// mechanism, Thus this function also allows working with a token passed
// as part of the cookie. by default it will look for cookie name "AUTH_TOKEN",
// Unless it is overidden as part of the argument cookie, if empty it falls back
// to default cookie name
// priority order
// 1. Authorization Header
// 2. if no token found above, get from cookie
func AuthenticateRequest(req *http.Request, cookieName string) (*common.AuthInfo, error) {
	if req.Header == nil {
		return nil, errors.Wrapf(errors.Unauthorized, "No Auth Header found")
	}

	var token string
	value, ok := req.Header["Authorization"]
	if ok {
		if strings.HasPrefix(value[0], "Bearer ") {
			token = strings.TrimPrefix(value[0], "Bearer ")
		}
	} else {
		if cookieName == "" {
			// if empty fallback to default cookie name
			cookieName = "AUTH_TOKEN"
		}
		cookie, err := req.Cookie(cookieName)
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "No Auth Token found")
		}
		token = cookie.Value
	}

	return AuthenticateToken(token)
}
