// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package auth

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"

	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/core/errors"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
)

// internal structure of auth Verifier
// typically maintained per keycloak realm
type authVerifier struct {
	verifier *oidc.IDTokenVerifier
}

type localAuthInfo struct {
	common.AuthInfo `json:",inline"`
	RealmAccess     struct {
		Roles []string `json:"roles,omitempty"`
	} `json:"realm_access,omitempty"`
}

// verify the bearer auth token and return claims
func (v *authVerifier) decode(tokenStr string) (*common.AuthInfo, error) {
	token, err := v.verifier.Verify(context.Background(), tokenStr)
	if err != nil {
		return nil, errors.Wrapf(errors.Unauthorized, "Failed to verify the provided token: %s", err)
	}

	info := &localAuthInfo{}
	err = token.Claims(info)
	if err != nil {
		return nil, errors.Wrapf(errors.Unauthorized, "Failed to decode token Claims: %s", err)
	}

	// TODO(prabhjot) we might need to handle this better instead of hard coding
	if info.Realm == "root" {
		// ensure isRoot flag is set in this scenario
		info.IsRoot = true
	}

	info.Roles = info.RealmAccess.Roles

	return &(info.AuthInfo), nil
}

type authManager struct {
	url      string
	client   *keycloak.Client
	clientId string
	mu       sync.RWMutex
	authMap  map[string]*authVerifier
}

var (
	authMgr *authManager
)

// gets verifier corresponding to given realm name
func (m *authManager) getVerifier(realm string) *authVerifier {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.authMap[realm]
	if !ok {
		return nil
	}
	return v
}

// locate a new verifier for given realm
// typically the consumer should first attempt to call a get
// as the lock held in get is read only allow multiple parallel
// executions in most used code path, upon its failure locate
// can be used as a fallback to ensure creation of new verifier
// while holding write lock
func (m *authManager) locateVerifier(realm string) *authVerifier {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.authMap[realm]
	if !ok {
		// get an insecure http client, assuming that we will always be
		// connecting to internal keycloak endpoint.
		// this needs to change if there is any change in the architecture
		// for the deployment of the system and supported capabilities
		insecureClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		clienCtx := oidc.ClientContext(context.Background(), insecureClient)
		uri := m.url + "/realms/" + realm
		log.Printf("got uri %s, for verifier", uri)
		// ensure that provider doesn't validate the issuer as we will
		// be validating it against local endpoint and there will always
		// be a issue mis-match otherwise
		provider, err := oidc.NewProvider(oidc.InsecureIssuerURLContext(clienCtx, uri), uri)
		if err != nil {
			log.Panicf("failed to create new auth verifier: %s", err)
		}
		v = &authVerifier{
			verifier: provider.Verifier(&oidc.Config{
				ClientID:        m.clientId,
				SkipIssuerCheck: true, // since we will be working with internal keycloak always,
			}),
		}
		m.authMap[realm] = v
	}
	return v
}

// Initialize authentication module, providing the constructs to validate
// token available in the incoming HTTP requests
func Initialize(url, clientId string) error {
	if authMgr != nil {
		return errors.Wrapf(errors.AlreadyExists, "Authentication module is already initialized")
	}

	authMgr = &authManager{
		url:      url,
		client:   keycloak.NewPublicClient(url),
		clientId: clientId,
		authMap:  make(map[string]*authVerifier),
	}

	return nil
}
