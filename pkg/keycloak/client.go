// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package keycloak

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"

	"github.com/Prabhjot-Sethi/core/errors"
)

const (
	// Master realm name - typically named as master
	MasterRealmName = "master"

	// AdminClientID - client id to be used for creating Admin Client
	AdminClientID = "admin-cli"
)

var (
	// TokenExpiry safegaurd time ensures refreshing the token within
	// reasonable time ahead of actual expiry, in seconds
	tokenExpirySafeGuard = 10
)

type Client struct {
	// client cancel function
	cancel context.CancelFunc

	// gocloak lib handle
	gocloak.GoCloak

	// base url of the client
	url string

	// Realm where the user will be authenticated
	userRealm string

	// Client ID where user is being authenticated
	clientID string

	// token to be used for transaction with keycloak
	token *gocloak.JWT

	// mutex for token access
	tokenMu sync.RWMutex
}

// create a new keycloak client for given endpoint
// and credentials
func New(url string) (*Client, error) {
	client := &Client{
		GoCloak:   *(gocloak.NewClient(url)),
		userRealm: MasterRealmName,
		clientID:  AdminClientID,
		url:       url,
	}

	// perform adming login using the provided login credentials and user realm
	token, err := client.LoginAdmin(context.Background(), getKeycloakUsername(),
		getKeycloakPassword(), client.userRealm)
	if err != nil {
		return nil, err
	}

	client.token = token

	// starts the loop to keep the access token active all the time
	go client.refreshToken()

	return client, nil
}

// create a new keycloak client for given endpoint
// and user credentials
// This requires direct flow validations enabled, which
// typically is not considered secure and is not
// recommended for production scenarios, more to be used
// in development environment.
// where direct flow enablement needs to be done manually
func NewUserClient(url, realm, user, password string) (*Client, error) {
	client := &Client{
		GoCloak:   *(gocloak.NewClient(url)),
		userRealm: realm,
		clientID:  "controller",
		url:       url,
	}

	// perform adming login using the provided login credentials and user realm
	token, err := client.Login(context.Background(), client.clientID, "", client.userRealm, user, password)
	if err != nil {
		return nil, err
	}

	client.token = token

	// starts the loop to keep the access token active all the time
	go client.refreshToken()

	return client, nil
}

// Gets the current access token from the client
func (c *Client) GetAccessToken() (string, error) {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	if c.token != nil {
		return c.token.AccessToken, nil
	}
	return "", errors.Wrapf(errors.InvalidArgument, "no current active session")
}

func (c *Client) refreshToken() {
	var ctx context.Context
	ctx, c.cancel = context.WithCancel(context.Background())
	defer c.cancel()
	interval := max(c.token.ExpiresIn-tokenExpirySafeGuard, 1)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := func() error {
				c.tokenMu.Lock()
				defer c.tokenMu.Unlock()
				token, err := c.RefreshToken(context.Background(), c.token.RefreshToken, c.clientID, "", c.userRealm)
				if err != nil {
					// failed to refresh token
					log.Printf("failed to refresh the token, got error: %s", err)
					c.token = nil
					return err
				}
				c.token = token
				interval := max(c.token.ExpiresIn-tokenExpirySafeGuard, 1)
				ticker.Reset(time.Duration(interval) * time.Second)
				return nil
			}()
			if err != nil {
				// return from the for loop upon encountering an error
				return
			}
		}
	}
}

// Logout and Close the existing Keycloak Client and session
func (c *Client) Logout(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	err := c.GoCloak.Logout(ctx, c.clientID, "", c.userRealm, c.token.RefreshToken)
	if err != nil {
		return err
	}

	if c.cancel != nil {
		c.cancel()
	}
	c.token = nil

	return nil
}
