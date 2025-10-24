// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package keycloak

import (
	"context"
	"crypto/tls"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-resty/resty/v2"

	"github.com/go-core-stack/core/errors"
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

	// isAdmin indicates if the client is admin client
	isAdmin bool
}

// create a new keycloak client for given endpoint
// and credentials
func New(url string) (*Client, error) {
	client := &Client{
		GoCloak:   *(gocloak.NewClient(url)),
		userRealm: MasterRealmName,
		clientID:  AdminClientID,
		url:       url,
		isAdmin:   true,
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
func NewUserClient(url, realm, user, password string, skipTlsVerify bool) (*Client, error) {
	client := &Client{
		GoCloak:   *(gocloak.NewClient(url)),
		userRealm: realm,
		clientID:  "controller",
		url:       url,
	}

	// most of the time clients are going to be external and will require
	// SSL Validation, and since we are using internal keycloak deployment
	// provide a construct to skip SSL verification
	// this will typically not required in production scenarios and will be
	// used mostly in development environments
	if skipTlsVerify {
		restyClient := client.RestyClient()

		// skip ssl verify as we are always going to connect to internal deployment
		// of keycloak
		restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
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

// create a new unauthenticated public keycloak client for given endpoint
// typically will be consumed by public authentication validators
//
// Public client is required only to be consumed by OIDC verifier for
// validating the provided token and usage is expected to be restricted
// to auth gateway internal use only
func NewPublicClient(url string) *Client {
	client := &Client{
		GoCloak: *(gocloak.NewClient(url)),
	}

	restyClient := client.RestyClient()
	// skip ssl verify as we are always going to connect to internal url of the keycloak
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	return client
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
					if c.isAdmin {
						// for admin client try to re-login
						// perform adming login using the provided login credentials and user realm
						token, err = c.LoginAdmin(context.Background(), getKeycloakUsername(),
							getKeycloakPassword(), c.userRealm)
						if err != nil {
							log.Panicf("failed to re-login admin client, got error: %s", err)
							return err
						}
					} else {
						c.token = nil
						return err
					}
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

func (c *Client) getAdminRealmURL(basePath, realm string, path ...string) string {
	path = append([]string{basePath, "admin", "realms", realm}, path...)
	return strings.Join(path, "/")
}

// sessionCount Contains count of number of session in domain
type sessionCount struct {
	Count int `json:"count,omitempty"`
}

// GetClientUserSessions returns user sessions associated with the client
func (c *Client) GetClientUserSessionsCount(ctx context.Context, token, realm, idOfClient string) (int, error) {
	var result sessionCount
	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.getAdminRealmURL(c.url, realm, "clients", idOfClient, "session-count"))
	if resp == nil || resp.IsError() || err != nil {
		return -1, err
	}

	return result.Count, nil
}

// CopyAuthenticationFlow duplicates the existing authentication flow
// into a new flow with the provided name
func (c *Client) CopyAuthenticationFlow(ctx context.Context, token, realm, src, dest string) error {
	data := &struct {
		NewName *string `json:"newName,omitempty"`
	}{
		NewName: gocloak.StringP(dest),
	}
	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetBody(data).
		Post(c.getAdminRealmURL(c.url, realm, "authentication", "flows", src, "copy"))

	if err != nil {
		return err
	}

	if resp == nil || resp.IsError() {
		return errors.Wrapf(errors.Unknown, "failed to create of copy authentication flow %s, status code: %d", src, resp.StatusCode())
	}

	return nil
}

func (c *Client) LocateAuthenticationExecution(ctx context.Context, token, realm, flowId, executionProvider string) (ret *gocloak.ModifyAuthenticationExecutionRepresentation, err error) {
	var list []*gocloak.ModifyAuthenticationExecutionRepresentation
	list, err = c.GetAuthenticationExecutions(ctx, token, realm, flowId)
	if err != nil {
		return
	}
	for _, e := range list {
		if e.Level != nil && *e.Level != 0 {
			// lets consider only top level executions
			// and ignore sub flows.
			continue
		}
		if e.ProviderID != nil && *e.ProviderID == executionProvider {
			// execution is already available, return the same
			ret = e
			return
		}
	}
	execCreateRequest := gocloak.CreateAuthenticationExecutionRepresentation{
		Provider: gocloak.StringP(executionProvider),
	}
	err = c.CreateAuthenticationExecution(ctx, token, realm, flowId, execCreateRequest)
	if err != nil {
		return
	}
	// fetch the list of Executions again to locate the created execution and return
	list, err = c.GetAuthenticationExecutions(ctx, token, realm, flowId)
	if err != nil {
		return
	}
	for _, e := range list {
		if e.Level != nil && *e.Level != 0 {
			// lets consider only top level executions
			// and ignore sub flows.
			continue
		}
		if e.ProviderID != nil && *e.ProviderID == executionProvider {
			ret = e
			return
		}
	}
	err = errors.Wrapf(errors.Unknown, "failed to locate execution for provider %s in flow %s", executionProvider, flowId)
	return
}

func (c *Client) ConfigureUserSessionLimit(ctx context.Context, token, realm string, e *gocloak.ModifyAuthenticationExecutionRepresentation, sessions int, denyNewSession bool, alias, errorMsg string) error {
	var err error
	behavior := "Deny new session"
	if !denyNewSession {
		behavior = "Terminate oldest session"
	}
	config := struct {
		//ID     *string            `json:"id,omitempty"`
		Alias  *string            `json:"alias,omitempty"`
		Config *map[string]string `json:"config,omitempty"`
	}{
		Alias: gocloak.StringP(alias),
		Config: &map[string]string{
			"userRealmLimit":  strconv.Itoa(sessions),
			"behavior":        behavior,
			"userClientLimit": "0",
			"errorMessage":    errorMsg,
		},
	}
	var resp *resty.Response
	if e.AuthenticationConfig == nil {
		resp, err = c.GetRequestWithBearerAuth(ctx, token).
			SetBody(config).
			Post(c.getAdminRealmURL(c.url, realm, "authentication", "executions", *e.ID, "config"))
	} else {
		resp, err = c.GetRequestWithBearerAuth(ctx, token).
			SetBody(config).
			Put(c.getAdminRealmURL(c.url, realm, "authentication", "config", *e.AuthenticationConfig))
	}

	if err != nil {
		return err
	}

	if resp == nil || resp.IsError() {
		return errors.Wrapf(errors.Unknown, "failed to configure user session limit, status code: %d", resp.StatusCode())
	}
	return nil
}

func (c *Client) LowerAuthenticationExecutionPriority(ctx context.Context, token, realm, executionId string) error {
	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		Post(c.getAdminRealmURL(c.url, realm, "authentication", "executions", executionId, "lower-priority"))

	if err != nil {
		return err
	}

	if resp == nil || resp.IsError() {
		return errors.Wrapf(errors.Unknown, "failed to lower authentication execution priority, status code: %d", resp.StatusCode())
	}

	return nil
}

// SetExecutionToLastPosition moves an execution to the last position by using LowerAuthenticationExecutionPriority repeatedly
func (c *Client) SetExecutionToPosition(ctx context.Context, token, realm, flowId, executionId string) error {
	maxAttempts := 20 // Safety limit to prevent infinite loops

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Get current executions to check position
		executions, err := c.GetAuthenticationExecutions(ctx, token, realm, flowId)
		if err != nil {
			return err
		}

		// Find our execution's current position
		var ourExecution *gocloak.ModifyAuthenticationExecutionRepresentation
		ourIndex := -1
		for i, exec := range executions {
			if exec.ID != nil && *exec.ID == executionId {
				ourExecution = exec
				ourIndex = i
				break
			}
		}

		if ourExecution == nil {
			return errors.Wrapf(errors.Unknown, "execution %s not found in flow %s", executionId, flowId)
		}

		// Check if we're already at the last position among same-level executions
		isLast := true
		for i := ourIndex + 1; i < len(executions); i++ {
			nextExec := executions[i]
			if nextExec.Level != nil && ourExecution.Level != nil && *nextExec.Level == *ourExecution.Level {
				isLast = false
				break
			}
		}

		if isLast {
			return nil
		}

		// Lower priority once
		err = c.LowerAuthenticationExecutionPriority(ctx, token, realm, executionId)
		if err != nil {
			return errors.Wrapf(errors.Unknown, "failed to lower execution priority on attempt %d: %v", attempt, err)
		}
	}

	return errors.Wrapf(errors.Unknown, "failed to position execution %s to last after %d attempts", executionId, maxAttempts)
}

// GetMaxExecutionPriority returns the maximum priority among top-level executions in a flow
// Since Priority field is not exposed in the struct using position based calculation
func (c *Client) GetMaxExecutionPriority(ctx context.Context, token, realm, flowId string) (int, error) {
	executions, err := c.GetAuthenticationExecutions(ctx, token, realm, flowId)
	if err != nil {
		return 0, err
	}

	// Count top-level executions to estimate max priority
	topLevelCount := 0
	for _, exec := range executions {
		if exec.Level != nil && *exec.Level == 0 { // Only top-level executions
			topLevelCount++
		}
	}

	// Return estimated max priority
	return topLevelCount * 10, nil
}
