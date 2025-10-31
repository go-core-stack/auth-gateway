// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package tenant

import (
	"context"
	"log"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/table"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
)

// Tenant Setup Controller responsible for managing Keycloak
// configuration and synchronizing Tenant Database Store with
// Keycloak configuration
type SetupController struct {
	tbl    *table.TenantTable
	client *keycloak.Client
}

type SetupReconciler struct {
	reconciler.Controller
	ctrl *SetupController
}

const (
	// Auth Flows
	BrowserFlow      = "auth browser"
	IDPPostLoginFlow = "auth idp post login"
)

// update or create required auth flows in the realm
// and use the default or provided configurations to
// update the same
func (r *SetupReconciler) updateRealmAuthFlows(realm string) error {
	token, err := r.ctrl.client.GetAccessToken()
	if err != nil {
		log.Panicf("keycloak session not active: %s", err)
	}
	ctx := context.Background()
	// check if the required auth flows are already created
	// Ensure flow "auth idp post login" exists
	flows, err := r.ctrl.client.GetAuthenticationFlows(ctx, token, realm)
	if err != nil {
		log.Printf("Failed fetching existing flows: error: %s", err)
		return err
	}

	var browserFlow, idpPostLoginFlow bool
	for _, f := range flows {
		if *f.Alias == IDPPostLoginFlow {
			idpPostLoginFlow = true
		}
		if *f.Alias == BrowserFlow {
			browserFlow = true
		}
	}
	// if identity provider post login flow is not created, create it
	if !idpPostLoginFlow {
		flow := gocloak.AuthenticationFlowRepresentation{
			Alias:       gocloak.StringP(IDPPostLoginFlow),
			BuiltIn:     gocloak.BoolP(false),
			Description: gocloak.StringP("Identity Provider post login auth checks"),
			ProviderID:  gocloak.StringP("basic-flow"),
			TopLevel:    gocloak.BoolP(true),
		}
		err = r.ctrl.client.CreateAuthenticationFlow(ctx, token, realm, flow)
		if err != nil {
			log.Printf("failed to create Auth IDP post login flow, error: %s", err)
			return err
		}
	}

	// Ensure flow "auth browser" exists
	if !browserFlow {
		err = r.ctrl.client.CopyAuthenticationFlow(ctx, token, realm, "browser", BrowserFlow)
		if err != nil {
			log.Printf("failed to create Auth browser login flow, error: %s", err)
			return err
		}
	}

	// ensure configuration in the realm to use custom auth flows for login
	updateRealm := gocloak.RealmRepresentation{
		Realm:       gocloak.StringP(realm),
		BrowserFlow: gocloak.StringP(BrowserFlow),
	}
	err = r.ctrl.client.UpdateRealm(ctx, token, updateRealm)
	if err != nil {
		log.Printf("browser flow update in realm failed, error: %s", err)
		return err
	}

	// Detect the "forms" subflow name under "auth browser"
	actualFormsFlowName, err := r.detectFormsSubflow(ctx, token, realm)
	if err != nil {
		return err
	}

	// Process both target flows
	targetFlows := []string{IDPPostLoginFlow, actualFormsFlowName}

	for _, flowName := range targetFlows {
		// Locate or create execution with providerId "user-session-limits"
		e, err := r.ctrl.client.LocateAuthenticationExecution(ctx, token, realm, flowName, "user-session-limits")
		if err != nil {
			return err
		}

		// Configure with alias, userRealmLimit=5, behavior="Deny new session"
		alias := flowName + " session limiter"
		err = r.ctrl.client.ConfigureUserSessionLimit(ctx, token, realm, e, 5, true, alias, "")
		if err != nil {
			return err
		}

		// Position user-session-limits execution to last position in flow
		err = r.ctrl.client.SetExecutionToPosition(ctx, token, realm, flowName, *e.ID)
		if err != nil {
			return err
		}

		// Set requirement=REQUIRED
		e.Requirement = gocloak.StringP("REQUIRED")
		err = r.ctrl.client.UpdateAuthenticationExecution(ctx, token, realm, flowName, *e)
		if err != nil {
			log.Printf("failed to enable user session limit config, error: %s", err)
			return err
		}

		// Re-list executions and verify positioning
		executions, err := r.ctrl.client.GetAuthenticationExecutions(ctx, token, realm, flowName)
		if err != nil {
			return err
		}

		// Check if user-session-limits is last and has highest priority
		var userSessionExec *gocloak.ModifyAuthenticationExecutionRepresentation
		isLast := true

		for i, exec := range executions {
			if exec.ProviderID != nil && *exec.ProviderID == "user-session-limits" {
				userSessionExec = exec
				// Check if there are any executions after this one at the same level
				for j := i + 1; j < len(executions); j++ {
					if executions[j].Level != nil && exec.Level != nil && *executions[j].Level == *exec.Level {
						isLast = false
						break
					}
				}
			}
		}

		// If not last, attempt to reposition again
		if !isLast {
			err = r.ctrl.client.SetExecutionToPosition(ctx, token, realm, flowName, *userSessionExec.ID)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// detectFormsSubflow detects the forms subflow name under "auth browser"
func (r *SetupReconciler) detectFormsSubflow(ctx context.Context, token, realm string) (string, error) {
	// When copying the "browser" flow to "auth browser", Keycloak creates a subflow named "auth browser forms"
	formsFlowName := BrowserFlow + " forms"

	executions, err := r.ctrl.client.GetAuthenticationExecutions(ctx, token, realm, formsFlowName)
	if err != nil {
		return "", err
	}

	// Verify this flow contains form executions
	hasFormExecutions := false
	for _, exec := range executions {
		if exec.ProviderID != nil {
			provider := *exec.ProviderID
			if provider == "auth-username-password-form" || provider == "auth-otp-form" {
				hasFormExecutions = true
				break
			}
		}
	}

	if !hasFormExecutions {
		return "", errors.New("forms subflow exists but contains no form authenticators")
	}

	return formsFlowName, nil
}

func (r *SetupReconciler) Reconcile(k any) (*reconciler.Result, error) {
	key := k.(*table.TenantKey)

	entry, err := r.ctrl.tbl.Find(context.Background(), key)
	if err != nil {
		if errors.IsNotFound(err) {
			// entry is deleted, nothing needs to be done
			return &reconciler.Result{}, nil
		}
		log.Panicf("Failed to find Tenant Entry: %s", err)
	}

	if entry.KCStatus == nil || entry.KCStatus.UpdateTime == 0 {
		// create realm corresponding to the tenant
		token, err := r.ctrl.client.GetAccessToken()
		if err != nil {
			log.Panicf("keycloak session not active: %s", err)
		}
		realm := gocloak.RealmRepresentation{
			Realm:               gocloak.StringP(key.Name),
			DisplayName:         gocloak.StringP(entry.Config.DispName),
			Enabled:             gocloak.BoolP(true),
			BruteForceProtected: gocloak.BoolP(true),
			FailureFactor:       gocloak.IntP(10),
			EventsEnabled:       gocloak.BoolP(true),
		}
		found, _ := r.ctrl.client.GetRealm(context.Background(), token, key.Name)
		if found != nil {
			err = r.ctrl.client.UpdateRealm(context.Background(), token, realm)
		} else {
			_, err = r.ctrl.client.CreateRealm(context.Background(), token, realm)
		}

		if err != nil {
			log.Println("failed to configure keycloak with relevant tenant configuration")
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		err = r.updateRealmAuthFlows(key.Name)
		if err != nil {
			log.Printf("failed to configure keycloak auth flows, error: %s", err)
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		update := &table.TenantEntry{
			KCStatus: &table.TenantKCStatus{
				RealmName:  key.Name,
				UpdateTime: time.Now().Unix(),
			},
		}

		err = r.ctrl.tbl.Update(context.Background(), key, update)
		if err != nil {
			log.Printf("failed to update Realm for tenant %s: got err %s", key.Name, err)
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}

	if entry.AuthClient == nil || entry.AuthClient.UpdateTime == 0 {
		// create Auth client corresponding to the tenant
		token, err := r.ctrl.client.GetAccessToken()
		if err != nil {
			log.Panicf("keycloak session not active: %s", err)
		}
		clientId := "controller"
		params := gocloak.GetClientsParams{
			ClientID: gocloak.StringP(clientId),
		}
		found, err := r.ctrl.client.GetClients(context.Background(), token, key.Name, params)
		if err != nil {
			log.Printf("failed to fetch clients from keycloak: %s", err)
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		id := ""
		if len(found) == 0 {
			authClient := gocloak.Client{
				ClientID:     gocloak.StringP(clientId),
				Protocol:     gocloak.StringP("openid-connect"),
				Enabled:      gocloak.BoolP(true),
				RedirectURIs: &[]string{"*"},
				WebOrigins:   &[]string{"*"},
			}
			id, err = r.ctrl.client.CreateClient(context.Background(), token, key.Name, authClient)
			if err != nil {
				log.Printf("failed to create auth client in keycloak: %s", err)
				return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
			}
		} else {
			id = *found[0].ID

			// Verify and update existing client configuration if needed
			existingClient := found[0]
			needsUpdate := false
			updates := gocloak.Client{
				ID:       existingClient.ID,
				ClientID: existingClient.ClientID,
			}

			if existingClient.Enabled == nil || !*existingClient.Enabled {
				updates.Enabled = gocloak.BoolP(true)
				needsUpdate = true
			}

			if existingClient.PublicClient == nil || !*existingClient.PublicClient {
				updates.PublicClient = gocloak.BoolP(true)
				needsUpdate = true
			}

			if existingClient.StandardFlowEnabled == nil || !*existingClient.StandardFlowEnabled {
				updates.StandardFlowEnabled = gocloak.BoolP(true)
				needsUpdate = true
			}

			if needsUpdate {
				err = r.ctrl.client.UpdateClient(context.Background(), token, key.Name, updates)
				if err != nil {
					log.Printf("failed to update existing client configuration: %s", err)
				}
			}
		}

		mList := []gocloak.ProtocolMapperRepresentation{
			{
				Config: &map[string]string{
					"access.token.claim":       "true",
					"id.token.claim":           "false",
					"included.client.audience": clientId,
				},
				Name:           gocloak.StringP("audience-info"),
				Protocol:       gocloak.StringP("openid-connect"),
				ProtocolMapper: gocloak.StringP("oidc-audience-mapper"),
			},
			{
				Config: &map[string]string{
					"access.token.claim": "true",
					"id.token.claim":     "false",
					"claim.name":         "realm",
					"claim.value":        key.Name,
					"jsonType.label":     "string",
				},
				Name:           gocloak.StringP("realm-info"),
				Protocol:       gocloak.StringP("openid-connect"),
				ProtocolMapper: gocloak.StringP("oidc-hardcoded-claim-mapper"),
			},
		}

		for _, mapper := range mList {
			mapperExists := false
			if len(found) != 0 {
				// Check if mapper already exists
				if found[0].ProtocolMappers != nil {
					for _, m := range *found[0].ProtocolMappers {
						if *m.Name == *mapper.Name {
							mapperExists = true
							break
						}
					}
				}
			}

			if !mapperExists {
				_, err := r.ctrl.client.CreateClientProtocolMapper(context.Background(), token, key.Name, id, mapper)
				if err != nil {
					log.Printf("failed to create client protocol mapper: %s", err)
					return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
				}
			}
		}

		update := &table.TenantEntry{
			AuthClient: &table.TenantAuthClientStatus{
				ClientId:   clientId,
				UpdateTime: time.Now().Unix(),
			},
		}

		err = r.ctrl.tbl.Update(context.Background(), key, update)
		if err != nil {
			log.Printf("failed to update Realm for tenant %s: got err %s", key.Name, err)
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}

	return &reconciler.Result{}, nil
}

// Creates New Setup Controller
func NewSetupController(client *keycloak.Client) (*SetupController, error) {
	tbl, err := table.GetTenantTable()
	if err != nil {
		return nil, err
	}

	ctrl := &SetupController{
		tbl:    tbl,
		client: client,
	}

	r := &SetupReconciler{
		ctrl: ctrl,
	}

	err = tbl.Register("TenantSetupController", r)
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}
