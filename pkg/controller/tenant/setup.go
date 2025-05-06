// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package tenant

import (
	"context"
	"log"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/keycloak"
	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
	"github.com/Prabhjot-Sethi/core/errors"
	"github.com/Prabhjot-Sethi/core/reconciler"
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

func (r *SetupReconciler) Reconcile(k any) (*reconciler.Result, error) {
	key := k.(*table.TenantKey)

	entry := &table.TenantEntry{}
	err := r.ctrl.tbl.Find(context.Background(), key, entry)
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
