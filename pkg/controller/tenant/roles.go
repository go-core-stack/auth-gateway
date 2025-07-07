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

// Tenant Role Controller responsible for managing Keycloak
// configuration and synchronizing Tenant Database Store with
// Keycloak configuration
type RoleController struct {
	tbl    *table.TenantTable
	client *keycloak.Client
}

type RoleReconciler struct {
	reconciler.Controller
	ctrl *RoleController
}

func (r *RoleReconciler) Reconcile(k any) (*reconciler.Result, error) {
	key := k.(*table.TenantKey)

	entry, err := r.ctrl.tbl.Find(context.Background(), key)
	if err != nil {
		if errors.IsNotFound(err) {
			// entry is deleted, nothing needs to be done
			return &reconciler.Result{}, nil
		}
		log.Panicf("Failed to find Tenant Entry: %s", err)
	}

	if entry.RoleStatus == nil || entry.RoleStatus.UpdateTime == 0 {
		// create realm corresponding to the tenant
		token, err := r.ctrl.client.GetAccessToken()
		if err != nil {
			log.Panicf("keycloak session not active: %s", err)
		}

		realm, err := r.ctrl.client.GetRealm(context.Background(), token, key.Name)
		if err != nil || realm == nil {
			// realm doesn't exist wait for sometime before retrying
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		rRole, err := r.ctrl.client.GetRealmRole(context.Background(), token, key.Name, "admin")
		if err != nil || rRole == nil {
			role := gocloak.Role{
				Name:        gocloak.StringP("admin"),
				Description: gocloak.StringP("Tenant Admin Role"),
			}
			_, err = r.ctrl.client.CreateRealmRole(context.Background(), token, key.Name, role)
			if err != nil {
				log.Println("failed to configure keycloak with relevant tenant role configuration")
				return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
			}
		}

		// Below code can be activated to remove roles from default association
		/*
			defaultRoleName := "default-roles-" + key.Name
			roles, _ := r.ctrl.client.GetCompositeRealmRoles(context.Background(), token, key.Name, defaultRoleName)
			lRoles := []gocloak.Role{}
			for _, cRole := range roles {
				lRoles = append(lRoles, *cRole)
			}
			r.ctrl.client.DeleteRealmRoleComposite(context.Background(), token, key.Name, defaultRoleName, lRoles)
		*/

		update := &table.TenantEntry{
			RoleStatus: &table.TenantRoleStatus{
				UpdateTime: time.Now().Unix(),
			},
		}

		err = r.ctrl.tbl.Update(context.Background(), key, update)
		if err != nil {
			log.Printf("failed to update Role for tenant %s: got err %s", key.Name, err)
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}
	return &reconciler.Result{}, nil
}

// Creates New Role Controller
func NewRoleController(client *keycloak.Client) (*RoleController, error) {
	tbl, err := table.GetTenantTable()
	if err != nil {
		return nil, err
	}

	ctrl := &RoleController{
		tbl:    tbl,
		client: client,
	}

	r := &RoleReconciler{
		ctrl: ctrl,
	}

	err = tbl.Register("TenantRoleController", r)
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}
