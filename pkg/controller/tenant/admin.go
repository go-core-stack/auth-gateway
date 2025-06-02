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
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
)

// Tenant Admin Controller responsible for managing Keycloak
// configuration and synchronizing Tenant Database Store with
// Keycloak configuration
type AdminController struct {
	tbl    *table.TenantTable
	client *keycloak.Client
}

type AdminReconciler struct {
	reconciler.Controller
	ctrl *AdminController
}

func (r *AdminReconciler) Reconcile(k any) (*reconciler.Result, error) {
	key := k.(*table.TenantKey)

	entry, err := r.ctrl.tbl.Find(context.Background(), key)
	if err != nil {
		if errors.IsNotFound(err) {
			// entry is deleted, nothing needs to be done
			return &reconciler.Result{}, nil
		}
		log.Panicf("Failed to find Tenant Entry: %s", err)
	}

	userID := entry.Config.DefaultAdmin.UserID
	if entry.AdminStatus == nil || entry.AdminStatus.Admin != userID {
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
			// admin role doesn't exist wait for sometime before retrying
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		user := gocloak.User{
			Enabled:  gocloak.BoolP(true),
			Username: gocloak.StringP(userID),
		}

		ctx := context.Background()
		params := gocloak.GetUsersParams{
			Username: gocloak.StringP(userID),
		}
		users, err := r.ctrl.client.GetUsers(ctx, token, key.Name, params)
		if err != nil {
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		userExists := false
		if len(users) != 0 {
			user.ID = users[0].ID
			userExists = true
		}

		var kID string
		if userExists {
			// trigger an Update
			err = r.ctrl.client.UpdateUser(ctx, token, key.Name, user)
			if err != nil {
				log.Println("user update failed")
			}
			kID = *user.ID
		} else {
			// trigger a Create
			kID, err = r.ctrl.client.CreateUser(ctx, token, key.Name, user)
			if err != nil {
				log.Println("user create failed")
			}
			err = r.ctrl.client.SetPassword(ctx, token, kID, key.Name, entry.Config.DefaultAdmin.Password, true)
			if err != nil {
				log.Println("Failed setting password for user")
			}
		}

		// check that the admin has relevant role associated
		adminRoles, err := r.ctrl.client.GetRealmRolesByUserID(ctx, token, key.Name, kID)
		if err != nil {
			log.Println("Failed fetching realm roles associated with user")
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		configured := false
		for _, role := range adminRoles {
			if *role.Name == "admin" {
				configured = true
			}
		}

		if !configured {
			err = r.ctrl.client.AddRealmRoleToUser(ctx, token, key.Name, kID, []gocloak.Role{*rRole})
			if err != nil {
				log.Panicf("Failed to add admin role to user: %s", err)
			}
		}

		update := &table.TenantEntry{
			AdminStatus: &table.TenantAdminStatus{
				Admin:      entry.Config.DefaultAdmin.UserID,
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

// Creates New Admin Controller
func NewAdminController(client *keycloak.Client) (*AdminController, error) {
	tbl, err := table.GetTenantTable()
	if err != nil {
		return nil, err
	}

	ctrl := &AdminController{
		tbl:    tbl,
		client: client,
	}

	r := &AdminReconciler{
		ctrl: ctrl,
	}

	err = tbl.Register("TenantAdminController", r)
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}
