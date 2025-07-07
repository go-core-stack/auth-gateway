// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package user

import (
	"context"
	"log"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/table"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
	"github.com/go-core-stack/core/utils"
)

// User reconciler Controller responsible for managing Keycloak
// configuration and synchronizing User Database Store with
// Keycloak configuration
type UserController struct {
	tenantTbl *table.TenantTable
	userTbl   *table.UserTable
	client    *keycloak.Client
}

type UserReconciler struct {
	reconciler.Controller
	ctrl *UserController
}

func (r *UserReconciler) getTenant(ctx context.Context, name string) (*table.TenantEntry, error) {
	tKey := table.TenantKey{
		Name: name,
	}

	tEntry, err := r.ctrl.tenantTbl.Find(ctx, &tKey)
	if err != nil {
		return nil, err
	}

	if tEntry.KCStatus == nil || tEntry.KCStatus.RealmName == "" {
		return nil, errors.Wrapf(errors.InvalidArgument, "Tenant %s setup not completed", name)
	}
	return tEntry, nil
}

func (r *UserReconciler) updateUser(ctx context.Context, tEntry *table.TenantEntry, uEntry *table.UserEntry) error {
	token, _ := r.ctrl.client.GetAccessToken()
	users, err := r.ctrl.client.GetUsers(ctx, token, tEntry.KCStatus.RealmName, gocloak.GetUsersParams{
		Username: gocloak.StringP(uEntry.Key.Username),
	})
	if err != nil {
		return err
	}
	user := users[0]
	user.FirstName = gocloak.StringP(uEntry.Info.FirstName)
	user.LastName = gocloak.StringP(uEntry.Info.LastName)
	user.Enabled = gocloak.BoolP(!utils.PBool(uEntry.Disabled))
	user.Email = gocloak.StringP(uEntry.Info.Email)
	err = r.ctrl.client.UpdateUser(ctx, token, tEntry.KCStatus.RealmName, *user)
	if err != nil {
		log.Printf("failed to update user: %v, got err: %s", uEntry.Key, err)
		return err
	}

	return nil
}

func (r *UserReconciler) Reconcile(k any) (*reconciler.Result, error) {
	ctx := context.Background()
	key := k.(*table.UserKey)
	tEntry, err := r.getTenant(ctx, key.Tenant)
	if err != nil {
		return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
	}

	entry, err := r.ctrl.userTbl.Find(context.Background(), key)
	if err != nil {
		if errors.IsNotFound(err) {
			// entry is deleted, nothing needs to be done
			return &reconciler.Result{}, nil
		}
		log.Panicf("Failed to find Tenant Entry: %s", err)
	}

	if entry.KCStatus != nil && entry.KCStatus.Updated >= entry.Updated {
		// Keycloak Status is up to date, nothing needs to be done
		return &reconciler.Result{}, nil
	}

	if utils.PBool(entry.Deleted) {
		if tEntry.Config.DefaultAdmin.UserID == key.Username {
			// no need to delete the default admin user
			return &reconciler.Result{}, nil
		}

		token, _ := r.ctrl.client.GetAccessToken()
		params := gocloak.GetUsersParams{
			Username: gocloak.StringP(key.Username),
		}
		users, err := r.ctrl.client.GetUsers(ctx, token, tEntry.KCStatus.RealmName, params)
		if err != nil || len(users) == 0 {
			log.Printf("failed to find the user in given tenant %s, got error: %s", key.Tenant, err)
			// TODO(Prabhjot) might need to consider error handling
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}
		// assume that it is always the first and the only user in the list
		err = r.ctrl.client.DeleteUser(ctx, token, tEntry.KCStatus.RealmName, *users[0].ID)
		if err != nil {
			log.Printf("failed to delete user %s:%s, got error: %s", key.Tenant, key.Username, err)
			// TODO(Prabhjot) might need to consider error handling
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}

		err = r.ctrl.userTbl.DeleteKey(ctx, key)
		if err != nil {
			if !errors.IsNotFound(err) {
				return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
			}
		}
		return &reconciler.Result{}, nil
	}

	update := &table.UserEntry{
		Key: key,
		KCStatus: &table.UserKeycloakStatus{
			Updated:  time.Now().Unix(),
			Disabled: entry.Disabled,
		},
	}

	defer func() {
		if update != nil {
			err = r.ctrl.userTbl.Update(ctx, key, update)
			if err != nil {
				log.Panicf("failed to update User Entry for %s:%s: got err %s", key.Tenant, key.Username, err)
			}
		}
	}()

	if entry.KCStatus == nil {
		// create new user
		user := gocloak.User{
			FirstName: gocloak.StringP(entry.Info.FirstName),
			LastName:  gocloak.StringP(entry.Info.LastName),
			Email:     gocloak.StringP(entry.Info.Email),
			Enabled:   gocloak.BoolP(!utils.PBool(entry.Disabled)),
			Username:  gocloak.StringP(key.Username),
		}
		token, _ := r.ctrl.client.GetAccessToken()
		userID, err := r.ctrl.client.CreateUser(ctx, token, tEntry.KCStatus.RealmName, user)
		if err != nil {
			log.Printf("failed to create user for Tenant: %s, got error: %s", key.Tenant, err)
			if ok := keycloak.IsConflictError(err); !ok {
				// retry again if it is not conflict error
				update = nil // do not update the entry
				return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
			}
			// update existing user as per configuration
			err = r.updateUser(ctx, tEntry, entry)
			if err != nil {
				log.Printf("failed to update user %s:%s, got error: %s", key.Tenant, key.Username, err)
				update = nil // do not update the entry
				return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
			}
		} else {
			user.ID = gocloak.StringP(userID)
			if entry.Password != nil {
				err = r.ctrl.client.SetPassword(ctx, token, userID, tEntry.KCStatus.RealmName, entry.Password.Value, true)
				if err != nil {
					log.Printf("failed to set user first login password in for user %s:%s, got error: %s", key.Tenant, key.Username, err)
				}
			}
		}
	} else {
		// update existing user as per configuration
		err = r.updateUser(ctx, tEntry, entry)
		if err != nil {
			log.Printf("failed to update user %s:%s, got error: %s", key.Tenant, key.Username, err)
			update = nil // do not update the entry
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}
	}

	return &reconciler.Result{}, nil
}

// Creates New User Controller
func NewUserController(client *keycloak.Client) (*UserController, error) {
	tbl, err := table.GetUserTable()
	if err != nil {
		return nil, err
	}

	tenantTbl, err := table.GetTenantTable()
	if err != nil {
		return nil, err
	}

	ctrl := &UserController{
		userTbl:   tbl,
		tenantTbl: tenantTbl,
		client:    client,
	}

	r := &UserReconciler{
		ctrl: ctrl,
	}

	err = tbl.Register("UserController", r)
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}
