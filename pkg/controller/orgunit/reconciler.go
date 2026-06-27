// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package orgunit

import (
	"context"
	"log"
	"time"

	"github.com/go-core-stack/auth-gateway/pkg/config"
	"github.com/go-core-stack/auth-gateway/pkg/table"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
)

// OrgUnitCleanupController manages the lifecycle of soft-deleted org-units,
// hard-deleting them after the configured hold period expires.
type OrgUnitCleanupController struct {
	tbl          *table.OrgUnitTable
	holdDuration int
}

type orgUnitReconciler struct {
	reconciler.Controller
	ctrl *OrgUnitCleanupController
}

func (r *orgUnitReconciler) Reconcile(k any) (*reconciler.Result, error) {
	ctx := context.Background()
	key := k.(*table.OrgUnitKey)

	entry, err := r.ctrl.tbl.Find(ctx, key)
	if err != nil {
		if !errors.IsNotFound(err) {
			// transient error — requeue with backoff
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}
		// entry already gone — nothing to do
		return &reconciler.Result{}, nil
	}

	// only process soft-deleted entries
	if entry.Deleted == 0 {
		return &reconciler.Result{}, nil
	}

	holdExpiry := entry.Deleted + int64(r.ctrl.holdDuration)
	now := time.Now().Unix()

	if holdExpiry > now {
		// hold period has not expired — requeue after remaining time (+1s buffer)
		remaining := holdExpiry - now
		return &reconciler.Result{RequeueAfter: time.Duration(remaining+1) * time.Second}, nil
	}

	// hold period expired — hard-delete the entry
	err = r.ctrl.tbl.DeleteKey(ctx, key)
	if err != nil && !errors.IsNotFound(err) {
		// transient error — requeue with backoff
		log.Printf("orgunit reconciler: failed to hard-delete org-unit %s: %s", key.ID, err)
		return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
	}

	log.Printf("orgunit reconciler: hard-deleted org-unit %s after hold period", key.ID)
	return &reconciler.Result{}, nil
}

// NewOrgUnitCleanupController creates and registers the org-unit reconciler.
// It should only be called when experimental.allow_ou_delete is enabled.
func NewOrgUnitCleanupController(experimental config.ExperimentalConfig) (*OrgUnitCleanupController, error) {
	tbl, err := table.GetOrgUnitTable()
	if err != nil {
		return nil, err
	}

	ctrl := &OrgUnitCleanupController{
		tbl:          tbl,
		holdDuration: experimental.HoldDeletedOU,
	}

	r := &orgUnitReconciler{
		ctrl: ctrl,
	}

	err = tbl.Register("OrgUnitCleanupController", r)
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}
