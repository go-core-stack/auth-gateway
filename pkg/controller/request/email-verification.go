// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package request

import (
	"context"
	"time"

	"github.com/Prabhjot-Sethi/auth-gateway/pkg/table"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
)

type EmailVerificationCleanupController struct {
	tbl *table.EmailVerificationTable
}

type EmailVerificationReconciler struct {
	reconciler.Controller
	ctrl *EmailVerificationCleanupController
}

func (r *EmailVerificationReconciler) Reconcile(k any) (*reconciler.Result, error) {
	ctx := context.Background()
	key := k.(*table.Email)
	entry, err := r.ctrl.tbl.Find(ctx, key)
	if err != nil {
		if !errors.IsNotFound(err) {
			return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
		}
		return &reconciler.Result{}, nil
	}
	timeout := entry.Created + 300 - time.Now().Unix()
	if timeout > 0 {
		return &reconciler.Result{RequeueAfter: time.Duration(timeout+1) * time.Second}, nil
	}
	err = r.ctrl.tbl.DeleteKey(ctx, key)
	if err != nil && !errors.IsNotFound(err) {
		return &reconciler.Result{RequeueAfter: 5 * time.Second}, nil
	}
	return &reconciler.Result{}, nil
}

// Creates New Email Verification cleanup controller
func NewEmailVerificationCleanupController() (*EmailVerificationCleanupController, error) {
	tbl, err := table.GetEmailVerificationTable()
	if err != nil {
		return nil, err
	}

	ctrl := &EmailVerificationCleanupController{
		tbl: tbl,
	}

	r := &EmailVerificationReconciler{
		ctrl: ctrl,
	}

	err = tbl.Register("CleanupController", r)
	if err != nil {
		return nil, err
	}

	return ctrl, nil
}
