// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
)

// TestGateway_RootOnlyRoutes checks the root-tenancy restriction against
// every combination of the root-only and user-specific flags.
func TestGateway_RootOnlyRoutes(t *testing.T) {
	const path = "/api/test/v1/item"

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}

	tests := []struct {
		name           string
		isRoot         bool
		isUserSpecific bool
		callerRoot     bool
		roles          []string
		want           int
	}{
		{"root user-specific, root non-admin", true, true, true, nil, http.StatusOK},
		{"root user-specific, other tenancy admin", true, true, false, []string{"admin"}, http.StatusForbidden},
		{"root user-specific, other tenancy non-admin", true, true, false, nil, http.StatusForbidden},
		{"user-specific, other tenancy non-admin", false, true, false, nil, http.StatusOK},
		{"root, root admin", true, false, true, []string{"admin"}, http.StatusOK},
		{"root, root non-admin", true, false, true, nil, http.StatusForbidden},
		{"root, other tenancy admin", true, false, false, []string{"admin"}, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setTestRoute(t, path, route.GET, routeData{
				scheme:         target.Scheme,
				host:           target.Host,
				isRoot:         tc.isRoot,
				isUserSpecific: tc.isUserSpecific,
			})
			gw := &gateway{
				proxyV1: &httputil.ReverseProxy{Director: func(*http.Request) {}},
			}
			gw.authenticateRequest = func(*http.Request) (*common.AuthInfo, error) {
				return &common.AuthInfo{
					Realm:    "tenant-a",
					UserName: "user",
					IsRoot:   tc.callerRoot,
					Roles:    tc.roles,
				}, nil
			}

			rec := httptest.NewRecorder()
			gw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
