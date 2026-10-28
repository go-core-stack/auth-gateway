// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/go-core-stack/auth/context"
)

// recorder is a stub handler that names itself in the response and
// keeps the auth context header it was handed.
type recorder struct {
	name       string
	authHeader string
}

func (h *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.authHeader = r.Header.Get(common.HttpClientAuthContext)
	_, _ = w.Write([]byte(h.name))
}

func TestExternalHandlerApiDocs(t *testing.T) {
	tests := []struct {
		name           string
		apiDocsEnabled bool
		path           string
		want           string
	}{
		{"enabled apidocs ui", true, "/apidocs/", "apidocs"},
		{"enabled apidocs forward", true, "/apidocs/svc/swagger.json", "apidocs"},
		{"enabled realm", true, "/api/v1/realm.json", "realm"},
		{"enabled other", true, "/api/v1/tenants", "gateway"},
		{"disabled apidocs ui", false, "/apidocs/", "gateway"},
		{"disabled apidocs forward", false, "/apidocs/svc/swagger.json", "gateway"},
		{"disabled realm", false, "/api/v1/realm.json", "realm"},
		{"disabled other", false, "/api/v1/tenants", "gateway"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := &recorder{name: "gateway"}
			rs := &recorder{name: "realm"}
			oa := &recorder{name: "apidocs"}
			constructed := 0
			h := newExternalHandler(tc.apiDocsEnabled, gw, rs, func() http.Handler {
				constructed++
				return oa
			})

			wantConstructed := 0
			if tc.apiDocsEnabled {
				wantConstructed = 1
			}
			if constructed != wantConstructed {
				t.Fatalf("apidocs server constructed %d times, want %d", constructed, wantConstructed)
			}

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set(common.HttpClientAuthContext, "forged")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if got := w.Body.String(); got != tc.want {
				t.Fatalf("path %s served by %q, want %q", tc.path, got, tc.want)
			}
			if tc.want == "apidocs" && oa.authHeader != "" {
				t.Fatalf("apidocs server received auth context header %q", oa.authHeader)
			}
		})
	}
}
