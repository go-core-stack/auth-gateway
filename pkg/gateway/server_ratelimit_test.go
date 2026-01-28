// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/patricia"
)

func setTestRoute(t *testing.T, path string, method route.MethodType, data routeData) {
	t.Helper()

	routeLock.Lock()
	prevRoutes := gwRoutes
	gwRoutes = patricia.NewUrlTree[*routeNodes]()
	nodes := &routeNodes{
		method: data,
	}
	gwRoutes.Insert(path, nodes)
	routeLock.Unlock()

	t.Cleanup(func() {
		routeLock.Lock()
		gwRoutes = prevRoutes
		routeLock.Unlock()
	})
}

func TestGateway_RateLimiting(t *testing.T) {
	const path = "/api/auth/v1/tenant"
	setTestRoute(t, path, route.GET, routeData{
		scheme:         "http",
		host:           "example.com",
		isPublic:       false,
		isRoot:         false,
		isUserSpecific: false,
		scopes:         nil,
	})

	limiter := NewTenantRateLimiter(RateLimitConfig{
		Enabled:    true,
		DefaultRPS: 0,
		BurstSize:  1,
	})
	if !limiter.Allow("tenant-a") {
		t.Fatalf("expected initial limiter allowance")
	}

	authCalled := false
	gw := &gateway{
		rateLimiter: limiter,
	}
	gw.authenticateRequest = func(r *http.Request) (*common.AuthInfo, error) {
		authCalled = true
		return &common.AuthInfo{
			Realm:    "tenant-a",
			UserName: "user",
			Roles:    []string{"admin"},
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if !authCalled {
		t.Fatalf("expected authentication to run before rate limiting")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("expected Retry-After header to be 1, got %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type to be application/json, got %q", got)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != rateLimitResponseBody {
		t.Fatalf("expected body %q, got %q", rateLimitResponseBody, body)
	}
}

func TestGateway_RateLimiterDisabledDoesNotPanic(t *testing.T) {
	const path = "/api/auth/v1/tenant"
	setTestRoute(t, path, route.GET, routeData{
		scheme:         "http",
		host:           "example.com",
		isPublic:       false,
		isRoot:         false,
		isUserSpecific: false,
		scopes:         nil,
	})

	authCalled := false
	gw := &gateway{}
	gw.authenticateRequest = func(r *http.Request) (*common.AuthInfo, error) {
		authCalled = true
		return &common.AuthInfo{
			Realm:    "tenant-a",
			UserName: "user",
			Roles:    []string{},
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if !authCalled {
		t.Fatalf("expected authentication to run with rate limiter disabled")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}
