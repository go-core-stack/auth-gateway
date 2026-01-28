// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"testing"
	"time"
)

func TestTenantRateLimiterDisabled(t *testing.T) {
	rl := NewTenantRateLimiter(RateLimitConfig{Enabled: false})

	for i := 0; i < 1000; i++ {
		if !rl.Allow("tenant1") {
			t.Fatalf("expected allow when rate limiting disabled")
		}
	}
}

func TestTenantRateLimiterRateLimit(t *testing.T) {
	rl := NewTenantRateLimiter(RateLimitConfig{
		Enabled:    true,
		DefaultRPS: 10,
		BurstSize:  10,
	})

	for i := 0; i < 10; i++ {
		if !rl.Allow("tenant1") {
			t.Fatalf("expected allow for burst request %d", i+1)
		}
	}

	if rl.Allow("tenant1") {
		t.Fatalf("expected rate limit after burst is exhausted")
	}

	if !rl.Allow("tenant2") {
		t.Fatalf("expected separate limiter per tenant")
	}
}

func TestTenantRateLimiterSubOneRPS(t *testing.T) {
	rl := NewTenantRateLimiter(RateLimitConfig{
		Enabled:    true,
		DefaultRPS: 0.5,
		BurstSize:  0,
	})

	// With sub-1 RPS and no explicit BurstSize, burst should be clamped to 1
	// so the first request must be allowed
	if !rl.Allow("tenant1") {
		t.Fatalf("expected first request to be allowed for sub-1 RPS config")
	}

	// Second immediate request should be rate limited
	if rl.Allow("tenant1") {
		t.Fatalf("expected second request to be rate limited")
	}
}

func TestTenantRateLimiterCleanup(t *testing.T) {
	rl := NewTenantRateLimiter(RateLimitConfig{
		Enabled:    true,
		DefaultRPS: 10,
		BurstSize:  10,
	})

	rl.Allow("tenant1")
	rl.Allow("tenant2")

	rl.mu.RLock()
	if len(rl.limiters) != 2 {
		rl.mu.RUnlock()
		t.Fatalf("expected 2 limiters, got %d", len(rl.limiters))
	}
	rl.mu.RUnlock()

	rl.Cleanup(0)

	rl.mu.RLock()
	defer rl.mu.RUnlock()
	if len(rl.limiters) != 0 {
		t.Fatalf("expected 0 limiters after cleanup, got %d", len(rl.limiters))
	}
}

// TestTenantRateLimiterCleanupRemovesIdleLimiters verifies that cleanup removes
// only limiters that have been idle longer than maxIdle duration.
func TestTenantRateLimiterCleanupRemovesIdleLimiters(t *testing.T) {
	rl := NewTenantRateLimiter(RateLimitConfig{
		Enabled:    true,
		DefaultRPS: 10,
		BurstSize:  10,
	})

	// Create limiters for multiple tenants
	rl.Allow("tenant1")
	rl.Allow("tenant2")
	rl.Allow("tenant3")

	rl.mu.RLock()
	if len(rl.limiters) != 3 {
		rl.mu.RUnlock()
		t.Fatalf("expected 3 limiters, got %d", len(rl.limiters))
	}
	rl.mu.RUnlock()

	// Wait briefly to simulate idle time
	time.Sleep(100 * time.Millisecond)

	// Cleanup should remove idle limiters (100ms > 50ms maxIdle)
	rl.Cleanup(50 * time.Millisecond)

	rl.mu.RLock()
	remaining := len(rl.limiters)
	rl.mu.RUnlock()

	if remaining != 0 {
		t.Fatalf("expected 0 limiters after cleanup with 50ms maxIdle, got %d", remaining)
	}
}

// TestTenantRateLimiterCleanupKeepsActiveLimiters verifies that cleanup does not
// remove limiters that have been used recently.
func TestTenantRateLimiterCleanupKeepsActiveLimiters(t *testing.T) {
	rl := NewTenantRateLimiter(RateLimitConfig{
		Enabled:    true,
		DefaultRPS: 10,
		BurstSize:  10,
	})

	// Create limiter
	rl.Allow("active-tenant")

	// Cleanup with long maxIdle should keep the limiter
	rl.Cleanup(1 * time.Hour)

	rl.mu.RLock()
	remaining := len(rl.limiters)
	rl.mu.RUnlock()

	if remaining != 1 {
		t.Fatalf("expected 1 limiter to remain (not idle), got %d", remaining)
	}
}
