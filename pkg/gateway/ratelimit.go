// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled    bool
	DefaultRPS float64
	BurstSize  int
}

// TenantRateLimiter manages per-tenant rate limiters.
type TenantRateLimiter struct {
	limiters map[string]*tenantLimiter
	mu       sync.RWMutex
	config   RateLimitConfig
}

type tenantLimiter struct {
	limiter  *rate.Limiter
	lastUsed atomic.Int64
}

// NewTenantRateLimiter creates a new rate limiter manager.
func NewTenantRateLimiter(config RateLimitConfig) *TenantRateLimiter {
	return &TenantRateLimiter{
		limiters: make(map[string]*tenantLimiter),
		config:   config,
	}
}

// Allow checks if a request from the tenant should be allowed.
func (t *TenantRateLimiter) Allow(tenant string) bool {
	if !t.config.Enabled {
		return true
	}

	limiter := t.getOrCreateLimiter(tenant)
	limiter.lastUsed.Store(time.Now().UnixNano())
	return limiter.limiter.Allow()
}

func (t *TenantRateLimiter) getOrCreateLimiter(tenant string) *tenantLimiter {
	t.mu.RLock()
	if l, exists := t.limiters[tenant]; exists {
		t.mu.RUnlock()
		return l
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()

	if l, exists := t.limiters[tenant]; exists {
		return l
	}

	burst := t.config.BurstSize
	if burst == 0 {
		burst = int(math.Ceil(t.config.DefaultRPS))
		if burst < 1 {
			burst = 1
		}
	}

	l := &tenantLimiter{
		limiter: rate.NewLimiter(rate.Limit(t.config.DefaultRPS), burst),
	}
	l.lastUsed.Store(time.Now().UnixNano())

	t.limiters[tenant] = l
	return l
}

// Cleanup removes idle limiters to prevent memory growth.
func (t *TenantRateLimiter) Cleanup(maxIdle time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if maxIdle <= 0 {
		for tenant := range t.limiters {
			delete(t.limiters, tenant)
		}
		return
	}

	now := time.Now()
	for tenant, limiter := range t.limiters {
		lastUsed := time.Unix(0, limiter.lastUsed.Load())
		if now.Sub(lastUsed) > maxIdle {
			delete(t.limiters, tenant)
		}
	}
}
