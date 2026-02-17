package limits

import (
	"context"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/trace"
)

type Policy struct {
	RequestsPerMinute int
	MaxTokensPerDay   int64
	MaxCostUSDPerDay  float64
}

type Config struct {
	PerKey       Policy
	PerWorkspace Policy
}

type GatewayLimiter struct {
	store trace.TraceStore
	cfg   Config
	nowFn func() time.Time

	mu                sync.Mutex
	keyRequests       map[string][]time.Time
	workspaceRequests map[string][]time.Time
	lastSweep         time.Time
}

const rateStateSweepInterval = 2 * time.Minute

func NewGatewayLimiter(store trace.TraceStore, cfg Config) *GatewayLimiter {
	return &GatewayLimiter{
		store:             store,
		cfg:               cfg,
		nowFn:             func() time.Time { return time.Now().UTC() },
		keyRequests:       map[string][]time.Time{},
		workspaceRequests: map[string][]time.Time{},
	}
}

func (l *GatewayLimiter) Enabled() bool {
	if l == nil {
		return false
	}
	return policyEnabled(l.cfg.PerKey) || policyEnabled(l.cfg.PerWorkspace)
}

func (l *GatewayLimiter) CheckRequest(r *http.Request, identity *auth.Identity) (*auth.ProxyLimitResult, error) {
	if l == nil || !l.Enabled() || identity == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	if l.nowFn != nil {
		now = l.nowFn().UTC()
	}
	if result, err := l.checkDailyUsage(r.Context(), identity, now); err != nil || result != nil {
		return result, err
	}
	return l.checkRequestRates(identity, now), nil
}

func (l *GatewayLimiter) checkDailyUsage(ctx context.Context, identity *auth.Identity, now time.Time) (*auth.ProxyLimitResult, error) {
	if l.store == nil {
		return nil, nil
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	tenantFilter := trace.AnalyticsFilter{
		OrgID:       strings.TrimSpace(identity.OrgID),
		WorkspaceID: strings.TrimSpace(identity.WorkspaceID),
		From:        dayStart,
		To:          now,
	}

	if result, err := l.checkPolicyUsage(ctx, l.cfg.PerKey, tenantFilter, strings.TrimSpace(identity.KeyID), "KEY"); err != nil || result != nil {
		return result, err
	}
	return l.checkPolicyUsage(ctx, l.cfg.PerWorkspace, tenantFilter, "", "WORKSPACE")
}

func (l *GatewayLimiter) checkPolicyUsage(
	ctx context.Context,
	policy Policy,
	filter trace.AnalyticsFilter,
	gatewayKeyID string,
	scope string,
) (*auth.ProxyLimitResult, error) {
	if !policyDailyUsageEnabled(policy) {
		return nil, nil
	}
	if gatewayKeyID != "" {
		filter.GatewayKeyID = gatewayKeyID
	}

	if policy.MaxTokensPerDay > 0 {
		usage, err := l.store.GetUsageSummary(ctx, filter)
		if err != nil {
			return nil, err
		}
		if usage != nil && usage.TotalTokens >= policy.MaxTokensPerDay {
			return &auth.ProxyLimitResult{
				Code:    scope + "_DAILY_TOKENS_EXCEEDED",
				Message: "daily token limit exceeded for " + strings.ToLower(scope),
			}, nil
		}
	}
	if policy.MaxCostUSDPerDay > 0 {
		cost, err := l.store.GetCostSummary(ctx, filter)
		if err != nil {
			return nil, err
		}
		if cost != nil && cost.TotalCostUSD >= policy.MaxCostUSDPerDay {
			return &auth.ProxyLimitResult{
				Code:    scope + "_DAILY_COST_EXCEEDED",
				Message: "daily cost limit exceeded for " + strings.ToLower(scope),
			}, nil
		}
	}
	return nil, nil
}

func (l *GatewayLimiter) checkRequestRates(identity *auth.Identity, now time.Time) *auth.ProxyLimitResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepRateState(now)

	if policy := l.cfg.PerKey; policy.RequestsPerMinute > 0 {
		key := perKeyRateKey(identity)
		events := pruneOldRequests(l.keyRequests[key], now)
		if len(events) >= policy.RequestsPerMinute {
			l.keyRequests[key] = events
			return &auth.ProxyLimitResult{
				Code:              "KEY_RATE_LIMIT_EXCEEDED",
				Message:           "request rate limit exceeded for key",
				RetryAfterSeconds: retryAfterSeconds(events, now),
			}
		}
		l.keyRequests[key] = append(events, now)
	}

	if policy := l.cfg.PerWorkspace; policy.RequestsPerMinute > 0 {
		key := perWorkspaceRateKey(identity)
		events := pruneOldRequests(l.workspaceRequests[key], now)
		if len(events) >= policy.RequestsPerMinute {
			l.workspaceRequests[key] = events
			return &auth.ProxyLimitResult{
				Code:              "WORKSPACE_RATE_LIMIT_EXCEEDED",
				Message:           "request rate limit exceeded for workspace",
				RetryAfterSeconds: retryAfterSeconds(events, now),
			}
		}
		l.workspaceRequests[key] = append(events, now)
	}

	return nil
}

func (l *GatewayLimiter) maybeSweepRateState(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < rateStateSweepInterval {
		return
	}

	for key, events := range l.keyRequests {
		pruned := pruneOldRequests(events, now)
		if len(pruned) == 0 {
			delete(l.keyRequests, key)
			continue
		}
		l.keyRequests[key] = pruned
	}
	for key, events := range l.workspaceRequests {
		pruned := pruneOldRequests(events, now)
		if len(pruned) == 0 {
			delete(l.workspaceRequests, key)
			continue
		}
		l.workspaceRequests[key] = pruned
	}
	l.lastSweep = now
}

func policyEnabled(policy Policy) bool {
	return policy.RequestsPerMinute > 0 || policy.MaxTokensPerDay > 0 || policy.MaxCostUSDPerDay > 0
}

func policyDailyUsageEnabled(policy Policy) bool {
	return policy.MaxTokensPerDay > 0 || policy.MaxCostUSDPerDay > 0
}

func pruneOldRequests(events []time.Time, now time.Time) []time.Time {
	if len(events) == 0 {
		return nil
	}
	cutoff := now.Add(-1 * time.Minute)
	keepIdx := 0
	for keepIdx < len(events) && events[keepIdx].Before(cutoff) {
		keepIdx++
	}
	if keepIdx >= len(events) {
		return nil
	}
	out := make([]time.Time, len(events)-keepIdx)
	copy(out, events[keepIdx:])
	return out
}

func retryAfterSeconds(events []time.Time, now time.Time) int {
	if len(events) == 0 {
		return 1
	}
	wait := events[0].Add(time.Minute).Sub(now).Seconds()
	if wait <= 1 {
		return 1
	}
	return int(math.Ceil(wait))
}

func perKeyRateKey(identity *auth.Identity) string {
	return strings.TrimSpace(identity.OrgID) + "|" + strings.TrimSpace(identity.WorkspaceID) + "|" + strings.TrimSpace(identity.KeyID)
}

func perWorkspaceRateKey(identity *auth.Identity) string {
	return strings.TrimSpace(identity.OrgID) + "|" + strings.TrimSpace(identity.WorkspaceID)
}
