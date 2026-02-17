package api

import (
	"net/http"
	"strings"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/trace"
)

func applyTraceTenantScope(r *http.Request, filter *trace.TraceFilter) {
	if filter == nil || r == nil {
		return
	}
	if orgID, workspaceID, scoped := requestTenantScope(r); scoped {
		filter.OrgID = orgID
		filter.WorkspaceID = workspaceID
	}
}

func applyAnalyticsTenantScope(r *http.Request, filter *trace.AnalyticsFilter) {
	if filter == nil || r == nil {
		return
	}
	if orgID, workspaceID, scoped := requestTenantScope(r); scoped {
		filter.OrgID = orgID
		filter.WorkspaceID = workspaceID
	}
}

func requestTenantScope(r *http.Request) (string, string, bool) {
	if r == nil {
		return "", "", false
	}
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok || identity == nil {
		return "", "", false
	}
	return nonEmptyTenant(identity.OrgID), nonEmptyTenant(identity.WorkspaceID), true
}

func traceVisibleInTenantScope(r *http.Request, item *trace.Trace) bool {
	if item == nil {
		return false
	}
	orgID, workspaceID, scoped := requestTenantScope(r)
	if !scoped {
		return true
	}
	return nonEmptyTenant(item.OrgID) == orgID && nonEmptyTenant(item.WorkspaceID) == workspaceID
}

func nonEmptyTenant(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return value
}
