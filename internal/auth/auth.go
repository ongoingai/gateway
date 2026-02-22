package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/ongoingai/gateway/internal/pathutil"
)

type Permission string

const (
	PermissionProxyWrite    Permission = "proxy:write"
	PermissionAnalyticsRead Permission = "analytics:read"
	PermissionKeysManage    Permission = "keys:manage"
)

type AuthorizationRule struct {
	Resource   string
	Action     string
	Scope      string
	Permission Permission
	Methods    []string
	Path       string
	Public     bool
}

const defaultHeaderName = "X-OngoingAI-Gateway-Key"

var ErrMissingGatewayKey = errors.New("missing gateway key")
var ErrInvalidGatewayKey = errors.New("invalid gateway key")

type KeyConfig struct {
	ID          string
	Token       string
	TokenHash   string
	OrgID       string
	WorkspaceID string
	Team        string
	Role        string
	Permissions []string
}

type Options struct {
	Enabled bool
	Header  string
	Keys    []KeyConfig
}

type Identity struct {
	KeyID       string
	OrgID       string
	WorkspaceID string
	Team        string
	Role        string

	permissions map[Permission]struct{}
}

func (i *Identity) HasPermission(permission Permission) bool {
	if i == nil {
		return false
	}
	_, ok := i.permissions[permission]
	return ok
}

type Authorizer struct {
	enabled bool
	header  string
	keys    map[string]*Identity
}

func NewAuthorizer(options Options) (*Authorizer, error) {
	header := normalizeHeaderName(options.Header)
	if header == "" {
		header = defaultHeaderName
	}

	authorizer := &Authorizer{
		enabled: options.Enabled,
		header:  header,
		keys:    map[string]*Identity{},
	}
	if !options.Enabled {
		return authorizer, nil
	}
	if len(options.Keys) == 0 {
		return nil, errors.New("auth is enabled but no gateway keys are configured")
	}

	for _, key := range options.Keys {
		tokenHash := normalizeTokenHash(key.TokenHash)
		if tokenHash == "" {
			token := strings.TrimSpace(key.Token)
			if token == "" {
				return nil, errors.New("gateway key token cannot be empty")
			}
			tokenHash = hashToken(token)
		}
		if tokenHash == "" {
			return nil, errors.New("gateway key token cannot be empty")
		}
		if _, exists := authorizer.keys[tokenHash]; exists {
			return nil, errors.New("duplicate gateway key token in auth config")
		}

		permissions := defaultRolePermissions(key.Role)
		for _, raw := range key.Permissions {
			permission := Permission(strings.ToLower(strings.TrimSpace(raw)))
			if permission == "" {
				continue
			}
			permissions[permission] = struct{}{}
		}

		authorizer.keys[tokenHash] = &Identity{
			KeyID:       strings.TrimSpace(key.ID),
			OrgID:       nonEmpty(strings.TrimSpace(key.OrgID), "default"),
			WorkspaceID: nonEmpty(firstNonEmpty(strings.TrimSpace(key.WorkspaceID), strings.TrimSpace(key.Team)), "default"),
			Team:        firstNonEmpty(strings.TrimSpace(key.Team), strings.TrimSpace(key.WorkspaceID)),
			Role:        strings.ToLower(strings.TrimSpace(key.Role)),
			permissions: permissions,
		}
	}

	return authorizer, nil
}

func (a *Authorizer) Enabled() bool {
	return a != nil && a.enabled
}

func (a *Authorizer) HeaderName() string {
	if a == nil || strings.TrimSpace(a.header) == "" {
		return defaultHeaderName
	}
	return a.header
}

func (a *Authorizer) Authenticate(r *http.Request) (*Identity, error) {
	if !a.Enabled() {
		return nil, nil
	}

	token := strings.TrimSpace(r.Header.Get(a.HeaderName()))
	if token == "" {
		return nil, ErrMissingGatewayKey
	}

	identity, ok := a.keys[hashToken(token)]
	if !ok {
		return nil, ErrInvalidGatewayKey
	}
	return identity.clone(), nil
}

type MiddlewareOptions struct {
	APIPrefix          string
	OpenAIPrefix       string
	AnthropicPrefix    string
	ProxyLimiter       ProxyLimiter
	ProxyUsageRecorder ProxyUsageRecorder
	AuditRecorder      AuditRecorder
}

type AuthorizerResolver func(r *http.Request) (*Authorizer, error)
type ProxyLimiter func(r *http.Request, identity *Identity) (*ProxyLimitResult, error)
type ProxyUsageRecorder func(r *http.Request, identity *Identity)
type AuditRecorder func(r *http.Request, event AuditEvent)

type AuditEvent struct {
	Action             string
	Outcome            string
	Reason             string
	StatusCode         int
	Path               string
	Resource           string
	ResourceAction     string
	Scope              string
	Provider           string
	RequiredPermission Permission
	KeyID              string
	OrgID              string
	WorkspaceID        string
	LimitCode          string
}

type ProxyLimitResult struct {
	Code              string
	Message           string
	RetryAfterSeconds int
}

func Middleware(authorizer *Authorizer, options MiddlewareOptions, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if authorizer == nil || !authorizer.Enabled() {
		return next
	}
	return middlewareWithResolver(func(_ *http.Request) (*Authorizer, error) {
		return authorizer, nil
	}, options, next)
}

func DynamicMiddleware(resolver AuthorizerResolver, options MiddlewareOptions, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if resolver == nil {
		return next
	}
	return middlewareWithResolver(resolver, options, next)
}

func middlewareWithResolver(resolver AuthorizerResolver, options MiddlewareOptions, next http.Handler) http.Handler {
	apiPrefix := pathutil.NormalizePrefix(options.APIPrefix)
	if apiPrefix == "/" {
		apiPrefix = "/api"
	}
	openAIPrefix := pathutil.NormalizePrefix(options.OpenAIPrefix)
	anthropicPrefix := pathutil.NormalizePrefix(options.AnthropicPrefix)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decision := requiredAccess(r.Method, r.URL.Path, apiPrefix, openAIPrefix, anthropicPrefix)
		if decision.mode == accessModeBypass {
			next.ServeHTTP(w, r)
			return
		}
		recordDeny := func(statusCode int, reason string, identity *Identity, limitCode string) {
			if options.AuditRecorder == nil {
				return
			}
			event := AuditEvent{
				Action:             "gateway_auth",
				Outcome:            "deny",
				Reason:             strings.TrimSpace(reason),
				StatusCode:         statusCode,
				Path:               r.URL.Path,
				Resource:           strings.TrimSpace(decision.resource),
				ResourceAction:     strings.TrimSpace(decision.resourceAction),
				Scope:              strings.TrimSpace(decision.scope),
				Provider:           decision.provider,
				RequiredPermission: decision.permission,
				LimitCode:          strings.TrimSpace(limitCode),
			}
			if identity != nil {
				event.KeyID = strings.TrimSpace(identity.KeyID)
				event.OrgID = nonEmpty(strings.TrimSpace(identity.OrgID), "default")
				event.WorkspaceID = nonEmpty(strings.TrimSpace(identity.WorkspaceID), "default")
			}
			options.AuditRecorder(r, event)
		}
		if decision.mode == accessModeDeny {
			recordDeny(http.StatusForbidden, nonEmpty(strings.TrimSpace(decision.denyReason), "action_not_allowed"), nil, "")
			writeAuthError(w, http.StatusForbidden, "request is not authorized by gateway policy")
			return
		}

		authorizer, err := resolver(r)
		if err != nil || authorizer == nil || !authorizer.Enabled() {
			recordDeny(http.StatusServiceUnavailable, "verification_unavailable", nil, "")
			writeAuthError(w, http.StatusServiceUnavailable, "gateway key verification unavailable")
			return
		}

		identity, err := authorizer.Authenticate(r)
		if err != nil {
			reason := "invalid_gateway_key"
			if errors.Is(err, ErrMissingGatewayKey) {
				reason = "missing_gateway_key"
			}
			recordDeny(http.StatusUnauthorized, reason, nil, "")
			writeAuthError(w, http.StatusUnauthorized, "missing or invalid gateway key")
			return
		}
		if !identity.HasPermission(decision.permission) {
			recordDeny(http.StatusForbidden, "permission_denied", identity, "")
			writeAuthError(w, http.StatusForbidden, "gateway key does not have required permission")
			return
		}

		request := r.Clone(WithIdentity(r.Context(), identity))
		request.Header = r.Header.Clone()
		request.Header.Del(authorizer.HeaderName())

		if decision.provider != "" && !hasProviderCredential(request.Header, decision.provider) {
			recordDeny(http.StatusForbidden, "missing_provider_credential", identity, "")
			writeAuthError(w, http.StatusForbidden, "missing provider API key — pass your provider key via Authorization or X-API-Key header")
			return
		}
		if decision.provider != "" && options.ProxyLimiter != nil {
			limitResult, err := options.ProxyLimiter(request, identity)
			if err != nil {
				recordDeny(http.StatusServiceUnavailable, "usage_limit_check_unavailable", identity, "")
				writeAuthError(w, http.StatusServiceUnavailable, "gateway usage limit check unavailable")
				return
			}
			if limitResult != nil {
				recordDeny(http.StatusTooManyRequests, "usage_limit_exceeded", identity, limitResult.Code)
				writeProxyLimitError(w, *limitResult)
				return
			}
		}
		if decision.provider != "" && options.ProxyUsageRecorder != nil {
			options.ProxyUsageRecorder(request, identity)
		}

		next.ServeHTTP(w, request)
	})
}

type accessMode int

const (
	accessModeBypass accessMode = iota
	accessModeRequirePermission
	accessModeDeny
)

type accessDecision struct {
	mode           accessMode
	resource       string
	resourceAction string
	scope          string
	permission     Permission
	provider       string
	denyReason     string
}

func requiredAccess(method, path, apiPrefix, openAIPrefix, anthropicPrefix string) accessDecision {
	method = strings.ToUpper(strings.TrimSpace(method))

	if isPreflight(method) && (pathutil.HasPathPrefix(path, apiPrefix) || pathutil.HasPathPrefix(path, openAIPrefix) || pathutil.HasPathPrefix(path, anthropicPrefix)) {
		return accessDecision{mode: accessModeBypass}
	}

	switch {
	case pathutil.HasPathPrefix(path, openAIPrefix):
		return accessDecision{
			mode:           accessModeRequirePermission,
			resource:       "proxy",
			resourceAction: "forward",
			scope:          "workspace",
			permission:     PermissionProxyWrite,
			provider:       "openai",
		}
	case pathutil.HasPathPrefix(path, anthropicPrefix):
		return accessDecision{
			mode:           accessModeRequirePermission,
			resource:       "proxy",
			resourceAction: "forward",
			scope:          "workspace",
			permission:     PermissionProxyWrite,
			provider:       "anthropic",
		}
	case pathutil.HasPathPrefix(path, apiPrefix):
		switch {
		case path == apiPrefix+"/health" && isReadMethod(method):
			return accessDecision{mode: accessModeBypass}
		case (path == apiPrefix+"/traces" || isTraceDetailPath(path, apiPrefix) || isTraceReplayPath(path, apiPrefix)) && isReadMethod(method):
			return accessDecision{
				mode:           accessModeRequirePermission,
				resource:       "traces",
				resourceAction: "read",
				scope:          "workspace",
				permission:     PermissionAnalyticsRead,
			}
		case isTraceForkPath(path, apiPrefix) && method == http.MethodPost:
			return accessDecision{
				mode:           accessModeRequirePermission,
				resource:       "traces",
				resourceAction: "read",
				scope:          "workspace",
				permission:     PermissionAnalyticsRead,
			}
		case isAnalyticsPath(path, apiPrefix) && isReadMethod(method):
			return accessDecision{
				mode:           accessModeRequirePermission,
				resource:       "analytics",
				resourceAction: "read",
				scope:          "workspace",
				permission:     PermissionAnalyticsRead,
			}
		case isDiagnosticsPath(path, apiPrefix) && isReadMethod(method):
			return accessDecision{
				mode:           accessModeRequirePermission,
				resource:       "diagnostics",
				resourceAction: "read",
				scope:          "workspace",
				permission:     PermissionAnalyticsRead,
			}
		case path == apiPrefix+"/gateway-keys" && (method == http.MethodGet || method == http.MethodPost):
			return accessDecision{
				mode:           accessModeRequirePermission,
				resource:       "gateway_keys",
				resourceAction: "manage",
				scope:          "workspace",
				permission:     PermissionKeysManage,
			}
		case isGatewayKeyRevokePath(path, apiPrefix) && method == http.MethodDelete:
			return accessDecision{
				mode:           accessModeRequirePermission,
				resource:       "gateway_keys",
				resourceAction: "manage",
				scope:          "workspace",
				permission:     PermissionKeysManage,
			}
		case isGatewayKeyRotatePath(path, apiPrefix) && method == http.MethodPost:
			return accessDecision{
				mode:           accessModeRequirePermission,
				resource:       "gateway_keys",
				resourceAction: "manage",
				scope:          "workspace",
				permission:     PermissionKeysManage,
			}
		default:
			return accessDecision{
				mode:       accessModeDeny,
				resource:   "api",
				scope:      "workspace",
				denyReason: "action_unmapped",
			}
		}
	default:
		return accessDecision{mode: accessModeBypass}
	}
}

func hasProviderCredential(header http.Header, provider string) bool {
	switch provider {
	case "openai":
		return strings.TrimSpace(header.Get("Authorization")) != "" || strings.TrimSpace(header.Get("X-API-Key")) != ""
	case "anthropic":
		return strings.TrimSpace(header.Get("X-API-Key")) != "" || strings.TrimSpace(header.Get("Authorization")) != ""
	default:
		return true
	}
}

func defaultRolePermissions(role string) map[Permission]struct{} {
	permissions := map[Permission]struct{}{}
	for _, permission := range permissionsForRole(role) {
		permissions[permission] = struct{}{}
	}
	return permissions
}

func permissionsForRole(role string) []Permission {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner", "admin":
		return []Permission{
			PermissionProxyWrite,
			PermissionAnalyticsRead,
			PermissionKeysManage,
		}
	case "viewer":
		return []Permission{
			PermissionAnalyticsRead,
		}
	case "", "developer", "member":
		return []Permission{
			PermissionProxyWrite,
			PermissionAnalyticsRead,
		}
	default:
		// Unknown roles receive no implicit permissions; explicit permissions can
		// still be granted in key config.
		return nil
	}
}

// AuthorizationMatrix documents the enforced gateway policy in resource/action terms.
func AuthorizationMatrix() []AuthorizationRule {
	return []AuthorizationRule{
		{
			Resource:   "health",
			Action:     "read",
			Scope:      "public",
			Methods:    []string{http.MethodGet, http.MethodHead},
			Path:       "/api/health",
			Public:     true,
			Permission: "",
		},
		{
			Resource:   "traces",
			Action:     "read",
			Scope:      "workspace",
			Methods:    []string{http.MethodGet, http.MethodHead},
			Path:       "/api/traces and /api/traces/:id plus replay/fork subroutes",
			Permission: PermissionAnalyticsRead,
		},
		{
			Resource:   "analytics",
			Action:     "read",
			Scope:      "workspace",
			Methods:    []string{http.MethodGet, http.MethodHead},
			Path:       "/api/analytics/*",
			Permission: PermissionAnalyticsRead,
		},
		{
			Resource:   "diagnostics",
			Action:     "read",
			Scope:      "workspace",
			Methods:    []string{http.MethodGet, http.MethodHead},
			Path:       "/api/diagnostics/trace-pipeline",
			Permission: PermissionAnalyticsRead,
		},
		{
			Resource:   "gateway_keys",
			Action:     "manage",
			Scope:      "workspace",
			Methods:    []string{http.MethodGet, http.MethodPost, http.MethodDelete},
			Path:       "/api/gateway-keys*",
			Permission: PermissionKeysManage,
		},
		{
			Resource:   "proxy",
			Action:     "forward",
			Scope:      "workspace",
			Methods:    []string{"*"},
			Path:       "/openai/* and /anthropic/*",
			Permission: PermissionProxyWrite,
		},
	}
}

func isReadMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

func isPreflight(method string) bool {
	return strings.EqualFold(strings.TrimSpace(method), http.MethodOptions)
}

func isTraceDetailPath(path, apiPrefix string) bool {
	id, action, ok := parseTracePath(path, apiPrefix)
	return ok && id != "" && action == ""
}

func isTraceReplayPath(path, apiPrefix string) bool {
	id, action, ok := parseTracePath(path, apiPrefix)
	return ok && id != "" && action == "replay"
}

func isTraceForkPath(path, apiPrefix string) bool {
	id, action, ok := parseTracePath(path, apiPrefix)
	return ok && id != "" && action == "fork"
}

func parseTracePath(path, apiPrefix string) (string, string, bool) {
	prefix := apiPrefix + "/traces/"
	if !pathutil.HasPathPrefix(path, prefix) {
		return "", "", false
	}
	suffix := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	if suffix == "" {
		return "", "", false
	}
	parts := strings.Split(suffix, "/")
	if len(parts) > 2 {
		return "", "", false
	}
	id := strings.TrimSpace(parts[0])
	if id == "" {
		return "", "", false
	}
	action := ""
	if len(parts) == 2 {
		action = strings.TrimSpace(parts[1])
		if action == "" {
			return "", "", false
		}
	}
	return id, action, true
}

func isAnalyticsPath(path, apiPrefix string) bool {
	switch path {
	case apiPrefix + "/analytics/usage",
		apiPrefix + "/analytics/cost",
		apiPrefix + "/analytics/models",
		apiPrefix + "/analytics/keys",
		apiPrefix + "/analytics/summary":
		return true
	default:
		return false
	}
}

func isDiagnosticsPath(path, apiPrefix string) bool {
	switch path {
	case apiPrefix + "/diagnostics/trace-pipeline":
		return true
	default:
		return false
	}
}

func isGatewayKeyRevokePath(path, apiPrefix string) bool {
	prefix := apiPrefix + "/gateway-keys/"
	if !pathutil.HasPathPrefix(path, prefix) {
		return false
	}
	suffix := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	return suffix != "" && !strings.Contains(suffix, "/")
}

func isGatewayKeyRotatePath(path, apiPrefix string) bool {
	prefix := apiPrefix + "/gateway-keys/"
	if !pathutil.HasPathPrefix(path, prefix) {
		return false
	}
	suffix := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	parts := strings.Split(suffix, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] == "rotate"
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func writeProxyLimitError(w http.ResponseWriter, result ProxyLimitResult) {
	message := strings.TrimSpace(result.Message)
	if message == "" {
		message = "gateway usage limit exceeded"
	}
	payload := map[string]any{
		"error": message,
	}
	if code := strings.TrimSpace(result.Code); code != "" {
		payload["code"] = code
	}
	if result.RetryAfterSeconds > 0 {
		payload["retry_after_seconds"] = result.RetryAfterSeconds
		w.Header().Set("Retry-After", strconv.Itoa(result.RetryAfterSeconds))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(payload)
}

func normalizeHeaderName(header string) string {
	value := strings.TrimSpace(header)
	if value == "" {
		return ""
	}
	return textproto.CanonicalMIMEHeaderKey(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func nonEmpty(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func normalizeTokenHash(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	return value
}

func (i *Identity) clone() *Identity {
	if i == nil {
		return nil
	}
	out := *i
	if len(i.permissions) > 0 {
		out.permissions = make(map[Permission]struct{}, len(i.permissions))
		for permission := range i.permissions {
			out.permissions[permission] = struct{}{}
		}
	}
	return &out
}

type contextIdentityKey struct{}

func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if identity == nil {
		return ctx
	}
	return context.WithValue(ctx, contextIdentityKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	if ctx == nil {
		return nil, false
	}
	identity, ok := ctx.Value(contextIdentityKey{}).(*Identity)
	return identity, ok && identity != nil
}
