package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/configstore"
)

const gatewayKeyMutationBodyLimit int64 = 64 << 10

var errGatewayKeyMutationBodyTooLarge = errors.New("gateway key mutation body too large")
var errGatewayKeyMutationInvalidJSON = errors.New("gateway key mutation invalid json")

type gatewayKeysResponse struct {
	Items []gatewayKeyResponse `json:"items"`
}

type gatewayKeyResponse struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	WorkspaceID string    `json:"workspace_id"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	Role        string    `json:"role,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

type gatewayKeySecretResponse struct {
	gatewayKeyResponse
	Token string `json:"token"`
}

type GatewayKeyAuditEvent struct {
	Action      string
	Outcome     string
	Reason      string
	StatusCode  int
	ActorKeyID  string
	OrgID       string
	WorkspaceID string
	TargetKeyID string
}

type GatewayKeyAuditRecorder func(r *http.Request, event GatewayKeyAuditEvent)

type createGatewayKeyRequest struct {
	ID          string   `json:"id"`
	Token       string   `json:"token"`
	OrgID       string   `json:"org_id"`
	WorkspaceID string   `json:"workspace_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type rotateGatewayKeyRequest struct {
	Token string `json:"token"`
}

func GatewayKeysHandler(store configstore.GatewayKeyStore, auditRecorder GatewayKeyAuditRecorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListGatewayKeys(w, r, store)
		case http.MethodPost:
			handleCreateGatewayKey(w, r, store, auditRecorder)
		default:
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
}

func GatewayKeyDetailHandler(store configstore.GatewayKeyStore, auditRecorder GatewayKeyAuditRecorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/gateway-keys/")
		if path == "" {
			http.NotFound(w, r)
			return
		}
		parts := strings.Split(path, "/")
		if len(parts) == 1 {
			if r.Method != http.MethodDelete {
				w.Header().Set("Allow", "DELETE, OPTIONS")
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleRevokeGatewayKey(w, r, store, parts[0], auditRecorder)
			return
		}
		if len(parts) == 2 && parts[1] == "rotate" {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST, OPTIONS")
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			handleRotateGatewayKey(w, r, store, parts[0], auditRecorder)
			return
		}
		http.NotFound(w, r)
	})
}

func handleListGatewayKeys(w http.ResponseWriter, r *http.Request, store configstore.GatewayKeyStore) {
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "gateway key store is not configured")
		return
	}

	filter := gatewayKeyTenantFilter(r)
	items, err := store.ListGatewayKeys(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list gateway keys")
		return
	}

	out := make([]gatewayKeyResponse, 0, len(items))
	for _, item := range items {
		out = append(out, toGatewayKeyResponse(item))
	}
	writeJSON(w, http.StatusOK, gatewayKeysResponse{Items: out})
}

func handleCreateGatewayKey(w http.ResponseWriter, r *http.Request, store configstore.GatewayKeyStore, auditRecorder GatewayKeyAuditRecorder) {
	recordAudit := func(outcome, reason string, statusCode int, key configstore.GatewayKey) {
		emitGatewayKeyAudit(r, auditRecorder, GatewayKeyAuditEvent{
			Action:      "create",
			Outcome:     strings.TrimSpace(outcome),
			Reason:      strings.TrimSpace(reason),
			StatusCode:  statusCode,
			ActorKeyID:  requestActor(r),
			OrgID:       nonEmptyTenant(key.OrgID),
			WorkspaceID: nonEmptyTenant(key.WorkspaceID),
			TargetKeyID: strings.TrimSpace(key.ID),
		})
	}

	if store == nil {
		recordAudit("error", "store_unavailable", http.StatusServiceUnavailable, configstore.GatewayKey{})
		writeError(w, http.StatusServiceUnavailable, "gateway key store is not configured")
		return
	}

	var body createGatewayKeyRequest
	if err := decodeGatewayKeyMutationBody(w, r, &body); err != nil {
		switch {
		case errors.Is(err, errGatewayKeyMutationBodyTooLarge):
			recordAudit("error", "body_too_large", http.StatusRequestEntityTooLarge, configstore.GatewayKey{})
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		default:
			recordAudit("error", "invalid_json", http.StatusBadRequest, configstore.GatewayKey{})
			writeError(w, http.StatusBadRequest, "invalid json body")
		}
		return
	}

	id := strings.TrimSpace(body.ID)
	if id == "" {
		var err error
		id, err = generateGatewayKeyID()
		if err != nil {
			recordAudit("error", "generate_id_failed", http.StatusInternalServerError, configstore.GatewayKey{})
			writeError(w, http.StatusInternalServerError, "failed to generate gateway key id")
			return
		}
	}
	token := strings.TrimSpace(body.Token)
	if token == "" {
		var err error
		token, err = generateGatewayKeyToken()
		if err != nil {
			recordAudit("error", "generate_token_failed", http.StatusInternalServerError, configstore.GatewayKey{
				ID: id,
			})
			writeError(w, http.StatusInternalServerError, "failed to generate gateway key token")
			return
		}
	}

	orgID, workspaceID := tenantOrRequestScope(r, body.OrgID, body.WorkspaceID)
	row := configstore.GatewayKey{
		ID:          id,
		Token:       token,
		OrgID:       orgID,
		WorkspaceID: workspaceID,
		Team:        workspaceID,
		Name:        strings.TrimSpace(body.Name),
		Description: strings.TrimSpace(body.Description),
		CreatedBy:   requestActor(r),
		Role:        strings.TrimSpace(body.Role),
		Permissions: append([]string(nil), body.Permissions...),
	}
	created, err := store.CreateGatewayKey(r.Context(), row)
	if err != nil {
		switch {
		case errors.Is(err, configstore.ErrNotImplemented):
			recordAudit("error", "not_implemented", http.StatusNotImplemented, row)
			writeError(w, http.StatusNotImplemented, "gateway key mutations are not supported by this config store")
		case errors.Is(err, configstore.ErrConflict):
			recordAudit("error", "conflict", http.StatusConflict, row)
			writeError(w, http.StatusConflict, "gateway key already exists")
		default:
			recordAudit("error", "create_failed", http.StatusInternalServerError, row)
			writeError(w, http.StatusInternalServerError, "failed to create gateway key")
		}
		return
	}
	recordAudit("success", "", http.StatusCreated, *created)

	resp := gatewayKeySecretResponse{
		gatewayKeyResponse: toGatewayKeyResponse(*created),
		Token:              created.Token,
	}
	writeJSON(w, http.StatusCreated, resp)
}

func handleRevokeGatewayKey(w http.ResponseWriter, r *http.Request, store configstore.GatewayKeyStore, id string, auditRecorder GatewayKeyAuditRecorder) {
	recordAudit := func(outcome, reason string, statusCode int) {
		orgID, workspaceID, scoped := requestTenantScope(r)
		if !scoped {
			orgID = "default"
			workspaceID = "default"
		}
		emitGatewayKeyAudit(r, auditRecorder, GatewayKeyAuditEvent{
			Action:      "revoke",
			Outcome:     strings.TrimSpace(outcome),
			Reason:      strings.TrimSpace(reason),
			StatusCode:  statusCode,
			ActorKeyID:  requestActor(r),
			OrgID:       orgID,
			WorkspaceID: workspaceID,
			TargetKeyID: strings.TrimSpace(id),
		})
	}

	if store == nil {
		recordAudit("error", "store_unavailable", http.StatusServiceUnavailable)
		writeError(w, http.StatusServiceUnavailable, "gateway key store is not configured")
		return
	}
	err := store.RevokeGatewayKey(r.Context(), strings.TrimSpace(id), gatewayKeyTenantFilter(r))
	if err != nil {
		switch {
		case errors.Is(err, configstore.ErrNotImplemented):
			recordAudit("error", "not_implemented", http.StatusNotImplemented)
			writeError(w, http.StatusNotImplemented, "gateway key mutations are not supported by this config store")
		case errors.Is(err, configstore.ErrNotFound):
			recordAudit("error", "not_found", http.StatusNotFound)
			writeError(w, http.StatusNotFound, "gateway key not found")
		default:
			recordAudit("error", "revoke_failed", http.StatusInternalServerError)
			writeError(w, http.StatusInternalServerError, "failed to revoke gateway key")
		}
		return
	}
	recordAudit("success", "", http.StatusNoContent)
	w.WriteHeader(http.StatusNoContent)
}

func handleRotateGatewayKey(w http.ResponseWriter, r *http.Request, store configstore.GatewayKeyStore, id string, auditRecorder GatewayKeyAuditRecorder) {
	recordAudit := func(outcome, reason string, statusCode int) {
		orgID, workspaceID, scoped := requestTenantScope(r)
		if !scoped {
			orgID = "default"
			workspaceID = "default"
		}
		emitGatewayKeyAudit(r, auditRecorder, GatewayKeyAuditEvent{
			Action:      "rotate",
			Outcome:     strings.TrimSpace(outcome),
			Reason:      strings.TrimSpace(reason),
			StatusCode:  statusCode,
			ActorKeyID:  requestActor(r),
			OrgID:       orgID,
			WorkspaceID: workspaceID,
			TargetKeyID: strings.TrimSpace(id),
		})
	}

	if store == nil {
		recordAudit("error", "store_unavailable", http.StatusServiceUnavailable)
		writeError(w, http.StatusServiceUnavailable, "gateway key store is not configured")
		return
	}

	var body rotateGatewayKeyRequest
	if err := decodeGatewayKeyMutationBody(w, r, &body); err != nil {
		switch {
		case errors.Is(err, errGatewayKeyMutationBodyTooLarge):
			recordAudit("error", "body_too_large", http.StatusRequestEntityTooLarge)
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		default:
			recordAudit("error", "invalid_json", http.StatusBadRequest)
			writeError(w, http.StatusBadRequest, "invalid json body")
		}
		return
	}
	token := strings.TrimSpace(body.Token)
	if token == "" {
		var err error
		token, err = generateGatewayKeyToken()
		if err != nil {
			recordAudit("error", "generate_token_failed", http.StatusInternalServerError)
			writeError(w, http.StatusInternalServerError, "failed to generate gateway key token")
			return
		}
	}

	rotated, err := store.RotateGatewayKey(r.Context(), strings.TrimSpace(id), token, gatewayKeyTenantFilter(r))
	if err != nil {
		switch {
		case errors.Is(err, configstore.ErrNotImplemented):
			recordAudit("error", "not_implemented", http.StatusNotImplemented)
			writeError(w, http.StatusNotImplemented, "gateway key mutations are not supported by this config store")
		case errors.Is(err, configstore.ErrNotFound):
			recordAudit("error", "not_found", http.StatusNotFound)
			writeError(w, http.StatusNotFound, "gateway key not found")
		case errors.Is(err, configstore.ErrConflict):
			recordAudit("error", "conflict", http.StatusConflict)
			writeError(w, http.StatusConflict, "gateway key token already exists")
		default:
			recordAudit("error", "rotate_failed", http.StatusInternalServerError)
			writeError(w, http.StatusInternalServerError, "failed to rotate gateway key")
		}
		return
	}
	recordAudit("success", "", http.StatusOK)

	resp := gatewayKeySecretResponse{
		gatewayKeyResponse: toGatewayKeyResponse(*rotated),
		Token:              rotated.Token,
	}
	writeJSON(w, http.StatusOK, resp)
}

func toGatewayKeyResponse(item configstore.GatewayKey) gatewayKeyResponse {
	return gatewayKeyResponse{
		ID:          item.ID,
		OrgID:       item.OrgID,
		WorkspaceID: item.WorkspaceID,
		Name:        item.Name,
		Description: item.Description,
		CreatedBy:   item.CreatedBy,
		LastUsedAt:  item.LastUsedAt,
		Role:        item.Role,
		Permissions: append([]string(nil), item.Permissions...),
		CreatedAt:   item.CreatedAt,
	}
}

func requestActor(r *http.Request) string {
	if r == nil {
		return "system"
	}
	identity, ok := auth.IdentityFromContext(r.Context())
	if !ok {
		return "system"
	}
	keyID := strings.TrimSpace(identity.KeyID)
	if keyID == "" {
		return "system"
	}
	return keyID
}

func emitGatewayKeyAudit(r *http.Request, recorder GatewayKeyAuditRecorder, event GatewayKeyAuditEvent) {
	if recorder == nil {
		return
	}
	recorder(r, event)
}

func gatewayKeyTenantFilter(r *http.Request) configstore.GatewayKeyFilter {
	orgID, workspaceID, scoped := requestTenantScope(r)
	if !scoped {
		return configstore.GatewayKeyFilter{}
	}
	return configstore.GatewayKeyFilter{
		OrgID:       orgID,
		WorkspaceID: workspaceID,
	}
}

func decodeGatewayKeyMutationBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if r == nil || r.Body == nil {
		return nil
	}

	r.Body = http.MaxBytesReader(w, r.Body, gatewayKeyMutationBodyLimit)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return errGatewayKeyMutationBodyTooLarge
		}
		return errGatewayKeyMutationInvalidJSON
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errGatewayKeyMutationInvalidJSON
	}

	return nil
}

func tenantOrRequestScope(r *http.Request, requestedOrgID, requestedWorkspaceID string) (string, string) {
	orgID, workspaceID, scoped := requestTenantScope(r)
	if scoped {
		return orgID, workspaceID
	}
	org := strings.TrimSpace(requestedOrgID)
	if org == "" {
		org = "default"
	}
	workspace := strings.TrimSpace(requestedWorkspaceID)
	if workspace == "" {
		workspace = "default"
	}
	return org, workspace
}

func generateGatewayKeyID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return "gk_" + hex.EncodeToString(buf), nil
}

func generateGatewayKeyToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return "ogk_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
