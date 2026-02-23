package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/config"
)

type piiGuardrailDecision struct {
	blocked bool
	reason  string
	counts  map[string]int
}

const (
	piiGuardrailBlockedMessage     = "request blocked by pii policy"
	piiGuardrailUncertaintyMessage = "request denied by pii guardrail policy uncertainty"
)

func piiGuardrailMiddleware(cfg config.Config, logger *slog.Logger, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if logger == nil {
		logger = slog.Default()
	}

	maxBodySize := cfg.Tracing.BodyMaxSize
	if maxBodySize <= 0 {
		maxBodySize = 1 << 20
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := detectProvider(cfg, r.URL.Path)
		if provider == "unknown" {
			next.ServeHTTP(w, r)
			return
		}

		orgID, workspaceID, keyID := gatewayIdentityFromContext(r)
		policy := cfg.ResolvePIIPolicy(config.PIIScopeInput{
			OrgID:       orgID,
			WorkspaceID: workspaceID,
			KeyID:       keyID,
			Provider:    provider,
			Route:       r.URL.Path,
		})
		mode := policy.Mode
		if mode != config.PIIModeRedactUpstream && mode != config.PIIModeBlock {
			next.ServeHTTP(w, r)
			return
		}

		decision, err := applyRequestPIIGuardrails(r, mode, policy, workspaceID, maxBodySize)
		if err != nil {
			logPIIGuardrailDeny(logger, r, mode, "policy_evaluation_failed", orgID, workspaceID, keyID, nil, err)
			http.Error(w, piiGuardrailUncertaintyMessage, http.StatusServiceUnavailable)
			return
		}
		if decision.blocked {
			logPIIGuardrailDeny(logger, r, mode, decision.reason, orgID, workspaceID, keyID, decision.counts, nil)
			http.Error(w, piiGuardrailBlockedMessage, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func applyRequestPIIGuardrails(
	req *http.Request,
	mode string,
	piiCfg config.PIIConfig,
	workspaceID string,
	maxBodySize int,
) (piiGuardrailDecision, error) {
	if req == nil {
		return piiGuardrailDecision{}, nil
	}
	if !piiCfg.Stages.RequestBody {
		return piiGuardrailDecision{}, nil
	}
	if req.Body == nil || req.Body == http.NoBody {
		return piiGuardrailDecision{}, nil
	}

	body, truncated, err := readAndRestoreRequestBody(req, maxBodySize)
	if err != nil {
		return piiGuardrailDecision{}, fmt.Errorf("read request body: %w", err)
	}
	if truncated {
		return piiGuardrailDecision{}, fmt.Errorf("request body exceeds pii inspection limit (%d bytes)", maxBodySize)
	}
	if len(body) == 0 {
		return piiGuardrailDecision{}, nil
	}
	if !isPIIGuardrailContentType(req.Header.Get("Content-Type")) {
		return piiGuardrailDecision{}, fmt.Errorf("unsupported content type for pii guardrail mode: %q", req.Header.Get("Content-Type"))
	}

	summary := newRedactionSummary()
	redactedBody, err := redactBodyForStorage(body, piiCfg, workspaceID, &summary)
	if err != nil {
		return piiGuardrailDecision{}, fmt.Errorf("redact request body: %w", err)
	}

	switch mode {
	case config.PIIModeBlock:
		if summary.applied {
			return piiGuardrailDecision{
				blocked: true,
				reason:  "pii_detected",
				counts:  summary.counts,
			}, nil
		}
	case config.PIIModeRedactUpstream:
		if summary.applied {
			setRequestBody(req, []byte(redactedBody))
		}
	}

	return piiGuardrailDecision{}, nil
}

func readAndRestoreRequestBody(req *http.Request, maxBodySize int) ([]byte, bool, error) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil, false, nil
	}
	if maxBodySize < 0 {
		maxBodySize = 0
	}

	limited := &io.LimitedReader{R: req.Body, N: int64(maxBodySize) + 1}
	data, err := io.ReadAll(limited)
	closeErr := req.Body.Close()
	if err != nil {
		return nil, false, err
	}
	if closeErr != nil {
		return nil, false, closeErr
	}

	truncated := len(data) > maxBodySize
	if truncated {
		data = data[:maxBodySize]
	}
	setRequestBody(req, data)
	return data, truncated, nil
}

func setRequestBody(req *http.Request, body []byte) {
	if req == nil {
		return
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}

	copied := append([]byte(nil), body...)
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(copied)), nil
	}
	if len(copied) == 0 {
		req.Body = http.NoBody
		req.ContentLength = 0
		req.TransferEncoding = nil
		req.Header.Del("Content-Length")
		return
	}

	req.Body = io.NopCloser(bytes.NewReader(copied))
	req.ContentLength = int64(len(copied))
	req.TransferEncoding = nil
	req.Header.Set("Content-Length", strconv.Itoa(len(copied)))
}

func isPIIGuardrailContentType(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(trimmed)
	if err != nil {
		return false
	}
	if mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") {
		return true
	}
	return strings.HasPrefix(mediaType, "text/")
}

func gatewayIdentityFromContext(req *http.Request) (orgID, workspaceID, keyID string) {
	workspaceID = "default"
	if req == nil {
		return "", workspaceID, ""
	}
	identity, ok := auth.IdentityFromContext(req.Context())
	if !ok || identity == nil {
		return "", workspaceID, ""
	}
	if v := strings.TrimSpace(identity.OrgID); v != "" {
		orgID = v
	}
	if v := strings.TrimSpace(identity.WorkspaceID); v != "" {
		workspaceID = v
	}
	if v := strings.TrimSpace(identity.KeyID); v != "" {
		keyID = v
	}
	return orgID, workspaceID, keyID
}

func logPIIGuardrailDeny(
	logger *slog.Logger,
	req *http.Request,
	mode string,
	reason string,
	orgID string,
	workspaceID string,
	keyID string,
	counts map[string]int,
	err error,
) {
	if logger == nil || req == nil {
		return
	}

	attrs := []any{
		"mode", mode,
		"reason", reason,
		"method", req.Method,
		"path", req.URL.Path,
	}
	if orgID != "" {
		attrs = append(attrs, "org_id", orgID)
	}
	if workspaceID != "" {
		attrs = append(attrs, "workspace_id", workspaceID)
	}
	if keyID != "" {
		attrs = append(attrs, "key_id", keyID)
	}
	if len(counts) > 0 {
		attrs = append(attrs, "redaction_counts", counts)
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}

	logger.WarnContext(req.Context(), "pii guardrail denied request", attrs...)
}
