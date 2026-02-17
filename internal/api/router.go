package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ongoingai/gateway/internal/configstore"
	"github.com/ongoingai/gateway/internal/trace"
)

type RouterOptions struct {
	AppVersion              string
	Store                   trace.TraceStore
	StorageDriver           string
	StoragePath             string
	GatewayKeyStore         configstore.GatewayKeyStore
	GatewayAuthHeader       string
	GatewayKeyAuditRecorder GatewayKeyAuditRecorder
}

func NewRouter(options RouterOptions) http.Handler {
	startedAt := time.Now().UTC()
	mux := http.NewServeMux()

	mux.Handle("/api/health", HealthHandler(HealthOptions{
		Version:       options.AppVersion,
		StartedAt:     startedAt,
		StorageDriver: options.StorageDriver,
		StoragePath:   options.StoragePath,
		Store:         options.Store,
	}))
	mux.Handle("/api/traces", TracesHandler(options.Store))
	mux.Handle("/api/traces/", TraceDetailHandler(options.Store))
	mux.Handle("/api/analytics/usage", UsageHandler(options.Store))
	mux.Handle("/api/analytics/cost", CostHandler(options.Store))
	mux.Handle("/api/analytics/models", ModelsHandler(options.Store))
	mux.Handle("/api/analytics/keys", KeysHandler(options.Store))
	mux.Handle("/api/analytics/summary", SummaryHandler(options.Store))
	mux.Handle("/api/gateway-keys", GatewayKeysHandler(options.GatewayKeyStore, options.GatewayKeyAuditRecorder))
	mux.Handle("/api/gateway-keys/", GatewayKeyDetailHandler(options.GatewayKeyStore, options.GatewayKeyAuditRecorder))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"name":    "ongoingai gateway",
			"version": options.AppVersion,
			"status":  "ok",
		})
	})

	return withCORS(mux, options.GatewayAuthHeader)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"error\":\"internal server error\"}\n"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method+", OPTIONS")
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func withCORS(next http.Handler, gatewayAuthHeader string) http.Handler {
	allowedHeaders := []string{"Content-Type", "Authorization", "X-API-Key", "X-OngoingAI-Gateway-Key"}
	customHeader := strings.TrimSpace(gatewayAuthHeader)
	if customHeader != "" {
		alreadyAllowed := false
		for _, header := range allowedHeaders {
			if strings.EqualFold(header, customHeader) {
				alreadyAllowed = true
				break
			}
		}
		if !alreadyAllowed {
			allowedHeaders = append(allowedHeaders, customHeader)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
