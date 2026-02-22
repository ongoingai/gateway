package api

import (
	"net/http"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

const tracePipelineDiagnosticsSchemaVersion = "trace-pipeline-diagnostics.v1"

type TracePipelineDiagnosticsOptions struct {
	Reader trace.TracePipelineDiagnosticsReader
}

type tracePipelineDiagnosticsResponse struct {
	SchemaVersion string                         `json:"schema_version"`
	GeneratedAt   time.Time                      `json:"generated_at"`
	Diagnostics   trace.TracePipelineDiagnostics `json:"diagnostics"`
}

func TracePipelineDiagnosticsHandler(options TracePipelineDiagnosticsOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if options.Reader == nil {
			writeError(w, http.StatusServiceUnavailable, "trace pipeline diagnostics unavailable")
			return
		}

		writeJSON(w, http.StatusOK, tracePipelineDiagnosticsResponse{
			SchemaVersion: tracePipelineDiagnosticsSchemaVersion,
			GeneratedAt:   time.Now().UTC(),
			Diagnostics:   options.Reader.TracePipelineDiagnostics(),
		})
	})
}
