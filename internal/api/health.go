package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

type HealthOptions struct {
	Version       string
	StartedAt     time.Time
	StorageDriver string
	StoragePath   string
	Store         trace.TraceStore
}

type healthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSec     int64  `json:"uptime_sec"`
	StorageDriver string `json:"storage_driver"`
	TraceCount    int64  `json:"trace_count"`
	DBSizeBytes   int64  `json:"db_size_bytes,omitempty"`
}

func HealthHandler(options HealthOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}

		uptime := time.Since(options.StartedAt)
		traceCount := int64(0)
		if options.Store != nil {
			if models, err := options.Store.GetModelStats(r.Context(), trace.AnalyticsFilter{}); err == nil {
				for _, model := range models {
					traceCount += model.RequestCount
				}
			}
		}

		dbSizeBytes := int64(0)
		if strings.EqualFold(options.StorageDriver, "sqlite") && options.StoragePath != "" {
			if info, err := os.Stat(options.StoragePath); err == nil {
				dbSizeBytes = info.Size()
			}
		}

		writeJSON(w, http.StatusOK, healthResponse{
			Status:        "ok",
			Version:       options.Version,
			UptimeSec:     int64(uptime.Seconds()),
			StorageDriver: options.StorageDriver,
			TraceCount:    traceCount,
			DBSizeBytes:   dbSizeBytes,
		})
	})
}
