package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSONWritesEncodedPayload(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"status": "ok"})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q, want application/json", got)
	}

	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("payload status=%q, want %q", payload["status"], "ok")
	}
}

func TestWriteJSONReturnsInternalServerErrorOnEncodeFailure(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]any{
		"bad": make(chan int),
	})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q, want application/json", got)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"internal server error"}` {
		t.Fatalf("body=%q, want %q", got, `{"error":"internal server error"}`)
	}
}
