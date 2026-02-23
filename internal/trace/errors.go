package trace

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
)

// Error class constants for trace write failure classification.
const (
	WriteErrorClassConnection = "connection"
	WriteErrorClassTimeout    = "timeout"
	WriteErrorClassContention = "contention"
	WriteErrorClassConstraint = "constraint"
	WriteErrorClassUnknown    = "unknown"
)

// ClassifyWriteError maps a trace write error to one of the defined error
// classes so operators can alert and dashboard on failure categories rather
// than opaque Go type names.
func ClassifyWriteError(err error) string {
	if err == nil {
		return WriteErrorClassUnknown
	}

	// Timeout checks (before connection, since net.Error can be both).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return WriteErrorClassTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return WriteErrorClassTimeout
	}

	// Connection checks.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return WriteErrorClassConnection
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return WriteErrorClassConnection
	}

	// String-based classification for errors from database drivers and
	// wrapped errors where type information is lost.
	msg := strings.ToLower(err.Error())

	if isConnectionString(msg) {
		return WriteErrorClassConnection
	}
	if isTimeoutString(msg) {
		return WriteErrorClassTimeout
	}
	if isContentionString(msg) {
		return WriteErrorClassContention
	}
	if isConstraintString(msg) {
		return WriteErrorClassConstraint
	}

	return WriteErrorClassUnknown
}

func isConnectionString(msg string) bool {
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "no such host")
}

func isTimeoutString(msg string) bool {
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded")
}

func isContentionString(msg string) bool {
	return strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "database is locked")
}

func isConstraintString(msg string) bool {
	return strings.Contains(msg, "violates foreign key constraint") ||
		strings.Contains(msg, "violates unique constraint") ||
		strings.Contains(msg, "violates check constraint") ||
		strings.Contains(msg, "duplicate key")
}
