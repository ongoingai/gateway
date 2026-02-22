package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/trace"
)

func openTraceStore(cfg config.Config) (trace.TraceStore, error) {
	switch strings.TrimSpace(cfg.Storage.Driver) {
	case "sqlite":
		return trace.NewSQLiteStore(cfg.Storage.Path)
	case "postgres":
		return trace.NewPostgresStore(cfg.Storage.DSN)
	default:
		return nil, fmt.Errorf("unsupported storage.driver %q", cfg.Storage.Driver)
	}
}

func closeTraceStore(store trace.TraceStore) error {
	if store == nil {
		return nil
	}
	if closer, ok := store.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func closeTraceStoreWithWarning(store trace.TraceStore, errOut io.Writer) {
	if err := closeTraceStore(store); err != nil {
		fmt.Fprintf(errOut, "warning: failed to close trace store: %v\n", err)
	}
}
