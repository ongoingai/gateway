package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func requirePostgresTestDSN(t *testing.T) string {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}
	return dsn
}

func postgresTraceTestPrefix(label string) string {
	return fmt.Sprintf("cli-%s-%d-", strings.TrimSpace(label), time.Now().UTC().UnixNano())
}

func deletePostgresTracesByPrefix(t *testing.T, dsn, idPrefix string) {
	t.Helper()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres cleanup connection: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close postgres cleanup connection: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const tableExistsQuery = `SELECT to_regclass('traces') IS NOT NULL`
	var tracesTableExists bool
	if err := db.QueryRowContext(ctx, tableExistsQuery).Scan(&tracesTableExists); err != nil {
		t.Fatalf("check postgres traces table existence: %v", err)
	}
	if !tracesTableExists {
		return
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM traces WHERE id LIKE $1`, idPrefix+"%"); err != nil {
		t.Fatalf("cleanup postgres traces for prefix %q: %v", idPrefix, err)
	}
}
