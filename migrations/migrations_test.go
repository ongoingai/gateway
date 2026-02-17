package migrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestApplySQLiteCreatesSchemaAndRecordsMigrations(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "ongoingai.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Apply(context.Background(), db, DriverSQLite); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	if !sqliteTableExists(t, db, "traces") {
		t.Fatal("expected traces table to exist after migrations")
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations rows: %v", err)
	}
	if count == 0 {
		t.Fatal("expected at least one applied migration row")
	}
}

func TestApplySQLiteIsIdempotent(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "ongoingai.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Apply(context.Background(), db, DriverSQLite); err != nil {
		t.Fatalf("first Apply() error: %v", err)
	}
	var firstCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&firstCount); err != nil {
		t.Fatalf("count schema_migrations after first Apply(): %v", err)
	}

	if err := Apply(context.Background(), db, DriverSQLite); err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	var secondCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&secondCount); err != nil {
		t.Fatalf("count schema_migrations after second Apply(): %v", err)
	}
	if secondCount != firstCount {
		t.Fatalf("schema_migrations count changed after re-apply: first=%d second=%d", firstCount, secondCount)
	}
}

func TestApplyRejectsUnsupportedDriver(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "ongoingai.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Apply(context.Background(), db, "mysql"); err == nil {
		t.Fatal("Apply() error=nil, want unsupported driver error")
	}
}

func sqliteTableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count); err != nil {
		t.Fatalf("query sqlite_master for table %q: %v", table, err)
	}
	return count > 0
}
