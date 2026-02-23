package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

// timeoutError satisfies net.Error with Timeout() == true.
type timeoutError struct{ msg string }

func (e *timeoutError) Error() string   { return e.msg }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return false }

func TestClassifyWriteError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "nil error",
			err:  nil,
			want: WriteErrorClassUnknown,
		},
		{
			name: "context.DeadlineExceeded",
			err:  context.DeadlineExceeded,
			want: WriteErrorClassTimeout,
		},
		{
			name: "context.Canceled",
			err:  context.Canceled,
			want: WriteErrorClassTimeout,
		},
		{
			name: "wrapped DeadlineExceeded",
			err:  fmt.Errorf("store write: %w", context.DeadlineExceeded),
			want: WriteErrorClassTimeout,
		},
		{
			name: "net.Error with Timeout",
			err:  &timeoutError{msg: "i/o timeout"},
			want: WriteErrorClassTimeout,
		},
		{
			name: "net.OpError",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("connection refused"),
			},
			want: WriteErrorClassConnection,
		},
		{
			name: "ECONNREFUSED",
			err:  fmt.Errorf("dial tcp: %w", syscall.ECONNREFUSED),
			want: WriteErrorClassConnection,
		},
		{
			name: "ECONNRESET",
			err:  fmt.Errorf("read: %w", syscall.ECONNRESET),
			want: WriteErrorClassConnection,
		},
		{
			name: "ECONNABORTED",
			err:  fmt.Errorf("write: %w", syscall.ECONNABORTED),
			want: WriteErrorClassConnection,
		},
		{
			name: "connection refused string",
			err:  errors.New("dial tcp 127.0.0.1:5432: connection refused"),
			want: WriteErrorClassConnection,
		},
		{
			name: "broken pipe string",
			err:  errors.New("write: broken pipe"),
			want: WriteErrorClassConnection,
		},
		{
			name: "no such host string",
			err:  errors.New("lookup db.example.com: no such host"),
			want: WriteErrorClassConnection,
		},
		{
			name: "timeout string",
			err:  errors.New("operation timeout after 5s"),
			want: WriteErrorClassTimeout,
		},
		{
			name: "deadline exceeded string",
			err:  errors.New("query deadline exceeded"),
			want: WriteErrorClassTimeout,
		},
		{
			name: "sqlite_busy",
			err:  errors.New("SQLITE_BUSY: database table is locked (5)"),
			want: WriteErrorClassContention,
		},
		{
			name: "database is locked",
			err:  errors.New("database is locked"),
			want: WriteErrorClassContention,
		},
		{
			name: "wrapped sqlite busy",
			err:  fmt.Errorf("write trace: %w", errors.New("sqlite_busy")),
			want: WriteErrorClassContention,
		},
		{
			name: "violates foreign key constraint",
			err:  errors.New(`pq: insert or update on table "traces" violates foreign key constraint "fk_org"`),
			want: WriteErrorClassConstraint,
		},
		{
			name: "violates unique constraint",
			err:  errors.New(`pq: duplicate key value violates unique constraint "traces_pkey"`),
			want: WriteErrorClassConstraint,
		},
		{
			name: "violates check constraint",
			err:  errors.New(`pq: value violates check constraint "positive_tokens"`),
			want: WriteErrorClassConstraint,
		},
		{
			name: "duplicate key",
			err:  errors.New("duplicate key value violates unique constraint"),
			want: WriteErrorClassConstraint,
		},
		{
			name: "generic unknown error",
			err:  errors.New("something went wrong"),
			want: WriteErrorClassUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyWriteError(tt.err)
			if got != tt.want {
				t.Fatalf("ClassifyWriteError(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
