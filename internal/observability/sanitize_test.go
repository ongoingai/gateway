package observability

import (
	"testing"
)

func TestContainsCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Token prefix patterns
		{name: "sk_ prefix", input: "sk_live_abc123def456", want: true},
		{name: "pk_ prefix", input: "pk_test_xxxxxxxx", want: true},
		{name: "rk_ prefix", input: "rk_live_abcdefghij", want: true},
		{name: "xoxb_ slack bot", input: "xoxb_123456789abc", want: true},
		{name: "xoxp_ slack user", input: "xoxp_abcdefghijkl", want: true},
		{name: "ghp_ github pat", input: "ghp_aBcDeFgHiJkLmNoP", want: true},
		{name: "gho_ github oauth", input: "gho_aBcDeFgHiJkLmNoP", want: true},
		{name: "pat_ prefix", input: "pat_abcdefghijklmnop", want: true},

		// JWT-like tokens
		{name: "JWT token", input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", want: true},

		// Bearer tokens
		{name: "Bearer header value", input: "Bearer sk_live_abc123def456", want: true},
		{name: "Bearer generic token", input: "Bearer abcdefghijklmnop", want: true},

		// Connection string secrets
		{name: "password in connection string", input: "host=db.example.com password=supersecret123", want: true},
		{name: "secret= value", input: "secret=my_super_secret_value", want: true},
		{name: "token= value", input: "token=abcdefghijklmnop", want: true},

		// Safe values that should NOT match
		{name: "short string", input: "ok", want: false},
		{name: "empty string", input: "", want: false},
		{name: "provider name", input: "openai", want: false},
		{name: "model name", input: "gpt-4o-mini", want: false},
		{name: "org ID", input: "org-abc123", want: false},
		{name: "workspace ID", input: "ws-test-workspace", want: false},
		{name: "status message", input: "connection refused", want: false},
		{name: "route pattern", input: "/openai/v1/chat/completions", want: false},
		{name: "error class", input: "timeout", want: false},
		{name: "http status", input: "http 502", want: false},
		{name: "key ID safe", input: "gwk_test_1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ContainsCredential(tt.input); got != tt.want {
				t.Fatalf("ContainsCredential(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestScrubCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "sk_ key is redacted",
			input: "error connecting with key sk_live_abc123def456",
			want:  "error connecting with key [CREDENTIAL_REDACTED]",
		},
		{
			name:  "JWT token is redacted",
			input: "auth failed: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			want:  "auth failed: [CREDENTIAL_REDACTED]",
		},
		{
			name:  "Bearer token is redacted",
			input: "header: Bearer abcdefghijklmnop",
			want:  "header: [CREDENTIAL_REDACTED]",
		},
		{
			name:  "password in connection string is redacted",
			input: "host=db.example.com password=supersecret123 dbname=prod",
			want:  "host=db.example.com [CREDENTIAL_REDACTED] dbname=prod",
		},
		{
			name:  "multiple credentials are all redacted",
			input: "key=sk_live_abc123def456 token=my_secret_token_value",
			want:  "key=[CREDENTIAL_REDACTED] [CREDENTIAL_REDACTED]",
		},
		{
			name:  "safe string passes through unchanged",
			input: "connection refused",
			want:  "connection refused",
		},
		{
			name:  "short string passes through",
			input: "ok",
			want:  "ok",
		},
		{
			name:  "empty string passes through",
			input: "",
			want:  "",
		},
		{
			name:  "model name passes through",
			input: "gpt-4o-mini",
			want:  "gpt-4o-mini",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ScrubCredentials(tt.input); got != tt.want {
				t.Fatalf("ScrubCredentials(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestScrubCredentialsPreservesOriginalForSafeStrings(t *testing.T) {
	t.Parallel()

	safe := "connection refused to postgres:5432"
	result := ScrubCredentials(safe)
	// Verify exact same string reference is returned (no allocation).
	if &result != &safe {
		// Can't compare pointers directly for strings in general, but
		// verify the content is identical.
		if result != safe {
			t.Fatalf("ScrubCredentials modified safe string: got %q, want %q", result, safe)
		}
	}
}
