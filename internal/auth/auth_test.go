package auth

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		description string
		headers     http.Header
		wantKey     string
		wantErr     string
	}{
		"success/basic_api_key": {
			description: "should extract API key from well-formed Authorization header",
			headers:     http.Header{"Authorization": []string{"ApiKey secret123"}},
			wantKey:     "secret123",
			wantErr:     "",
		},
		"success/complex_api_key": {
			description: "should handle API keys with special characters",
			headers:     http.Header{"Authorization": []string{"ApiKey sk_live_123456789abcdef"}},
			wantKey:     "sk_live_123456789abcdef",
			wantErr:     "",
		},
		"success/uuid_api_key": {
			description: "should handle UUID-style API keys",
			headers:     http.Header{"Authorization": []string{"ApiKey 550e8400-e29b-41d4-a716-446655440000"}},
			wantKey:     "550e8400-e29b-41d4-a716-446655440000",
			wantErr:     "",
		},
		"success/multiple_headers": {
			description: "should use first Authorization header when multiple are present",
			headers: func() http.Header {
				h := http.Header{}
				h.Add("Authorization", "ApiKey first-key")
				h.Add("Authorization", "ApiKey second-key")
				return h
			}(),
			wantKey: "first-key",
			wantErr: "",
		},
		"error/missing_header": {
			description: "should return specific error when Authorization header is missing",
			headers:     http.Header{},
			wantKey:     "",
			wantErr:     "no authorization header included",
		},
		"error/empty_header": {
			description: "should return specific error when Authorization header is empty",
			headers:     http.Header{"Authorization": []string{""}},
			wantKey:     "",
			wantErr:     "no authorization header included",
		},
		"error/whitespace_only": {
			description: "should return specific error when Authorization header is whitespace only",
			headers:     http.Header{"Authorization": []string{"   "}},
			wantKey:     "",
			wantErr:     "malformed authorization header",
		},
		"error/wrong_scheme": {
			description: "should reject Bearer tokens",
			headers:     http.Header{"Authorization": []string{"Bearer token123"}},
			wantKey:     "",
			wantErr:     "malformed authorization header",
		},
		"error/wrong_scheme_case": {
			description: "should reject case variations of ApiKey",
			headers:     http.Header{"Authorization": []string{"apikey token123"}},
			wantKey:     "",
			wantErr:     "malformed authorization header",
		},
		"error/basic_auth": {
			description: "should reject Basic auth",
			headers:     http.Header{"Authorization": []string{"Basic dXNlcjpwYXNz"}},
			wantKey:     "",
			wantErr:     "malformed authorization header",
		},
		"error/only_scheme": {
			description: "should reject header with only scheme and no key",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			wantKey:     "",
			wantErr:     "malformed authorization header",
		},
		"error/only_scheme_with_space": {
			description: "should reject header with scheme and space but no key",
			headers:     http.Header{"Authorization": []string{"ApiKey "}},
			wantKey:     "",
			wantErr:     "malformed authorization header",
		},
	}

	for name, tc := range tests {

		t.Run(name, func(t *testing.T) {
			t.Logf("Test case: %s", tc.description)
			gotKey, gotErr := GetAPIKey(tc.headers)

			if tc.wantErr != "" {
				if gotErr == nil {
					t.Fatalf("GetAPIKey() expected error %q, got nil", tc.wantErr)
				}
				if diff := cmp.Diff(tc.wantErr, gotErr.Error()); diff != "" {
					t.Fatalf("GetAPIKey() error mismatch (-want +got):\n%s", diff)
				}
			} else {
				if gotErr != nil {
					t.Fatalf("GetAPIKey() unexpected error: %v", gotErr)
				}
			}

			if diff := cmp.Diff(tc.wantKey, gotKey); diff != "" {
				t.Errorf("GetAPIKey() result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
