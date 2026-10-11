package httpapi_test

import (
	"crypto/tls"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/httpapi"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/organization"
)

func TestSupportedPageAllowsExplicitBusinessDateOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Synthetic page</title>"), 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.New(&organization.Service{}, &authz.Service{}, &identity.Service{}, make([]byte, 32), "https://fixture.invalid", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/?as_of=2026-10-11", 200},
		{"/employees/aaaaaaaa-1111-4111-8111-111111111111?as_of=2026-10-11", 200},
		{"/security/grants", 200},
		{"/?as_of=2026-02-30", 404},
		{"/?as_of=2026-10-11&q=SYNTHETIC_NAME", 404},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://fixture.invalid"+tc.path, nil)
			req.TLS = &tls.ConnectionState{}
			out := httptest.NewRecorder()
			handler.ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("explicit-date page HTTP status=%d; want%d", out.Code, tc.status)
			}
		})
	}
}
