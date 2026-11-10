// staff-normalize is an offline, explicitly applied data upgrade. DSNs and
// keys are read through the same protected-file/keyd boundaries as other CLIs.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

const supportedSourceCommit = "c7475e67af9caf3e7e5ad4929a2fde0d6eac74f8"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "staff_normalization_rejected")
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("staff-normalize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backend := flags.String("backend", "", "sqlite or postgres")
	dsnFile := flags.String("dsn-file", "", "protected existing database DSN file")
	ca := flags.String("postgres-ca-file", "", "checked PostgreSQL CA file")
	socket := flags.String("keyd-socket", "", "local keyd socket")
	source := flags.String("source-commit", "", "operator-verified source application commit")
	apply := flags.Bool("apply", false, "explicitly apply; default is read-only preflight")
	snapshot := flags.String("expected-snapshot", "", "snapshot from preflight after stopping all writers")
	stopped := flags.Bool("maintenance-confirmed", false, "all application and maintenance writers are stopped")
	restoreDSN := flags.String("restored-dsn-file", "", "isolated database restored from the pre-upgrade backup")
	restoreSocket := flags.String("restored-keyd-socket", "", "isolated keyd using restored offline keys")
	requestID := flags.String("request-id", "", "audit request UUID")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *source != supportedSourceCommit || *socket == "" || *dsnFile == "" || (*backend != "sqlite" && *backend != "postgres") {
		return fault.Invalid
	}
	if *apply && (!*stopped || len(*snapshot) != 64 || *restoreDSN == "" || *restoreSocket == "" || *restoreSocket == *socket || !value.ValidID(*requestID)) {
		return fault.Invalid
	}
	repo, dsn, err := open(ctx, *backend, *dsnFile, *ca, !*apply)
	if err != nil {
		return err
	}
	defer repo.Close()
	keys := &sensitive.KeydClient{Socket: *socket, Timeout: 10 * time.Second}
	cipher, mac, err := maintenanceKeys(ctx, repo, keys)
	if err != nil {
		return err
	}
	if *apply {
		restored, restoredDSN, e := open(ctx, *backend, *restoreDSN, *ca, true)
		if e != nil {
			return e
		}
		defer restored.Close()
		if sameDatabase(ctx, *backend, repo, restored, dsn, restoredDSN) {
			return fault.Invalid
		}
		restoredKeys := &sensitive.KeydClient{Socket: *restoreSocket, Timeout: 10 * time.Second}
		restoredCipher, restoredMAC, e := maintenanceKeys(ctx, restored, restoredKeys)
		if e != nil {
			return e
		}
		proof, e := restored.NormalizeStaffCodes(ctx, restoredCipher, restoredMAC, store.StaffNormalizationOptions{})
		if e != nil || proof.Snapshot != *snapshot {
			return fault.Conflict
		}
	}
	report, err := repo.NormalizeStaffCodes(ctx, cipher, mac, store.StaffNormalizationOptions{Apply: *apply, ExpectedSnapshot: *snapshot, RequestID: *requestID})
	if e := json.NewEncoder(out).Encode(report); e != nil {
		return fault.Unavailable
	}
	return err
}

func maintenanceKeys(ctx context.Context, repo *store.Repository, keys *sensitive.KeydClient) (sensitive.Cipher, store.StaffCodeMAC, error) {
	state, err := keys.Ready(ctx)
	if err != nil || repo.VerifyCryptoState(ctx, state) != nil {
		return sensitive.Cipher{}, nil, fault.Unavailable
	}
	target := state.ActiveKeys[sensitive.DomainStaffCodeLookup]
	if target.KeyID == "" || target.Version == 0 {
		return sensitive.Cipher{}, nil, fault.Unavailable
	}
	wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainPIIPayload)
	if err != nil {
		return sensitive.Cipher{}, nil, fault.Unavailable
	}
	mac := func(ctx context.Context, frame []byte) (sensitive.MACValue, error) {
		current, e := keys.Ready(ctx)
		if e != nil || current.Digest != state.Digest || current.MaterialGeneration != state.MaterialGeneration || repo.VerifyCryptoState(ctx, current) != nil {
			return sensitive.MACValue{}, fault.Unavailable
		}
		m, e := keys.MAC(ctx, sensitive.DomainStaffCodeLookup, frame)
		if e != nil || m.KeyID != target.KeyID || m.Version != target.Version {
			return sensitive.MACValue{}, fault.Unavailable
		}
		return m, nil
	}
	return sensitive.Cipher{Wrapper: wrapper}, mac, nil
}

func open(ctx context.Context, backend, dsnFile, caPath string, readOnly bool) (*store.Repository, string, error) {
	raw, err := configfile.Read(dsnFile, 16<<10, true)
	if err != nil {
		return nil, "", fault.Unavailable
	}
	defer clear(raw)
	dsn := strings.TrimSpace(string(raw))
	if backend == "sqlite" {
		if caPath != "" {
			return nil, "", fault.Invalid
		}
		repo, e := store.OpenStaffMaintenanceSQLite(ctx, dsn, readOnly)
		return repo, dsn, e
	}
	parsed, e := url.Parse(dsn)
	if e != nil || caPath == "" || parsed.Query().Get("sslmode") != "verify-full" || parsed.Query().Get("sslrootcert") != caPath {
		return nil, "", fault.Unavailable
	}
	ca, e := configfile.Read(caPath, 1<<20, false)
	if e != nil {
		return nil, "", fault.Unavailable
	}
	repo, e := store.OpenPostgresWithCheckedCA(ctx, dsn, ca)
	return repo, dsn, e
}

func sameDatabase(ctx context.Context, backend string, a, b *store.Repository, aDSN, bDSN string) bool {
	if backend == "sqlite" {
		x, e := os.Stat(aDSN)
		y, f := os.Stat(bDSN)
		return e != nil || f != nil || os.SameFile(x, y)
	}
	identity := func(r *store.Repository) (string, error) {
		var s string
		e := r.DB.QueryRowContext(ctx, "SELECT current_database()||':'||current_schema()||':'||inet_server_addr()::text||':'||inet_server_port()::text").Scan(&s)
		return s, e
	}
	x, e := identity(a)
	y, f := identity(b)
	return e != nil || f != nil || x == y
}
