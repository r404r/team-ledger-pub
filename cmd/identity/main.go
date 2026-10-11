package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Identity maintenance failed")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Identity maintenance committed")
}
func run(args []string) error {
	if len(args) == 0 || args[0] != "bind" && args[0] != "unbind" {
		return fault.Invalid
	}
	op := args[0]
	flags := flag.NewFlagSet("identity "+op, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backend := flags.String("backend", "", "sqlite or postgres")
	dsnFile := flags.String("dsn-file", "", "protected DSN file")
	issuer := flags.String("issuer", "", "exact approved HTTPS issuer")
	keyFile := flags.String("identity-key-file", "", "protected version-1 identity HMAC key file")
	subFile := flags.String("sub-file", "", "protected exact UTF-8 IdP subject file; no terminal newline")
	caFile := flags.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	org := flags.String("org-id", "", "existing approved organization UUID")
	subject := flags.String("subject-id", "", "existing approved subject UUID")
	requestID := flags.String("request-id", "", "maintenance request UUID")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || !value.ValidID(*org) || !value.ValidID(*subject) || !value.ValidID(*requestID) {
		return fault.Invalid
	}
	dsnBytes, err := configfile.Read(*dsnFile, 16<<10, true)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(dsnBytes)
	dsn := strings.TrimSpace(string(dsnBytes))
	var postgresCA []byte
	if *backend == "postgres" {
		u, err := url.Parse(dsn)
		if err != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || *caFile == "" || u.Query().Get("sslmode") != "verify-full" || u.Query().Get("sslrootcert") != *caFile {
			return fault.Unavailable
		}
		if postgresCA, err = configfile.Read(*caFile, 1<<20, false); err != nil {
			return fault.Unavailable
		}
	} else if *backend != "sqlite" || *caFile != "" {
		return fault.Invalid
	}
	key, err := configfile.Read(*keyFile, 32, true)
	if err != nil || len(key) != 32 {
		clear(key)
		return fault.Unavailable
	}
	defer clear(key)
	subBytes, err := configfile.Read(*subFile, 4096, true)
	if err != nil || len(subBytes) == 0 || strings.ContainsAny(string(subBytes), "\x00\r\n") {
		clear(subBytes)
		return fault.Invalid
	}
	defer clear(subBytes)
	digest, err := identity.IdentityDigest(key, *issuer, string(subBytes))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var repo *store.Repository
	if *backend == "postgres" {
		repo, err = store.OpenPostgresWithCheckedCA(ctx, dsn, postgresCA)
	} else {
		repo, err = store.Open(ctx, *backend, dsn)
	}
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.CheckSchema(ctx); err != nil {
		return err
	}
	mapping := identity.Identity{Digest: digest, KeyVersion: 1, OrgID: *org, SubjectID: *subject}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if op == "bind" {
		return repo.BindIdentity(ctx, mapping, *requestID, now)
	}
	return repo.UnbindIdentity(ctx, mapping, *requestID, now)
}
