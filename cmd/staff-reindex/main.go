package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Staff index maintenance failed")
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Staff index maintenance committed")
}

func run(args []string) error {
	set := flag.NewFlagSet("staff-reindex", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected DSN file")
	caFile := set.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	keydSocket := set.String("keyd-socket", "", "local teamledger-keyd Unix socket")
	manifestFile := set.String("manifest-file", "", "approved manifest file")
	if set.Parse(args) != nil || set.NArg() != 0 || *keydSocket == "" {
		return fault.Invalid
	}
	dsnRaw, err := configfile.Read(*dsnFile, 16<<10, true)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(dsnRaw)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	dsn := strings.TrimSpace(string(dsnRaw))
	var repo *store.Repository
	if *backend == "postgres" {
		u, parseErr := url.Parse(dsn)
		if parseErr != nil || *caFile == "" || u.Query().Get("sslmode") != "verify-full" || u.Query().Get("sslrootcert") != *caFile {
			return fault.Unavailable
		}
		ca, readErr := configfile.Read(*caFile, 1<<20, false)
		if readErr != nil {
			return fault.Unavailable
		}
		repo, err = store.OpenPostgresWithCheckedCA(ctx, dsn, ca)
	} else if *backend == "sqlite" && *caFile == "" {
		repo, err = store.Open(ctx, *backend, dsn)
	} else {
		return fault.Invalid
	}
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.CheckSchema(ctx); err != nil {
		return err
	}
	manifestRaw, err := configfile.Read(*manifestFile, 1<<20, false)
	if err != nil || len(manifestRaw) == 0 {
		return fault.Invalid
	}
	manifest := sha256.Sum256(manifestRaw)
	clear(manifestRaw)
	keys := &sensitive.KeydClient{Socket: *keydSocket, Timeout: 10 * time.Second}
	state, err := keys.Ready(ctx)
	if err != nil {
		return fault.Unavailable
	}
	domain := sensitive.DomainStaffCodeLookup
	target := state.Staged[domain]
	if target.KeyID == "" || target.Version == 0 {
		return fault.Conflict
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if state.Active[domain] != target.Version {
		if err = repo.BeginCryptoStage(ctx, state, domain, manifest[:], now); err != nil {
			return err
		}
	}
	wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainPIIPayload)
	if err != nil {
		return fault.Unavailable
	}
	cipher := sensitive.Cipher{Wrapper: wrapper}
	sources, err := repo.StaffIndexSources(ctx)
	if err != nil {
		return err
	}
	replacements := make([]store.StaffIndexReplacement, 0, len(sources))
	for _, source := range sources {
		plain, openErr := cipher.Open(ctx, source.Envelope.Context, source.Envelope)
		if openErr != nil {
			return fault.Unavailable
		}
		var payload struct {
			StaffCode string `json:"staff_code"`
		}
		decoder := json.NewDecoder(bytes.NewReader(plain))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			clear(plain)
			return fault.Unavailable
		}
		clear(plain)
		normalized, valid := organization.NormalizeStaffCode(payload.StaffCode)
		if !valid || normalized != payload.StaffCode {
			return fault.Unavailable
		}
		frame := []byte("staff-code\x00" + source.OrgID + "\x00" + normalized)
		value, macErr := keys.MACStaging(ctx, domain, manifest[:], frame)
		clear(frame)
		if macErr != nil || value.KeyID != target.KeyID || value.Version != target.Version || len(value.Digest) != sha256.Size {
			clear(value.Digest)
			return fault.Unavailable
		}
		replacements = append(replacements, store.StaffIndexReplacement{ID: source.ID, OrgID: source.OrgID, EmployeeID: source.EmployeeID, OldDigest: source.OldDigest, NewDigest: value.Digest})
	}
	if state.Active[domain] != target.Version {
		state, err = keys.Activate(ctx, domain, manifest[:])
		if err != nil {
			return fault.Unavailable
		}
	}
	if err = repo.ApplyStaffIndexReplacements(ctx, target, replacements); err != nil {
		return err
	}
	if err = repo.RecordCryptoActivation(ctx, state, domain, manifest[:], now); err != nil {
		return err
	}
	state, err = keys.Acknowledge(ctx, domain, manifest[:])
	if err != nil {
		return fault.Unavailable
	}
	if err = repo.CompleteCryptoActivation(ctx, state, domain, manifest[:], now); err != nil {
		return err
	}
	if state.Active[domain] != target.Version {
		return errors.New("staff index activation mismatch")
	}
	return nil
}
