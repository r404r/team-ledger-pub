package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
)

func identityReindexRun(args []string) error {
	set := flag.NewFlagSet("identity reindex", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected DSN file")
	caFile := set.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	keydSocket := set.String("keyd-socket", "", "local teamledger-keyd Unix socket")
	manifestFile := set.String("manifest-file", "", "approved manifest file")
	domainName := set.String("domain", "", "oidc or local_username")
	if set.Parse(args) != nil || set.NArg() != 0 || *keydSocket == "" || (*domainName != "oidc" && *domainName != "local_username") {
		return fault.Invalid
	}
	dsnRaw, err := configfile.Read(*dsnFile, 16<<10, true)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(dsnRaw)
	dsn := strings.TrimSpace(string(dsnRaw))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
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
	domain, local := sensitive.DomainIdentitySubjectLookup, false
	if *domainName == "local_username" {
		domain, local = sensitive.DomainLocalUsernameLookup, true
	}
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
	wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainIdentityMapping)
	if err != nil {
		return fault.Unavailable
	}
	cipher := sensitive.Cipher{Wrapper: wrapper}
	sources, err := repo.IdentityIndexSources(ctx)
	if err != nil {
		return err
	}
	replacements := make([]store.IdentityIndexReplacement, 0, len(sources))
	for _, source := range sources {
		if source.Local != local {
			continue
		}
		plain, openErr := cipher.Open(ctx, source.Envelope.Context, source.Envelope)
		if openErr != nil {
			return fault.Unavailable
		}
		var frame []byte
		if local {
			username := string(plain)
			canonical, canonicalErr := identity.CanonicalLocalUsername(username)
			if canonicalErr != nil || canonical != username {
				clear(plain)
				return fault.Unavailable
			}
			frame, err = identity.LocalUsernameLookupFrame(username)
		} else {
			var canonical struct {
				Issuer  string `json:"issuer"`
				Subject string `json:"subject"`
			}
			decoder := json.NewDecoder(bytes.NewReader(plain))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&canonical) != nil || decoder.Decode(&struct{}{}) != io.EOF {
				clear(plain)
				return fault.Unavailable
			}
			frame, err = identity.IdentityLookupFrame(canonical.Issuer, canonical.Subject)
		}
		clear(plain)
		if err != nil {
			return fault.Unavailable
		}
		value, macErr := keys.MACStaging(ctx, domain, manifest[:], frame)
		clear(frame)
		if macErr != nil || value.KeyID != target.KeyID || value.Version != target.Version || len(value.Digest) != 32 {
			clear(value.Digest)
			return fault.Unavailable
		}
		replacements = append(replacements, store.IdentityIndexReplacement{SourceID: source.ID, OrgID: source.OrgID, SubjectID: source.SubjectID, OldDigest: source.Digest, NewDigest: value.Digest, Local: local})
	}
	if state.Active[domain] != target.Version {
		state, err = keys.Activate(ctx, domain, manifest[:])
		if err != nil {
			return fault.Unavailable
		}
	}
	if err = repo.ApplyIdentityIndexReplacements(ctx, local, target, replacements); err != nil {
		return err
	}
	if err = repo.RecordCryptoActivation(ctx, state, domain, manifest[:], now); err != nil {
		return err
	}
	state, err = keys.Acknowledge(ctx, domain, manifest[:])
	if err != nil {
		return fault.Unavailable
	}
	return repo.CompleteCryptoActivation(ctx, state, domain, manifest[:], now)
}
