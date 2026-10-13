package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/identity"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

type bootstrapInput struct {
	Timezone string `json:"timezone"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func localRun(args []string) error {
	if len(args) == 0 || args[0] != "local-bootstrap" {
		return fault.Invalid
	}
	set := flag.NewFlagSet("identity local-bootstrap", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected DSN file")
	inputFile := set.String("input-file", "", "protected canonical bootstrap JSON")
	keydSocket := set.String("keyd-socket", "", "local teamledger-keyd Unix socket")
	caFile := set.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	requestID := set.String("request-id", "", "maintenance request UUID")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || !value.ValidID(*requestID) || *inputFile == "" || *keydSocket == "" || *dsnFile == "" {
		return fault.Invalid
	}
	raw, err := configfile.Read(*inputFile, 1024, true)
	if err != nil || len(raw) == 0 {
		clear(raw)
		return fault.Unavailable
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input bootstrapInput
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fault.Invalid
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(canonical)
		return fault.Invalid
	}
	clear(canonical)
	username, err := identity.CanonicalLocalUsername(input.Username)
	if err != nil || username != input.Username {
		return fault.Invalid
	}
	if _, err = time.LoadLocation(input.Timezone); err != nil {
		return fault.Invalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keys := &sensitive.KeydClient{Socket: *keydSocket, Timeout: 5 * time.Second}
	usernameMAC, err := identity.LocalUsernameMAC(ctx, keys, username)
	if err != nil {
		return err
	}
	defer clear(usernameMAC.Digest)
	phc, pepper, err := identity.NewPasswordCredential(ctx, keys, input.Password)
	if err != nil {
		return err
	}
	orgID, subjectID, accountID := value.NewID(), value.NewID(), value.NewID()
	wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainIdentityMapping)
	if err != nil {
		return fault.Unavailable
	}
	binding := sensitive.Context{OrgID: orgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	envelope, err := (sensitive.Cipher{Wrapper: wrapper}).Seal(ctx, binding, []byte(username))
	if err != nil {
		return fault.Unavailable
	}
	defer clear(envelope.SealedBytes)
	defer clear(envelope.Key.Data)
	dsnBytes, err := configfile.Read(*dsnFile, 16<<10, true)
	if err != nil {
		return fault.Unavailable
	}
	defer clear(dsnBytes)
	dsn := strings.TrimSpace(string(dsnBytes))
	var repo *store.Repository
	if *backend == "postgres" {
		ca, e := configfile.Read(*caFile, 1<<20, false)
		if e != nil {
			return fault.Unavailable
		}
		defer clear(ca)
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
	digest := sha256.Sum256(raw)
	bootstrap := store.LocalBootstrap{
		RequestID: *requestID, OrgID: orgID, SubjectID: subjectID, AccountID: accountID, Timezone: input.Timezone,
		InputDigest: digest[:], UsernameDigest: usernameMAC.Digest,
		UsernameKey: sensitive.KeyReference{KeyID: usernameMAC.KeyID, Version: usernameMAC.Version}, UsernameEnvelope: envelope,
		PepperKey: pepper, PasswordPHC: phc, Now: time.Now().UTC().Truncate(time.Microsecond),
	}
	result, err := repo.BootstrapLocal(ctx, bootstrap)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
