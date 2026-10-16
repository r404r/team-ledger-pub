package main

import (
	"bytes"
	"context"
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

type accountInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type usernameInput struct {
	Username string `json:"username"`
}

func openLocalRepo(ctx context.Context, backend, dsnFile, caFile string) (*store.Repository, error) {
	dsnBytes, err := configfile.Read(dsnFile, 16<<10, true)
	if err != nil {
		return nil, fault.Unavailable
	}
	defer clear(dsnBytes)
	dsn := strings.TrimSpace(string(dsnBytes))
	if backend == "sqlite" && caFile == "" {
		return store.Open(ctx, backend, dsn)
	}
	if backend != "postgres" || caFile == "" {
		return nil, fault.Invalid
	}
	ca, err := configfile.Read(caFile, 1<<20, false)
	if err != nil {
		return nil, fault.Unavailable
	}
	defer clear(ca)
	return store.OpenPostgresWithCheckedCA(ctx, dsn, ca)
}

func readAccountInput(path string) (accountInput, error) {
	var input accountInput
	raw, err := configfile.Read(path, 1024, true)
	if err != nil || len(raw) == 0 {
		clear(raw)
		return input, fault.Unavailable
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return input, fault.Invalid
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(canonical)
		return input, fault.Invalid
	}
	clear(canonical)
	username, err := identity.CanonicalLocalUsername(input.Username)
	if err != nil || username != input.Username {
		return input, fault.Invalid
	}
	return input, nil
}

func readUsernameInput(path string) (usernameInput, error) {
	var input usernameInput
	raw, err := configfile.Read(path, 1024, true)
	if err != nil || len(raw) == 0 {
		clear(raw)
		return input, fault.Unavailable
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return input, fault.Invalid
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(canonical)
		return input, fault.Invalid
	}
	clear(canonical)
	username, err := identity.CanonicalLocalUsername(input.Username)
	if err != nil || username != input.Username {
		return input, fault.Invalid
	}
	return input, nil
}

func localAccountRun(action string, args []string) error {
	set := flag.NewFlagSet("identity local-account-"+action, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected DSN file")
	inputFile := set.String("input-file", "", "protected canonical account JSON")
	keydSocket := set.String("keyd-socket", "", "local teamledger-keyd Unix socket")
	caFile := set.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	orgID := set.String("org-id", "", "existing organization UUID")
	subjectID := set.String("subject-id", "", "existing subject UUID")
	requestID := set.String("request-id", "", "maintenance request UUID")
	if set.Parse(args) != nil || set.NArg() != 0 || !value.ValidID(*orgID) || !value.ValidID(*subjectID) || !value.ValidID(*requestID) || *inputFile == "" || *keydSocket == "" || *dsnFile == "" {
		return fault.Invalid
	}
	input, err := readAccountInput(*inputFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keys := &sensitive.KeydClient{Socket: *keydSocket, Timeout: 5 * time.Second}
	username, err := identity.LocalUsernameMAC(ctx, keys, input.Username)
	if err != nil {
		return err
	}
	defer clear(username.Digest)
	repo, err := openLocalRepo(ctx, *backend, *dsnFile, *caFile)
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.CheckSchema(ctx); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if action == "disable" {
		return repo.DisableLocalAccount(ctx, *orgID, *subjectID, username.Digest, *requestID, now)
	}
	phc, pepper, err := identity.NewPasswordCredential(ctx, keys, input.Password)
	if err != nil {
		return err
	}
	if action == "reset" {
		return repo.ResetLocalAccount(ctx, *orgID, *subjectID, username.Digest, phc, pepper, *requestID, now)
	}
	accountID := value.NewID()
	wrapper, err := sensitive.NewKeydWrapper(keys, sensitive.DomainIdentityMapping)
	if err != nil {
		return fault.Unavailable
	}
	binding := sensitive.Context{OrgID: *orgID, RecordID: accountID, VersionID: accountID, ObjectKind: "local_username", Purpose: "identity", SchemaType: "identity.local_username.v1", SchemaVersion: 1}
	envelope, err := (sensitive.Cipher{Wrapper: wrapper}).Seal(ctx, binding, []byte(input.Username))
	if err != nil {
		return fault.Unavailable
	}
	defer clear(envelope.Key.Data)
	defer clear(envelope.SealedBytes)
	return repo.CreateLocalAccount(ctx, store.LocalAccountProvision{RequestID: *requestID, OrgID: *orgID, SubjectID: *subjectID, AccountID: accountID, UsernameDigest: username.Digest, UsernameKey: sensitive.KeyReference{KeyID: username.KeyID, Version: username.Version}, UsernameEnvelope: envelope, PepperKey: pepper, PasswordPHC: phc, Now: now})
}

func localMFAResetRun(args []string) error {
	set := flag.NewFlagSet("identity local-mfa-reset", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected DSN file")
	inputFile := set.String("input-file", "", "protected canonical username JSON")
	keydSocket := set.String("keyd-socket", "", "local teamledger-keyd Unix socket")
	caFile := set.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	orgID := set.String("org-id", "", "existing organization UUID")
	subjectID := set.String("subject-id", "", "existing subject UUID")
	requestID := set.String("request-id", "", "maintenance request UUID")
	if set.Parse(args) != nil || set.NArg() != 0 || !value.ValidID(*orgID) || !value.ValidID(*subjectID) || !value.ValidID(*requestID) || *inputFile == "" || *keydSocket == "" || *dsnFile == "" {
		return fault.Invalid
	}
	input, err := readUsernameInput(*inputFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	keys := &sensitive.KeydClient{Socket: *keydSocket, Timeout: 5 * time.Second}
	username, err := identity.LocalUsernameMAC(ctx, keys, input.Username)
	if err != nil {
		return err
	}
	defer clear(username.Digest)
	repo, err := openLocalRepo(ctx, *backend, *dsnFile, *caFile)
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.CheckSchema(ctx); err != nil {
		return err
	}
	return repo.ResetLocalMFA(ctx, *orgID, *subjectID, username.Digest, *requestID, time.Now().UTC().Truncate(time.Microsecond))
}

func modeSwitchRun(args []string) error {
	set := flag.NewFlagSet("identity mode-switch", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected DSN file")
	caFile := set.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	target := set.String("target", "", "local or oidc")
	requestID := set.String("request-id", "", "maintenance request UUID")
	if set.Parse(args) != nil || set.NArg() != 0 || !value.ValidID(*requestID) || (*target != "local" && *target != "oidc") {
		return fault.Invalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, err := openLocalRepo(ctx, *backend, *dsnFile, *caFile)
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.CheckSchema(ctx); err != nil {
		return err
	}
	return repo.SwitchIdentityMode(ctx, *target, *requestID, time.Now().UTC().Truncate(time.Microsecond))
}
func localSubjectRun(args []string) error {
	set := flag.NewFlagSet("identity local-subject-create", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected DSN file")
	caFile := set.String("postgres-ca-file", "", "protected public PostgreSQL CA file")
	orgID := set.String("org-id", "", "existing organization UUID")
	requestID := set.String("request-id", "", "maintenance request UUID")
	if set.Parse(args) != nil || set.NArg() != 0 || !value.ValidID(*orgID) || !value.ValidID(*requestID) {
		return fault.Invalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo, err := openLocalRepo(ctx, *backend, *dsnFile, *caFile)
	if err != nil {
		return err
	}
	defer repo.Close()
	subjectID := value.NewID()
	if err = repo.CreateLocalSubject(ctx, *orgID, subjectID, *requestID, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		SubjectID string `json:"subject_id"`
	}{subjectID})
}
