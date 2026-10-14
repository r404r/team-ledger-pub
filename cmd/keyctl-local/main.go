package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
	"github.com/r404r/team-ledger/internal/value"
)

func keyDomain(value string) (sensitive.KeyDomain, bool) {
	domains := map[string]sensitive.KeyDomain{
		"pii": sensitive.DomainPIIPayload, "interview": sensitive.DomainInterviewPayload,
		"assessment": sensitive.DomainAssessmentPayload, "financial": sensitive.DomainFinancialPayload,
		"identity_transaction": sensitive.DomainIdentityTransaction, "identity_mapping": sensitive.DomainIdentityMapping,
		"backup_archive": sensitive.DomainBackupArchive, "staff_code_lookup": sensitive.DomainStaffCodeLookup,
		"bonus_payment_lookup": sensitive.DomainBonusPaymentLookup, "identity_subject_lookup": sensitive.DomainIdentitySubjectLookup,
		"command_receipt": sensitive.DomainCommandReceipt, "assessment_generation": sensitive.DomainAssessmentGeneration,
		"csrf_token": sensitive.DomainCSRFToken, "cursor_token": sensitive.DomainCursorToken,
		"local_username_lookup": sensitive.DomainLocalUsernameLookup, "local_password_pepper": sensitive.DomainLocalPasswordPepper,
	}
	domain, ok := domains[value]
	return domain, ok
}

func lifecycle(action string, args []string) error {
	set := flag.NewFlagSet(action, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	socket := set.String("socket", "", "local keyd Unix socket")
	domainName := set.String("domain", "", "key domain")
	manifestFile := set.String("manifest-file", "", "approved manifest file")
	targetKeyID := set.String("target-key-id", "", "approved target key UUID")
	targetVersion := set.Uint64("target-version", 0, "approved next key version")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *socket == "" || *domainName == "" || *manifestFile == "" ||
		action == "stage" && (*targetKeyID == "" || *targetVersion == 0 || *targetVersion > math.MaxUint32) || action == "activate" && (*targetKeyID != "" || *targetVersion != 0) {
		return errors.New("invalid lifecycle arguments")
	}
	domain, ok := keyDomain(*domainName)
	if !ok {
		return errors.New("invalid key domain")
	}
	switch domain {
	case sensitive.DomainCommandReceipt, sensitive.DomainAssessmentGeneration:
		return errors.New("persistent MAC domain rotation is not available")
	case sensitive.DomainLocalPasswordPepper:
		return errors.New("password pepper rotation requires credential dependency maintenance")
	}
	if action == "activate" {
		switch domain {
		case sensitive.DomainCSRFToken:
			return errors.New("CSRF activation requires csrf-activate")
		case sensitive.DomainStaffCodeLookup, sensitive.DomainBonusPaymentLookup, sensitive.DomainIdentitySubjectLookup, sensitive.DomainLocalUsernameLookup:
			return errors.New("index activation requires its database maintenance command")
		}
	}
	raw, err := configfile.Read(*manifestFile, 1<<20, false)
	if err != nil || len(raw) == 0 {
		return errors.New("invalid manifest")
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	client := &sensitive.KeydClient{Socket: *socket, Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var state sensitive.ReadyState
	if action == "stage" {
		state, err = client.Stage(ctx, domain, sensitive.KeyReference{KeyID: *targetKeyID, Version: uint32(*targetVersion)}, digest[:])
	} else {
		state, err = client.Activate(ctx, domain, digest[:])
	}
	if err != nil {
		return errors.New("key lifecycle operation failed")
	}
	return json.NewEncoder(os.Stdout).Encode(state)
}

func status(args []string) error {
	set := flag.NewFlagSet("status", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	socket := set.String("socket", "", "local keyd Unix socket")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *socket == "" {
		return errors.New("invalid status arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state, err := (&sensitive.KeydClient{Socket: *socket, Timeout: 5 * time.Second}).Ready(ctx)
	if err != nil {
		return errors.New("local key service unavailable")
	}
	return json.NewEncoder(os.Stdout).Encode(state)
}

func readOfflineInputs(keyAFile, keyBFile, hostFile string) ([]byte, []byte, []byte, error) {
	keyA, err := configfile.Read(keyAFile, 32, true)
	if err != nil || len(keyA) != 32 {
		clear(keyA)
		return nil, nil, nil, errors.New("invalid media key A")
	}
	keyB, err := configfile.Read(keyBFile, 32, true)
	if err != nil || len(keyB) != 32 {
		clear(keyA)
		clear(keyB)
		return nil, nil, nil, errors.New("invalid media key B")
	}
	host, err := configfile.Read(hostFile, 4096, false)
	if err != nil {
		clear(keyA)
		clear(keyB)
		clear(host)
		return nil, nil, nil, errors.New("invalid host identity")
	}
	return keyA, keyB, host, nil
}

func offlineExport(args []string) error {
	set := flag.NewFlagSet("offline-export", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	keyDir := set.String("key-dir", "", "offline source key directory")
	archiveA := set.String("archive-a", "", "absolute archive path on media A")
	archiveB := set.String("archive-b", "", "absolute archive path on media B")
	keyAFile := set.String("media-key-a-file", "", "protected RAW32 media A key")
	keyBFile := set.String("media-key-b-file", "", "protected RAW32 media B key")
	hostFile := set.String("host-identity-file", "/etc/machine-id", "stable public host identity file")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *keyDir == "" || *archiveA == "" || *archiveB == "" || *keyAFile == "" || *keyBFile == "" {
		return errors.New("invalid offline export arguments")
	}
	keyA, keyB, host, err := readOfflineInputs(*keyAFile, *keyBFile, *hostFile)
	if err != nil {
		return err
	}
	defer clear(keyA)
	defer clear(keyB)
	defer clear(host)
	inventory, err := sensitive.ExportOfflinePair(*keyDir, *archiveA, *archiveB, keyA, keyB, host, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return fmt.Errorf("offline export failed: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Status    string                     `json:"status"`
		Inventory sensitive.OfflineInventory `json:"inventory"`
	}{"exported_unverified", inventory})
}

func offlineVerifyPair(args []string) error {
	set := flag.NewFlagSet("offline-verify-pair", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	archiveA := set.String("archive-a", "", "absolute read-only archive path on media A")
	archiveB := set.String("archive-b", "", "absolute read-only archive path on media B")
	keyAFile := set.String("media-key-a-file", "", "protected RAW32 media A key")
	keyBFile := set.String("media-key-b-file", "", "protected RAW32 media B key")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *archiveA == "" || *archiveB == "" || *keyAFile == "" || *keyBFile == "" {
		return errors.New("invalid offline verification arguments")
	}
	keyA, err := configfile.Read(*keyAFile, 32, true)
	if err != nil || len(keyA) != 32 {
		clear(keyA)
		return errors.New("invalid media key A")
	}
	defer clear(keyA)
	keyB, err := configfile.Read(*keyBFile, 32, true)
	if err != nil || len(keyB) != 32 {
		clear(keyB)
		return errors.New("invalid media key B")
	}
	defer clear(keyB)
	inventory, err := sensitive.VerifyOfflinePair(*archiveA, *archiveB, keyA, keyB)
	if err != nil {
		return errors.New("offline pair verification failed")
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Status    string                     `json:"status"`
		Inventory sensitive.OfflineInventory `json:"inventory"`
	}{"verified_pair", inventory})
}

func offlineRestore(args []string) error {
	set := flag.NewFlagSet("offline-restore", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	archive := set.String("archive", "", "absolute verified archive path")
	mediaKeyFile := set.String("media-key-file", "", "protected RAW32 media key")
	targetDir := set.String("target-key-dir", "", "nonexistent isolated target key directory")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *archive == "" || *mediaKeyFile == "" || *targetDir == "" {
		return errors.New("invalid offline restore arguments")
	}
	key, err := configfile.Read(*mediaKeyFile, 32, true)
	if err != nil || len(key) != 32 {
		clear(key)
		return errors.New("invalid media key")
	}
	defer clear(key)
	inventory, err := sensitive.RestoreOfflineArchive(*archive, *targetDir, key)
	if err != nil {
		return fmt.Errorf("offline restore failed: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Status    string                     `json:"status"`
		Inventory sensitive.OfflineInventory `json:"inventory"`
	}{"restored_isolated", inventory})
}

func csrfActivate(args []string) error {
	set := flag.NewFlagSet("csrf-activate", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	socket := set.String("socket", "", "local keyd Unix socket")
	manifestFile := set.String("manifest-file", "", "approved manifest file")
	backend := set.String("backend", "", "sqlite or postgres")
	dsnFile := set.String("dsn-file", "", "protected database DSN file")
	requestID := set.String("request-id", "", "maintenance request UUID")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *socket == "" || *manifestFile == "" || (*backend != "sqlite" && *backend != "postgres") || !value.ValidID(*requestID) {
		return errors.New("invalid CSRF activation arguments")
	}
	raw, err := configfile.Read(*manifestFile, 1<<20, false)
	if err != nil || len(raw) == 0 {
		return errors.New("invalid manifest")
	}
	manifest := sha256.Sum256(raw)
	clear(raw)
	dsnRaw, err := configfile.Read(*dsnFile, 16<<10, true)
	if err != nil {
		return errors.New("invalid database configuration")
	}
	defer clear(dsnRaw)
	client := &sensitive.KeydClient{Socket: *socket, Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	state, err := client.Ready(ctx)
	staged := state.Staged[sensitive.DomainCSRFToken]
	if err != nil || staged.Version == 0 || staged.KeyID == "" {
		return errors.New("CSRF key is not staged")
	}
	repo, err := store.Open(ctx, *backend, string(dsnRaw))
	if err != nil {
		return errors.New("database unavailable")
	}
	defer repo.Close()
	if err = repo.CheckSchema(ctx); err != nil {
		return errors.New("invalid database schema")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if state.Active[sensitive.DomainCSRFToken] != staged.Version {
		if err = repo.BeginCryptoStage(ctx, state, sensitive.DomainCSRFToken, manifest[:], now); err != nil {
			return err
		}
		if err = repo.RevokeCSRFVersion(ctx, state.ActiveKeys[sensitive.DomainCSRFToken], *requestID, now); err != nil {
			return err
		}
		state, err = client.Activate(ctx, sensitive.DomainCSRFToken, manifest[:])
		if err != nil {
			return errors.New("CSRF activation failed after safe session revocation")
		}
	}
	if err = repo.RecordCryptoActivation(ctx, state, sensitive.DomainCSRFToken, manifest[:], now); err != nil {
		return err
	}
	state, err = client.Acknowledge(ctx, sensitive.DomainCSRFToken, manifest[:])
	if err != nil {
		return errors.New("CSRF activation acknowledgement failed")
	}
	if err = repo.CompleteCryptoActivation(ctx, state, sensitive.DomainCSRFToken, manifest[:], now); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(state)
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: keyctl-local init|status|stage|activate|csrf-activate|offline-export|offline-verify-pair|offline-restore")
	}
	switch args[0] {
	case "init":
		set := flag.NewFlagSet("init", flag.ContinueOnError)
		set.SetOutput(os.Stderr)
		directory := set.String("dir", "", "absolute key directory")
		if err := set.Parse(args[1:]); err != nil || set.NArg() != 0 || *directory == "" {
			return errors.New("invalid init arguments")
		}
		return sensitive.InitKeyDirectory(*directory)
	case "status":
		return status(args[1:])
	case "stage", "activate":
		return lifecycle(args[0], args[1:])
	case "csrf-activate":
		return csrfActivate(args[1:])
	case "offline-export":
		return offlineExport(args[1:])
	case "offline-verify-pair":
		return offlineVerifyPair(args[1:])
	case "offline-restore":
		return offlineRestore(args[1:])
	default:
		return errors.New("usage: keyctl-local init|status|stage|activate|csrf-activate|offline-export|offline-verify-pair|offline-restore")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		switch {
		case errors.Is(err, sensitive.ErrOfflinePublishIndeterminate):
			_ = json.NewEncoder(os.Stderr).Encode(struct {
				Status string `json:"status"`
				Action string `json:"action"`
			}{"failed_indeterminate", "keep_keyd_stopped_and_inspect_requested_paths"})
		case errors.Is(err, sensitive.ErrOfflinePublishRolledBack):
			_ = json.NewEncoder(os.Stderr).Encode(struct {
				Status string `json:"status"`
				Action string `json:"action"`
			}{"failed_rolled_back", "inspect_requested_paths_before_retry"})
		default:
			fmt.Fprintln(os.Stderr, "key control failed")
		}
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "init" {
		fmt.Println("key directory initialized")
	}
}
