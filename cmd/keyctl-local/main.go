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

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: keyctl-local init|status|stage|activate")
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
	default:
		return errors.New("usage: keyctl-local init|status|stage|activate")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "key control failed")
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "init" {
		fmt.Println("key directory initialized")
	}
}
