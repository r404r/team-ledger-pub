package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/store"
)

func owner(value string) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, errors.New("invalid owner")
	}
	return int(parsed), nil
}

func requiredEnv(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", errors.New("missing audit retirement database configuration")
	}
	return value, nil
}

func databaseDSN() (string, error) {
	direct := os.Getenv("TEAMLEDGER_DB_DSN")
	path := os.Getenv("TEAMLEDGER_DB_DSN_FILE")
	if direct != "" && path != "" {
		return "", errors.New("ambiguous audit retirement database configuration")
	}
	if path == "" {
		if direct == "" {
			return "", errors.New("missing audit retirement database configuration")
		}
		return direct, nil
	}
	raw, err := configfile.Read(path, 32<<10, true)
	if err != nil || bytes.ContainsAny(raw, "\x00\r\n") {
		clear(raw)
		return "", errors.New("invalid audit retirement database configuration")
	}
	dsn := string(raw)
	clear(raw)
	return dsn, nil
}

func noUnackedSignerDependencies(ctx context.Context, keyID string) error {
	backend, err := requiredEnv("TEAMLEDGER_DB_BACKEND")
	if err != nil {
		return err
	}
	dsn, err := databaseDSN()
	if err != nil {
		return err
	}
	var repository *store.Repository
	if backend == "sqlite" {
		repository, err = store.Open(ctx, backend, dsn)
	} else if backend == "postgres" {
		caPath, pathErr := requiredEnv("TEAMLEDGER_DB_CA_FILE")
		if pathErr != nil {
			return pathErr
		}
		ca, readErr := configfile.Read(caPath, 1<<20, false)
		if readErr != nil {
			return readErr
		}
		defer clear(ca)
		repository, err = store.OpenPostgresWithCheckedCA(ctx, dsn, ca)
	} else {
		return errors.New("unsupported audit retirement database")
	}
	if err != nil {
		return errors.New("audit retirement database unavailable")
	}
	defer repository.Close()
	query := "SELECT count(*) FROM audit_receiver_ledger l JOIN audit_outbox o ON o.event_id=l.event_id WHERE l.key_id=? AND o.state<>'acked'"
	if backend == "postgres" {
		query = "SELECT count(*) FROM audit_receiver_ledger l JOIN audit_outbox o ON o.event_id=l.event_id WHERE l.key_id=$1 AND o.state<>'acked'"
	}
	var count int64
	if err = repository.DB.QueryRowContext(ctx, query, keyID).Scan(&count); err != nil {
		return errors.New("cannot verify audit signer dependencies")
	}
	if count != 0 {
		return errors.New("unacknowledged audit receipts still require signer trust")
	}
	return nil
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("missing audit material command")
	}
	command := args[0]
	if command != "init" && command != "signer-id" && command != "rotate-signer" && command != "retire-signer" && command != "rotate-leaves" && command != "rotate-ca" && command != "retire-ca" {
		return errors.New("unsupported audit material command")
	}
	flags := flag.NewFlagSet("audit-bootstrap "+command, flag.ContinueOnError)
	directory := flags.String("dir", "", "absolute audit material directory")
	receiverName := flags.String("receiver-name", "audit-receiver", "receiver TLS DNS name")
	bootstrapUID := flags.String("bootstrap-uid", "0", "bootstrap owner uid")
	receiverUID := flags.String("receiver-uid", "", "receiver uid")
	forwarderUID := flags.String("forwarder-uid", "", "forwarder uid")
	gid := flags.String("gid", "", "shared gid")
	retireKey := flags.String("key-id", "", "retired receipt signer key id")
	confirmNoBackupDependencies := flags.Bool("confirm-no-backup-dependencies", false, "confirm retained backups no longer depend on the retired receipt key")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *directory == "" || *receiverUID == "" || *forwarderUID == "" || *gid == "" {
		return errors.New("invalid audit material arguments")
	}
	bootstrapOwner, err := owner(*bootstrapUID)
	if err != nil {
		return err
	}
	receiverOwner, err := owner(*receiverUID)
	if err != nil {
		return err
	}
	forwarderOwner, err := owner(*forwarderUID)
	if err != nil {
		return err
	}
	group, err := owner(*gid)
	if err != nil {
		return err
	}
	owners := audit.MaterialOwners{BootstrapUID: bootstrapOwner, ReceiverUID: receiverOwner, ForwarderUID: forwarderOwner, GID: group}
	now := time.Now().UTC().Truncate(time.Microsecond)
	switch command {
	case "init":
		if *retireKey != "" {
			return errors.New("key id is not valid for init")
		}
		return audit.BootstrapMaterial(*directory, *receiverName, owners, now)
	case "signer-id":
		keyID, keyErr := audit.CurrentSignerID(*directory, owners)
		if keyErr == nil {
			fmt.Println("active_key_id=" + keyID)
		}
		return keyErr
	case "rotate-signer":
		if *retireKey != "" {
			return errors.New("key id is not valid for rotate-signer")
		}
		keyID, rotateErr := audit.RotateSigner(*directory, owners, now)
		if rotateErr == nil {
			fmt.Println("active_key_id=" + keyID)
		}
		return rotateErr
	case "retire-signer":
		if *retireKey == "" {
			return errors.New("key id is required")
		}
		if !*confirmNoBackupDependencies {
			return errors.New("backup dependency confirmation is required")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := noUnackedSignerDependencies(ctx, *retireKey); err != nil {
			return err
		}
		return audit.RetireSigner(*directory, owners, *retireKey, true)
	case "rotate-leaves":
		if *retireKey != "" {
			return errors.New("key id is not valid for rotate-leaves")
		}
		return audit.RotateLeaves(*directory, *receiverName, owners, now)
	case "rotate-ca":
		if *retireKey != "" {
			return errors.New("key id is not valid for rotate-ca")
		}
		return audit.RotateCA(*directory, *receiverName, owners, now)
	case "retire-ca":
		if *retireKey != "" {
			return errors.New("key id is not valid for retire-ca")
		}
		return audit.RetireOldCA(*directory, owners)
	}
	return errors.New("unsupported audit material command")
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "audit material operation failed:", err)
		os.Exit(1)
	}
}
