package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/r404r/team-ledger/internal/backup"
	"github.com/r404r/team-ledger/internal/configfile"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/store"
)

func protected(path string, limit int) ([]byte, error) { return configfile.Read(path, limit, true) }

var keyEnvelopeMagic = [8]byte{'T', 'L', 'B', 'K', 'E', 'Y', 'D', 1}

func writeArchiveKey(out io.Writer, key sensitive.WrappedKey) error {
	if len(key.Data) != 150 {
		return errors.New("invalid archive key")
	}
	header := make([]byte, 12)
	copy(header, keyEnvelopeMagic[:])
	binary.BigEndian.PutUint16(header[8:10], 1)
	binary.BigEndian.PutUint16(header[10:12], uint16(len(key.Data)))
	if _, err := out.Write(header); err != nil {
		return err
	}
	_, err := out.Write(key.Data)
	return err
}

func readArchiveKey(in io.Reader) (sensitive.WrappedKey, error) {
	header := make([]byte, 12)
	if _, err := io.ReadFull(in, header); err != nil ||
		string(header[:8]) != string(keyEnvelopeMagic[:]) ||
		binary.BigEndian.Uint16(header[8:10]) != 1 ||
		binary.BigEndian.Uint16(header[10:12]) != 150 {
		return sensitive.WrappedKey{}, errors.New("invalid archive key header")
	}
	packet := make([]byte, 150)
	if _, err := io.ReadFull(in, packet); err != nil {
		return sensitive.WrappedKey{}, errors.New("truncated archive key")
	}
	return sensitive.ParseBackupWrappedKey(packet)
}

func hashFile(path string) (int64, string, error) {
	file, e := os.Open(path)
	if e != nil {
		return 0, "", e
	}
	defer file.Close()
	hash := sha256.New()
	size, e := io.Copy(hash, file)
	if e != nil {
		return 0, "", e
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}
func syncRename(temp, final string) error {
	file, e := os.OpenFile(temp, os.O_RDWR, 0)
	if e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		file.Close()
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	if e = os.Rename(temp, final); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(final))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func createSQLite(ctx context.Context, dsn, archivePath string, keyd *sensitive.KeydClient, now time.Time) error {
	if !filepath.IsAbs(dsn) || !filepath.IsAbs(archivePath) {
		return errors.New("absolute paths required")
	}
	repo, e := store.Open(ctx, "sqlite", dsn)
	if e != nil {
		return e
	}
	defer repo.Close()
	work, e := os.MkdirTemp(filepath.Dir(archivePath), ".teamledger-snapshot-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	if e = os.Chmod(work, 0700); e != nil {
		return e
	}
	snapshotPath := filepath.Join(work, "database.sqlite")
	if e = repo.SQLiteSnapshot(ctx, snapshotPath); e != nil {
		return e
	}
	if e = os.Chmod(snapshotPath, 0600); e != nil {
		return e
	}
	snapshotInfo, statErr := os.Lstat(snapshotPath)
	if statErr != nil || !snapshotInfo.Mode().IsRegular() || snapshotInfo.Mode()&os.ModeSymlink != 0 || snapshotInfo.Mode().Perm() != 0600 {
		return errors.New("unsafe SQLite snapshot")
	}
	snapRepo, e := store.Open(ctx, "sqlite", snapshotPath)
	if e != nil {
		return e
	}
	manifest, e := snapRepo.BackupManifest(ctx, now, 0, strings.Repeat("0", 64))
	snapRepo.Close()
	if e == nil {
		manifest.DatabaseSize, manifest.DatabaseSHA256, e = hashFile(snapshotPath)
	}
	if e != nil {
		return e
	}
	return sealSnapshot(ctx, snapshotPath, archivePath, keyd, manifest)
}

func sealSnapshot(ctx context.Context, snapshotPath, archivePath string, keyd *sensitive.KeydClient, manifest backup.Manifest) error {
	source, e := os.Open(snapshotPath)
	if e != nil {
		return e
	}
	defer source.Close()
	temp, e := os.CreateTemp(filepath.Dir(archivePath), ".teamledger-backup-*")
	if e != nil {
		return e
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	var archiveKey [32]byte
	if _, e = rand.Read(archiveKey[:]); e == nil {
		var wrapped sensitive.WrappedKey
		wrapped, e = keyd.WrapBackup(ctx, archiveKey[:])
		if e == nil {
			e = writeArchiveKey(temp, wrapped)
		}
		if e == nil {
			e = backup.WriteArchive(temp, source, manifest, archiveKey[:])
		}
	}
	clear(archiveKey[:])
	closeErr := temp.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if _, e = os.Lstat(archivePath); !os.IsNotExist(e) {
		return errors.New("archive already exists")
	}
	return syncRename(tempPath, archivePath)
}

var pgDumpBinary = "/usr/bin/pg_dump"

var pgRestoreBinary = "/usr/bin/pg_restore"

func serviceQuote(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("invalid PostgreSQL service value")
	}
	return "'" + strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "'", "\\'") + "'", nil
}

func pgPassEscape(value string) string {
	return strings.NewReplacer("\\", "\\\\", ":", "\\:").Replace(value)
}

func postgresClientFiles(dsn, caPath, directory string) (string, string, string, error) {
	u, e := url.Parse(dsn)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.User == nil || u.User.Username() == "" || u.Path == "" || u.Path == "/" {
		return "", "", "", errors.New("invalid PostgreSQL URL")
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return "", "", "", errors.New("PostgreSQL password required")
	}
	query := u.Query()
	if query.Get("sslmode") != "verify-full" || query.Get("sslrootcert") != caPath {
		return "", "", "", errors.New("verified PostgreSQL TLS required")
	}
	schema := query.Get("search_path")
	for key := range query {
		if key != "sslmode" && key != "sslrootcert" && key != "search_path" {
			return "", "", "", errors.New("unsupported PostgreSQL URL option")
		}
	}
	if schema != "" {
		for _, char := range schema {
			if !(char == '_' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
				return "", "", "", errors.New("invalid PostgreSQL schema")
			}
		}
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	database := strings.TrimPrefix(u.EscapedPath(), "/")
	database, e = url.PathUnescape(database)
	if e != nil {
		return "", "", "", e
	}
	ca, e := configfile.Read(caPath, 1<<20, false)
	if e != nil {
		return "", "", "", e
	}
	defer clear(ca)
	caCopy := filepath.Join(directory, "postgres-ca.pem")
	passFile := filepath.Join(directory, "postgres.pgpass")
	serviceFile := filepath.Join(directory, "postgres.service")
	if e = os.WriteFile(caCopy, ca, 0600); e != nil {
		return "", "", "", e
	}
	pass := strings.Join([]string{pgPassEscape(u.Hostname()), pgPassEscape(port), pgPassEscape(database), pgPassEscape(u.User.Username()), pgPassEscape(password)}, ":") + "\n"
	if e = os.WriteFile(passFile, []byte(pass), 0600); e != nil {
		return "", "", "", e
	}
	values := []string{u.Hostname(), port, database, u.User.Username(), caCopy, passFile}
	for i := range values {
		values[i], e = serviceQuote(values[i])
		if e != nil {
			return "", "", "", e
		}
	}
	service := "[teamledger_backup]\nhost=" + values[0] + "\nport=" + values[1] + "\ndbname=" + values[2] + "\nuser=" + values[3] + "\nsslmode=verify-full\nsslrootcert=" + values[4] + "\npassfile=" + values[5] + "\n"
	if e = os.WriteFile(serviceFile, []byte(service), 0600); e != nil {
		return "", "", "", e
	}
	return serviceFile, schema, caCopy, nil
}

func createPostgres(ctx context.Context, dsn, caPath, archivePath string, keyd *sensitive.KeydClient, now time.Time) error {
	if !filepath.IsAbs(caPath) || !filepath.IsAbs(archivePath) || !filepath.IsAbs(pgDumpBinary) || filepath.Base(pgDumpBinary) != "pg_dump" {
		return errors.New("invalid PostgreSQL backup configuration")
	}
	ca, e := configfile.Read(caPath, 1<<20, false)
	if e != nil {
		return e
	}
	defer clear(ca)
	repo, e := store.OpenPostgresWithCheckedCA(ctx, dsn, ca)
	if e != nil {
		return e
	}
	defer repo.Close()
	tx, snapshot, e := repo.BeginPostgresBackup(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	work, e := os.MkdirTemp(filepath.Dir(archivePath), ".teamledger-pgdump-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	if e = os.Chmod(work, 0700); e != nil {
		return e
	}
	serviceFile, schema, _, e := postgresClientFiles(dsn, caPath, work)
	if e != nil {
		return e
	}
	dumpPath := filepath.Join(work, "database.dump")
	args := []string{"--format=custom", "--serializable-deferrable", "--no-owner", "--no-acl", "--snapshot=" + snapshot, "--file=" + dumpPath, "--dbname=service=teamledger_backup"}
	if schema != "" {
		args = append(args, "--schema="+schema)
	}
	command := exec.CommandContext(ctx, pgDumpBinary, args...)
	command.Env = []string{"PGSERVICEFILE=" + serviceFile, "PGSYSCONFDIR=/nonexistent"}
	output, runErr := command.CombinedOutput()
	clear(output)
	if runErr != nil {
		return errors.New("pg_dump failed")
	}
	size, digest, e := hashFile(dumpPath)
	if e != nil {
		return e
	}
	manifest, e := repo.BackupManifestTx(ctx, tx, now, size, digest)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	return sealSnapshot(ctx, dumpPath, archivePath, keyd, manifest)
}
func loadWrappers(client *sensitive.KeydClient) (map[string]sensitive.Wrapper, error) {
	if _, err := client.Ready(context.Background()); err != nil {
		return nil, errors.New("local key service unavailable")
	}
	out := make(map[string]sensitive.Wrapper, 4)
	for domain, keyDomain := range map[string]sensitive.KeyDomain{
		"pii": sensitive.DomainPIIPayload, "interview": sensitive.DomainInterviewPayload,
		"assessment": sensitive.DomainAssessmentPayload, "financial": sensitive.DomainFinancialPayload, "identity_mfa": sensitive.DomainIdentityMFA,
	} {
		wrapper, err := sensitive.NewKeydWrapper(client, keyDomain)
		if err != nil {
			return nil, err
		}
		out[domain] = wrapper
	}
	return out, nil
}
func restore(ctx context.Context, archivePath, target string, keyd *sensitive.KeydClient, now time.Time) error {
	if !filepath.IsAbs(archivePath) || !filepath.IsAbs(target) {
		return errors.New("absolute paths required")
	}
	if _, e := os.Lstat(target); !os.IsNotExist(e) {
		return errors.New("target already exists")
	}
	source, e := os.Open(archivePath)
	if e != nil {
		return e
	}
	defer source.Close()
	archiveHash := sha256.New()
	reader := io.TeeReader(source, archiveHash)
	temp, e := os.CreateTemp(filepath.Dir(target), ".teamledger-restore-*")
	if e != nil {
		return e
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if e = temp.Chmod(0600); e != nil {
		temp.Close()
		return e
	}
	wrapped, e := readArchiveKey(reader)
	if e != nil {
		temp.Close()
		return e
	}
	key, e := keyd.UnwrapBackup(ctx, wrapped)
	if e != nil {
		temp.Close()
		return errors.New("required archive key unavailable")
	}
	manifest, e := backup.ReadArchive(reader, temp, key)
	clear(key)
	closeErr := temp.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if manifest.Backend != "sqlite" || manifest.SchemaVersion != 14 {
		return errors.New("incompatible backup")
	}
	repo, e := store.Open(ctx, "sqlite", tempPath)
	if e != nil {
		return e
	}
	defer repo.Close()
	if e = repo.CheckSchema(ctx); e != nil {
		return e
	}
	wrappers, e := loadWrappers(keyd)
	if e != nil {
		return e
	}
	samples, e := repo.BackupKeySamples(ctx)
	if e != nil {
		return e
	}
	for _, sample := range samples {
		wrapper := wrappers[sample.Domain]
		if wrapper == nil {
			return errors.New("required independent key unavailable")
		}
		dek, unwrapErr := wrapper.Unwrap(ctx, sample.Key)
		clear(dek)
		if unwrapErr != nil {
			return errors.New("required independent key unavailable")
		}
	}
	host, e := os.Hostname()
	if e != nil || host == "" {
		return errors.New("invalid host")
	}
	hostDigest := sha256.Sum256([]byte("TEAMLEDGER-RESTORE-HOST\x00\x01" + host))
	if e = repo.FinalizeRestore(ctx, archiveHash.Sum(nil), hostDigest[:], int64(os.Geteuid()), now); e != nil {
		return e
	}
	if e = repo.Close(); e != nil {
		return e
	}
	return syncRename(tempPath, target)
}
func postgresRestoreList(ctx context.Context, dumpPath, work string) (string, error) {
	command := exec.CommandContext(ctx, pgRestoreBinary, "--list", dumpPath)
	output, err := command.Output()
	if err != nil {
		clear(output)
		return "", errors.New("pg_restore list failed")
	}
	defer clear(output)
	lines := strings.Split(string(output), "\n")
	removed := map[string]int{"session": 0, "session_auth": 0, "oidc_transaction": 0}
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[3] == "SCHEMA" && fields[4] == "-" && fields[5] == "public" {
			lines[index] = ";" + line
			continue
		}
		if len(fields) >= 8 && fields[3] == "TABLE" && fields[4] == "DATA" {
			if _, protected := removed[fields[len(fields)-2]]; protected {
				removed[fields[len(fields)-2]]++
				lines[index] = ";" + line
			}
		}
	}
	for _, table := range []string{"session", "session_auth", "oidc_transaction"} {
		if removed[table] != 1 {
			return "", errors.New("invalid PostgreSQL backup inventory")
		}
	}
	listPath := filepath.Join(work, "restore.list")
	if err = os.WriteFile(listPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		return "", err
	}
	return listPath, nil
}

func restorePostgres(ctx context.Context, archivePath, targetDSN, caPath string, keyd *sensitive.KeydClient, now time.Time) error {
	if !filepath.IsAbs(archivePath) || !filepath.IsAbs(caPath) || !filepath.IsAbs(pgRestoreBinary) || filepath.Base(pgRestoreBinary) != "pg_restore" {
		return errors.New("invalid PostgreSQL restore configuration")
	}
	work, e := os.MkdirTemp(filepath.Dir(archivePath), ".teamledger-pgrestore-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	if e = os.Chmod(work, 0700); e != nil {
		return e
	}
	dumpPath := filepath.Join(work, "database.dump")
	dump, e := os.OpenFile(dumpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	source, e := os.Open(archivePath)
	if e != nil {
		dump.Close()
		return e
	}
	archiveHash := sha256.New()
	reader := io.TeeReader(source, archiveHash)
	wrapped, readErr := readArchiveKey(reader)
	if readErr != nil {
		source.Close()
		dump.Close()
		return readErr
	}
	key, readErr := keyd.UnwrapBackup(ctx, wrapped)
	if readErr != nil {
		source.Close()
		dump.Close()
		return errors.New("required archive key unavailable")
	}
	manifest, readErr := backup.ReadArchive(reader, dump, key)
	clear(key)
	source.Close()
	closeErr := dump.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if manifest.Backend != "postgres" || manifest.SchemaVersion != 14 {
		return errors.New("incompatible backup")
	}
	restoreList, e := postgresRestoreList(ctx, dumpPath, work)
	if e != nil {
		return e
	}
	serviceFile, _, _, e := postgresClientFiles(targetDSN, caPath, work)
	if e != nil {
		return e
	}
	command := exec.CommandContext(ctx, pgRestoreBinary, "--exit-on-error", "--single-transaction", "--no-owner", "--no-acl", "--use-list="+restoreList, "--dbname=service=teamledger_backup", dumpPath)
	command.Env = []string{"PGSERVICEFILE=" + serviceFile, "PGSYSCONFDIR=/nonexistent"}
	output, runErr := command.CombinedOutput()
	clear(output)
	if runErr != nil {
		return errors.New("pg_restore failed")
	}
	ca, e := configfile.Read(caPath, 1<<20, false)
	if e != nil {
		return e
	}
	defer clear(ca)
	repo, e := store.OpenPostgresWithCheckedCA(ctx, targetDSN, ca)
	if e != nil {
		return e
	}
	defer repo.Close()
	if e = repo.CheckSchema(ctx); e != nil {
		return e
	}
	wrappers, e := loadWrappers(keyd)
	if e != nil {
		return e
	}
	samples, e := repo.BackupKeySamples(ctx)
	if e != nil {
		return e
	}
	for _, sample := range samples {
		wrapper := wrappers[sample.Domain]
		if wrapper == nil {
			return errors.New("required independent key unavailable")
		}
		dek, unwrapErr := wrapper.Unwrap(ctx, sample.Key)
		clear(dek)
		if unwrapErr != nil {
			return errors.New("required independent key unavailable")
		}
	}
	host, e := os.Hostname()
	if e != nil || host == "" {
		return errors.New("invalid host")
	}
	hostDigest := sha256.Sum256([]byte("TEAMLEDGER-RESTORE-HOST\x00\x01" + host))
	return repo.FinalizeRestore(ctx, archiveHash.Sum(nil), hostDigest[:], int64(os.Geteuid()), now)
}
func run(args []string) error {

	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	action := flags.String("action", "", "")
	backend := flags.String("backend", "", "")
	dbCA := flags.String("postgres-ca-file", "", "")
	dsnFile := flags.String("dsn-file", "", "")
	archivePath := flags.String("archive", "", "")
	target := flags.String("target", "", "")
	keydSocket := flags.String("keyd-socket", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("invalid arguments")
	}
	if *keydSocket == "" {
		return errors.New("keyd socket is required")
	}
	keyd := &sensitive.KeydClient{Socket: *keydSocket, Timeout: 10 * time.Second}
	if _, e := keyd.Ready(context.Background()); e != nil {
		return errors.New("local key service unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	switch *action {
	case "create":
		if *target != "" {
			return errors.New("invalid create arguments")
		}
		dsnRaw, e := protected(*dsnFile, 16<<10)
		if e != nil {
			return e
		}
		defer clear(dsnRaw)
		dsn := strings.TrimSpace(string(dsnRaw))
		switch *backend {
		case "sqlite":
			if *dbCA != "" {
				return errors.New("invalid SQLite backup arguments")
			}
			return createSQLite(ctx, dsn, *archivePath, keyd, now)
		case "postgres":
			return createPostgres(ctx, dsn, *dbCA, *archivePath, keyd, now)
		default:
			return errors.New("invalid backend")
		}
	case "restore":
		switch *backend {
		case "sqlite":
			if *dsnFile != "" || *dbCA != "" || *target == "" {
				return errors.New("invalid SQLite restore arguments")
			}
			return restore(ctx, *archivePath, *target, keyd, now)
		case "postgres":
			if *target != "" {
				return errors.New("invalid PostgreSQL restore arguments")
			}
			dsnRaw, readErr := protected(*dsnFile, 16<<10)
			if readErr != nil {
				return readErr
			}
			defer clear(dsnRaw)
			return restorePostgres(ctx, *archivePath, strings.TrimSpace(string(dsnRaw)), *dbCA, keyd, now)
		default:
			return errors.New("invalid backend")
		}
	default:
		return errors.New("invalid action")
	}
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "backup operation failed")
		os.Exit(1)
	}
	fmt.Println("backup operation committed")
}
