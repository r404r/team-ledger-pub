package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/sensitive"
	"github.com/r404r/team-ledger/internal/value"
)

type StaffCodeMAC func(context.Context, []byte) (sensitive.MACValue, error)
type StaffNormalizationOptions struct {
	Apply            bool
	ExpectedSnapshot string
	RequestID        string
}
type StaffNormalizationReport struct {
	SchemaVersion  int      `json:"schema_version"`
	Identifiers    int      `json:"identifiers"`
	ShortNumeric   int      `json:"short_numeric"`
	LongNumeric    int      `json:"long_numeric"`
	ConflictPairs  int      `json:"conflict_pairs"`
	NonNumeric     int      `json:"non_numeric"`
	ReservedOwners int      `json:"reserved_owners"`
	Snapshot       string   `json:"snapshot"`
	Blockers       []string `json:"blockers"`
	Applied        bool     `json:"applied"`
}
type normalizationSource struct {
	StaffIndexSource
	KeyID      string
	KeyVersion uint32
	PayloadID  string
	ValidFrom  string
	ValidTo    *string
}
type normalizationOwner struct {
	OrgID, EmployeeID, KeyID string
	KeyVersion               uint32
	Digest                   []byte
}
type normalizationReplacement struct {
	source normalizationSource
	mac    sensitive.MACValue
}

// NormalizeStaffCodes is an offline maintenance boundary. It never edits source
// facts, releases owners, or returns decrypted identifiers in reports/errors.
// The caller must stop all application processes and verify a restored DB/key pair.
func (r *Repository) NormalizeStaffCodes(ctx context.Context, cipher sensitive.Cipher, mac StaffCodeMAC, options StaffNormalizationOptions) (StaffNormalizationReport, error) {
	report := StaffNormalizationReport{Blockers: []string{}}
	if mac == nil {
		return report, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return report, safeError(err)
	}
	defer tx.Rollback()
	q := reader{tx, r.Backend}
	if options.Apply {
		if len(options.ExpectedSnapshot) != 64 {
			return report, fault.Invalid
		}
		if r.Backend == "postgres" {
			var locked bool
			if err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended(current_schema(),724202603))").Scan(&locked); err != nil || !locked {
				return report, fault.Busy
			}
			if _, err = tx.ExecContext(ctx, "LOCK TABLE schema_version,employee_business_identifier,employee_identifier_owner,workforce_payload IN ACCESS EXCLUSIVE MODE NOWAIT"); err != nil {
				return report, safeError(err)
			}
		} else {
			if _, err = tx.ExecContext(ctx, "UPDATE schema_version SET version=version"); err != nil {
				return report, safeError(err)
			}
		}
	}
	version, err := r.ledgerVersion(ctx, tx)
	if err != nil || (version != 19 && version != 20) {
		return report, fault.Unavailable
	}
	report.SchemaVersion = version
	if err = r.checkSchemaVersion(ctx, tx, version); err != nil {
		return report, err
	}
	sources, err := normalizationSources(ctx, q, "employee_business_identifier")
	if err != nil {
		return report, err
	}
	effective := sources
	if version == 20 {
		effective, err = normalizationSources(ctx, q, "staff_code_identifier")
		if err != nil {
			return report, err
		}
	}
	owners, err := normalizationOwners(ctx, q)
	if err != nil {
		return report, err
	}
	report.Snapshot = normalizationSnapshot(version, sources, effective, owners)
	report.Identifiers = len(sources)
	if options.Apply && options.ExpectedSnapshot != report.Snapshot {
		if version != 20 {
			return report, fault.Conflict
		}
		var resultSnapshot string
		if e := tx.QueryRowContext(ctx, q.structureSQL("SELECT result_snapshot FROM staff_code_normalization_receipt WHERE snapshot=?"), options.ExpectedSnapshot).Scan(&resultSnapshot); e != nil || resultSnapshot != report.Snapshot {
			return report, fault.Conflict
		}
	}
	verified := map[string]bool{}
	ownerKey := func(org, key string, version uint32, digest []byte) string {
		b, _ := json.Marshal([]any{org, key, version, digest})
		return string(b)
	}
	block := func(code string) {
		for _, existing := range report.Blockers {
			if existing == code {
				return
			}
		}
		report.Blockers = append(report.Blockers, code)
	}
	decode := func(source normalizationSource) (string, bool) {
		c := sensitive.Context{OrgID: source.OrgID, EmployeeID: source.EmployeeID, RecordID: source.ID, VersionID: source.PayloadID, ObjectKind: "employee_identifier", Purpose: "pii", SchemaType: "pii.employee_identifier.v1", SchemaVersion: 1}
		plain, e := cipher.Open(ctx, c, source.Envelope)
		if e != nil {
			block("ciphertext_invalid")
			return "", false
		}
		defer clear(plain)
		var body struct {
			StaffCode string `json:"staff_code"`
		}
		decoder := json.NewDecoder(bytes.NewReader(plain))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			block("ciphertext_invalid")
			return "", false
		}
		return body.StaffCode, true
	}
	compute := func(org, code string) (sensitive.MACValue, bool) {
		frame := []byte("staff-code\x00" + org + "\x00" + code)
		defer clear(frame)
		m, e := mac(ctx, frame)
		if e != nil || m.KeyID == "" || m.Version == 0 || len(m.Digest) != 32 {
			block("key_unavailable")
			return m, false
		}
		return m, true
	}
	type interval struct {
		employee, raw, from string
		to                  *string
	}
	intervals := map[string][]interval{}
	normalizedOwners := map[string]string{}
	replacements := []normalizationReplacement{}
	for index, source := range sources {
		raw, ok := decode(source)
		if !ok {
			continue
		}
		old, ok := compute(source.OrgID, raw)
		if !ok {
			continue
		}
		if source.KeyID != old.KeyID || source.KeyVersion != old.Version || !bytes.Equal(source.OldDigest, old.Digest) {
			block("source_lookup_invalid")
			continue
		}
		verified[ownerKey(source.OrgID, old.KeyID, old.Version, old.Digest)+source.EmployeeID] = true
		normalized, valid := organization.NormalizeStaffCode(raw)
		numeric := len(raw) > 0
		for _, c := range raw {
			if c < '0' || c > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			if len(raw) < 6 {
				report.ShortNumeric++
			}
			if len(raw) > 10 {
				report.LongNumeric++
			}
		} else {
			report.NonNumeric++
		}
		if !valid {
			block("invalid_staff_code")
			continue
		}
		target, ok := compute(source.OrgID, normalized)
		if !ok {
			continue
		}
		key := ownerKey(source.OrgID, target.KeyID, target.Version, target.Digest)
		if owner, found := normalizedOwners[key]; found && owner != source.EmployeeID {
			block("owner_conflict")
		}
		normalizedOwners[key] = source.EmployeeID
		intervals[key] = append(intervals[key], interval{source.EmployeeID, raw, source.ValidFrom, source.ValidTo})
		current := effective[index]
		currentRaw, ok := decode(current)
		if !ok {
			continue
		}
		currentMAC, ok := compute(source.OrgID, currentRaw)
		if !ok {
			continue
		}
		if current.KeyID != currentMAC.KeyID || current.KeyVersion != currentMAC.Version || !bytes.Equal(current.OldDigest, currentMAC.Digest) {
			block("projection_lookup_invalid")
			continue
		}
		verified[ownerKey(source.OrgID, currentMAC.KeyID, currentMAC.Version, currentMAC.Digest)+source.EmployeeID] = true
		if current.PayloadID != source.PayloadID && currentRaw != normalized {
			block("projection_invalid")
			continue
		}
		if raw == normalized || currentRaw == normalized {
			continue
		}
		// Seal only after the entire read-only validation pass succeeds.
		replacements = append(replacements, normalizationReplacement{source: source, mac: target})
	}
	for _, group := range intervals {
		distinct := map[string]bool{}
		for _, interval := range group {
			distinct[interval.raw] = true
		}
		report.ConflictPairs += len(distinct) * (len(distinct) - 1) / 2
		sort.Slice(group, func(i, j int) bool {
			if group[i].employee != group[j].employee {
				return group[i].employee < group[j].employee
			}
			return group[i].from < group[j].from
		})
		for i := 1; i < len(group); i++ {
			prior, current := group[i-1], group[i]
			if prior.employee == current.employee && (prior.to == nil || current.from < *prior.to) {
				block("interval_overlap")
				break
			}
		}
	}
	for _, owner := range owners {
		key := ownerKey(owner.OrgID, owner.KeyID, owner.KeyVersion, owner.Digest)
		if !verified[key+owner.EmployeeID] {
			report.ReservedOwners++
			block("owner_unverifiable")
		}
		if targetOwner, found := normalizedOwners[key]; found && targetOwner != owner.EmployeeID {
			block("owner_conflict")
		}
	}
	if len(report.Blockers) > 0 {
		return report, fault.Conflict
	}
	if !options.Apply {
		return report, nil
	}
	if version == 19 {
		ddl, checksum, e := r.migration(20)
		if e != nil {
			return report, e
		}
		for _, statement := range migrationStatements(ddl) {
			if _, e = tx.ExecContext(ctx, statement); e != nil {
				return report, safeError(e)
			}
		}
		if _, e = tx.ExecContext(ctx, q.structureSQL("INSERT INTO schema_version(version,backend,checksum) VALUES(20,?,?)"), r.Backend, checksum); e != nil {
			return report, safeError(e)
		}
	}
	if version == 20 && len(replacements) == 0 {
		var completed int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM staff_code_normalization_receipt").Scan(&completed); err != nil {
			return report, safeError(err)
		}
		if completed > 0 {
			report.Applied = true
			return report, nil
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, replacement := range replacements {
		source := replacement.source
		raw, ok := decode(source)
		if !ok {
			return report, fault.Unavailable
		}
		normalized, _ := organization.NormalizeStaffCode(raw)
		plain, e := json.Marshal(struct {
			StaffCode string `json:"staff_code"`
		}{normalized})
		if e != nil {
			return report, fault.Unavailable
		}
		payload := organization.WorkforcePayload{ID: value.NewID(), RecordedAt: now}
		binding := source.Envelope.Context
		binding.VersionID = payload.ID
		payload.Envelope, e = cipher.Seal(ctx, binding, plain)
		clear(plain)
		if e != nil {
			return report, fault.Unavailable
		}
		writer := transaction{reader: q, tx: tx, org: source.OrgID}
		if e = writer.insertWorkforcePayload(ctx, payload); e != nil {
			return report, e
		}
		m := replacement.mac
		if _, e = tx.ExecContext(ctx, q.structureSQL("INSERT INTO employee_identifier_owner(org_id,kind,key_id,key_version,digest,employee_id,claimed_at) VALUES(?,'staff_code',?,?,?,?,?) ON CONFLICT(org_id,kind,key_version,digest) DO NOTHING"), source.OrgID, m.KeyID, m.Version, m.Digest, source.EmployeeID, r.BindTime(now)); e != nil {
			return report, safeError(e)
		}
		if _, e = tx.ExecContext(ctx, q.structureSQL("INSERT INTO staff_code_normalization(org_id,identifier_id,employee_id,lookup_key_id,lookup_key_version,lookup_digest,payload_id) VALUES(?,?,?,?,?,?,?)"), source.OrgID, source.ID, source.EmployeeID, m.KeyID, m.Version, m.Digest, payload.ID); e != nil {
			return report, safeError(e)
		}
	}
	request := options.RequestID
	if request == "" {
		request = value.NewID()
	}
	if !value.ValidID(request) {
		return report, fault.Invalid
	}
	projected, err := normalizationSources(ctx, q, "staff_code_identifier")
	if err != nil {
		return report, err
	}
	newOwners, err := normalizationOwners(ctx, q)
	if err != nil {
		return report, err
	}
	resultSnapshot := normalizationSnapshot(20, sources, projected, newOwners)
	if _, err = tx.ExecContext(ctx, q.structureSQL("INSERT INTO staff_code_normalization_receipt(request_id,snapshot,result_snapshot,identifiers,short_numeric,non_numeric,completed_at) VALUES(?,?,?,?,?,?,?)"), request, report.Snapshot, resultSnapshot, report.Identifiers, report.ShortNumeric, report.NonNumeric, r.BindTime(now)); err != nil {
		return report, safeError(err)
	}
	if _, err = tx.ExecContext(ctx, q.structureSQL("UPDATE staff_code_normalization_state SET phase='ready',snapshot=?,request_id=?,completed_at=? WHERE id=1"), report.Snapshot, request, r.BindTime(now)); err != nil {
		return report, safeError(err)
	}
	if err = tx.Commit(); err != nil {
		return report, safeError(err)
	}
	report.Applied = true
	return report, nil
}

func normalizationSources(ctx context.Context, q reader, table string) ([]normalizationSource, error) {
	rows, err := q.db.QueryContext(ctx, "SELECT i.id,i.org_id,i.employee_id,i.lookup_key_id,i.lookup_key_version,i.lookup_digest,i.payload_id,"+q.structureDate("i.valid_from")+","+q.structureDate("i.valid_to")+",p.record_id,p.version_id,p.owner_kind,p.purpose,p.schema_type,p.schema_version,p.format_version,p.algorithm,p.dek_id,p.kek_id,p.kek_version,p.wrapped_dek,p.sealed_bytes FROM "+table+" i JOIN workforce_payload p ON p.org_id=i.org_id AND p.id=i.payload_id WHERE i.kind='staff_code' ORDER BY i.org_id,i.id")
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := []normalizationSource{}
	for rows.Next() {
		var s normalizationSource
		var schemaVersion, formatVersion, kekVersion int64
		e, c := &s.Envelope, &s.Envelope.Context
		if err = rows.Scan(&s.ID, &s.OrgID, &s.EmployeeID, &s.KeyID, &s.KeyVersion, &s.OldDigest, &s.PayloadID, &s.ValidFrom, &s.ValidTo, &c.RecordID, &c.VersionID, &c.ObjectKind, &c.Purpose, &c.SchemaType, &schemaVersion, &formatVersion, &e.Algorithm, &e.DEKID, &e.Key.KEKID, &kekVersion, &e.Key.Data, &e.SealedBytes); err != nil {
			return nil, safeError(err)
		}
		c.OrgID, c.EmployeeID, c.SchemaVersion = s.OrgID, s.EmployeeID, uint32(schemaVersion)
		e.FormatVersion, e.Key.Version = uint16(formatVersion), uint32(kekVersion)
		out = append(out, s)
	}
	return out, safeError(rows.Err())
}
func normalizationOwners(ctx context.Context, q reader) ([]normalizationOwner, error) {
	rows, err := q.db.QueryContext(ctx, "SELECT org_id,employee_id,key_id,key_version,digest FROM employee_identifier_owner WHERE kind='staff_code' ORDER BY org_id,key_id,key_version,digest")
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	out := []normalizationOwner{}
	for rows.Next() {
		var o normalizationOwner
		if err = rows.Scan(&o.OrgID, &o.EmployeeID, &o.KeyID, &o.KeyVersion, &o.Digest); err != nil {
			return nil, safeError(err)
		}
		out = append(out, o)
	}
	return out, safeError(rows.Err())
}

func normalizationSnapshot(version int, sources, effective []normalizationSource, owners []normalizationOwner) string {
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	// All values have bounded concrete fields; encoding cannot fail.
	_ = encoder.Encode(version)
	_ = encoder.Encode(sources)
	_ = encoder.Encode(effective)
	_ = encoder.Encode(owners)
	return hex.EncodeToString(hash.Sum(nil))
}
