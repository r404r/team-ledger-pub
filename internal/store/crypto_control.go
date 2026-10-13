package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"fmt"
	"github.com/r404r/team-ledger/internal/fault"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type CryptoControl struct {
	Phase          string
	State          sensitive.ReadyState
	Domain         sensitive.KeyDomain
	ManifestDigest []byte
	Target         sensitive.KeyReference
}

func canonicalActive(state sensitive.ReadyState) ([]byte, error) {
	if state.MaterialGeneration == 0 || len(state.Digest) != 64 || len(state.Active) != 14 || len(state.ActiveKeys) != 14 {
		return nil, fault.Invalid
	}
	if _, err := hex.DecodeString(state.Digest); err != nil {
		return nil, fault.Invalid
	}
	for _, domain := range []sensitive.KeyDomain{
		sensitive.DomainPIIPayload, sensitive.DomainInterviewPayload, sensitive.DomainAssessmentPayload,
		sensitive.DomainFinancialPayload, sensitive.DomainIdentityTransaction, sensitive.DomainIdentityMapping,
		sensitive.DomainBackupArchive, sensitive.DomainStaffCodeLookup, sensitive.DomainBonusPaymentLookup,
		sensitive.DomainIdentitySubjectLookup, sensitive.DomainCommandReceipt, sensitive.DomainAssessmentGeneration,
		sensitive.DomainCSRFToken, sensitive.DomainCursorToken,
	} {
		reference := state.ActiveKeys[domain]
		if state.Active[domain] == 0 || reference.Version != state.Active[domain] || reference.KeyID == "" {
			return nil, fault.Invalid
		}
	}
	raw, err := json.Marshal(state.ActiveKeys)
	if err != nil {
		return nil, fault.Invalid
	}
	return raw, nil
}

func scanCryptoControl(row *sql.Row) (CryptoControl, error) {
	var out CryptoControl
	var generation int64
	var active []byte
	var domain, targetID sql.NullString
	var manifest []byte
	var targetVersion sql.NullInt64
	err := row.Scan(&out.Phase, &generation, &out.State.Digest, &active, &domain, &manifest, &targetID, &targetVersion)
	if err != nil {
		return out, err
	}
	if generation <= 0 || json.Unmarshal(active, &out.State.ActiveKeys) != nil {
		return CryptoControl{}, fault.Unavailable
	}
	out.State.MaterialGeneration = uint64(generation)
	out.State.Active = make(map[sensitive.KeyDomain]uint32, len(out.State.ActiveKeys))
	for keyDomain, reference := range out.State.ActiveKeys {
		out.State.Active[keyDomain] = reference.Version
	}
	if domain.Valid {
		out.Domain = sensitive.KeyDomain(domain.String)
	}
	out.ManifestDigest = bytes.Clone(manifest)
	if targetID.Valid && targetVersion.Valid && targetVersion.Int64 > 0 {
		out.Target = sensitive.KeyReference{KeyID: targetID.String, Version: uint32(targetVersion.Int64)}
	}
	if _, err = canonicalActive(out.State); err != nil {
		return CryptoControl{}, fault.Unavailable
	}
	return out, nil
}
func (r *Repository) CryptoControl(ctx context.Context) (CryptoControl, error) {
	row := r.DB.QueryRowContext(ctx, "SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1")
	out, err := scanCryptoControl(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CryptoControl{}, fault.NotFound
	}
	if err != nil {
		return CryptoControl{}, safeError(err)
	}
	return out, nil
}

func sameCryptoState(control CryptoControl, state sensitive.ReadyState) bool {
	active, err := canonicalActive(state)
	current, currentErr := canonicalActive(control.State)
	return err == nil && currentErr == nil && control.State.MaterialGeneration == state.MaterialGeneration && control.State.Digest == state.Digest && bytes.Equal(current, active)
}

// VerifyCryptoState rejects a keyring that is unacknowledged or differs from
// the database's stable material generation.
func (r *Repository) VerifyCryptoState(ctx context.Context, state sensitive.ReadyState) error {
	if !state.WriteEnabled || len(state.Staged) != 0 {
		return fault.Unavailable
	}
	control, err := r.CryptoControl(ctx)
	if err != nil || control.Phase != "stable" || !sameCryptoState(control, state) {
		return fault.Unavailable
	}
	return nil
}

// VerifyOrInitializeCryptoState binds a clean v12 database to one stable keyring.
// A restored database already carries this row and cannot silently bind to other key material.
func (r *Repository) VerifyOrInitializeCryptoState(ctx context.Context, state sensitive.ReadyState, now time.Time) error {
	active, err := canonicalActive(state)
	if err != nil || !state.WriteEnabled || len(state.Staged) != 0 {
		return fault.Unavailable
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	control, err := scanCryptoControl(tx.QueryRowContext(ctx, r.read().sql("SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1", "SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1 FOR UPDATE")))
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, r.read().sql("INSERT INTO crypto_control(id,phase,material_generation,keyring_digest,active_json,updated_at) VALUES(1,'stable',?,?,?,?)", "INSERT INTO crypto_control(id,phase,material_generation,keyring_digest,active_json,updated_at) VALUES(1,'stable',$1,$2,$3,$4)"), int64(state.MaterialGeneration), state.Digest, string(active), now.UTC().UnixMicro())
		if err != nil {
			return safeError(err)
		}
		return safeError(tx.Commit())
	}
	if err != nil || control.Phase != "stable" || !sameCryptoState(control, state) {
		return fault.Unavailable
	}
	return safeError(tx.Commit())
}

func validCryptoTransition(state sensitive.ReadyState, domain sensitive.KeyDomain, manifest []byte, target sensitive.KeyReference) ([]byte, error) {
	active, err := canonicalActive(state)
	staged, ok := state.Staged[domain]
	if err != nil || len(manifest) != 32 || len(state.Staged) != 1 || !ok || staged != target || target.KeyID == "" || target.Version == 0 || state.WriteEnabled {
		return nil, fault.Invalid
	}
	return active, nil
}

func (r *Repository) BeginCryptoStage(ctx context.Context, state sensitive.ReadyState, domain sensitive.KeyDomain, manifest []byte, now time.Time) error {
	target := state.Staged[domain]
	active, err := validCryptoTransition(state, domain, manifest, target)
	if err != nil {
		return err
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	control, err := scanCryptoControl(tx.QueryRowContext(ctx, r.read().sql("SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1", "SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1 FOR UPDATE")))
	if err != nil {
		return safeError(err)
	}
	if control.Phase == "staged" && sameCryptoState(control, state) && control.Domain == domain && bytes.Equal(control.ManifestDigest, manifest) && control.Target == target {
		return safeError(tx.Commit())
	}
	oldActive, oldErr := canonicalActive(control.State)
	if control.Phase != "stable" || oldErr != nil || !bytes.Equal(oldActive, active) || control.State.MaterialGeneration >= state.MaterialGeneration {
		return fault.Unavailable
	}
	statement := r.read().sql("UPDATE crypto_control SET phase='staged',material_generation=?,keyring_digest=?,active_json=?,domain=?,manifest_digest=?,target_key_id=?,target_key_version=?,updated_at=? WHERE id=1 AND phase='stable'", "UPDATE crypto_control SET phase='staged',material_generation=$1,keyring_digest=$2,active_json=$3,domain=$4,manifest_digest=$5,target_key_id=$6,target_key_version=$7,updated_at=$8 WHERE id=1 AND phase='stable'")
	result, err := tx.ExecContext(ctx, statement, int64(state.MaterialGeneration), state.Digest, string(active), string(domain), manifest, target.KeyID, int64(target.Version), now.UTC().UnixMicro())
	if err != nil {
		return safeError(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fault.Unavailable
	}
	insert := r.read().sql("INSERT INTO crypto_material_receipt(kind,manifest_digest,domain,target_key_id,target_key_version,material_generation,keyring_digest,active_json,recorded_at) VALUES('A1',?,?,?,?,?,?,?,?)", "INSERT INTO crypto_material_receipt(kind,manifest_digest,domain,target_key_id,target_key_version,material_generation,keyring_digest,active_json,recorded_at) VALUES('A1',$1,$2,$3,$4,$5,$6,$7,$8)")
	if _, err = tx.ExecContext(ctx, insert, manifest, string(domain), target.KeyID, int64(target.Version), int64(state.MaterialGeneration), state.Digest, string(active), now.UTC().UnixMicro()); err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}

func (r *Repository) RecordCryptoActivation(ctx context.Context, state sensitive.ReadyState, domain sensitive.KeyDomain, manifest []byte, now time.Time) error {
	target := state.Staged[domain]
	active, err := validCryptoTransition(state, domain, manifest, target)
	if err != nil || state.Active[domain] != target.Version {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	control, err := scanCryptoControl(tx.QueryRowContext(ctx, r.read().sql("SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1", "SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1 FOR UPDATE")))
	if err != nil || control.Domain != domain || !bytes.Equal(control.ManifestDigest, manifest) || control.Target != target || control.Phase != "staged" && control.Phase != "activated" {
		return fault.Unavailable
	}
	if control.Phase == "activated" && sameCryptoState(control, state) {
		return safeError(tx.Commit())
	}
	if control.State.MaterialGeneration >= state.MaterialGeneration {
		return fault.Unavailable
	}
	update := r.read().sql("UPDATE crypto_control SET phase='activated',material_generation=?,keyring_digest=?,active_json=?,updated_at=? WHERE id=1 AND phase='staged'", "UPDATE crypto_control SET phase='activated',material_generation=$1,keyring_digest=$2,active_json=$3,updated_at=$4 WHERE id=1 AND phase='staged'")
	result, err := tx.ExecContext(ctx, update, int64(state.MaterialGeneration), state.Digest, string(active), now.UTC().UnixMicro())
	if err != nil {
		return safeError(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fault.Unavailable
	}
	insert := r.read().sql("INSERT INTO crypto_material_receipt(kind,manifest_digest,domain,target_key_id,target_key_version,material_generation,keyring_digest,active_json,recorded_at) VALUES('A2',?,?,?,?,?,?,?,?)", "INSERT INTO crypto_material_receipt(kind,manifest_digest,domain,target_key_id,target_key_version,material_generation,keyring_digest,active_json,recorded_at) VALUES('A2',$1,$2,$3,$4,$5,$6,$7,$8)")
	if _, err = tx.ExecContext(ctx, insert, manifest, string(domain), target.KeyID, int64(target.Version), int64(state.MaterialGeneration), state.Digest, string(active), now.UTC().UnixMicro()); err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}

func (r *Repository) CompleteCryptoActivation(ctx context.Context, state sensitive.ReadyState, domain sensitive.KeyDomain, manifest []byte, now time.Time) error {
	active, err := canonicalActive(state)
	if err != nil || !state.WriteEnabled || len(state.Staged) != 0 || len(manifest) != 32 {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	control, err := scanCryptoControl(tx.QueryRowContext(ctx, r.read().sql("SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1", "SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1 FOR UPDATE")))
	if err != nil || control.Phase != "activated" || control.Domain != domain || !bytes.Equal(control.ManifestDigest, manifest) || state.Active[domain] != control.Target.Version || control.State.MaterialGeneration >= state.MaterialGeneration {
		return fault.Unavailable
	}
	update := r.read().sql("UPDATE crypto_control SET phase='stable',material_generation=?,keyring_digest=?,active_json=?,domain=NULL,manifest_digest=NULL,target_key_id=NULL,target_key_version=NULL,updated_at=? WHERE id=1 AND phase='activated'", "UPDATE crypto_control SET phase='stable',material_generation=$1,keyring_digest=$2,active_json=$3,domain=NULL,manifest_digest=NULL,target_key_id=NULL,target_key_version=NULL,updated_at=$4 WHERE id=1 AND phase='activated'")
	result, err := tx.ExecContext(ctx, update, int64(state.MaterialGeneration), state.Digest, string(active), now.UTC().UnixMicro())
	if err != nil {
		return safeError(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fault.Unavailable
	}
	return safeError(tx.Commit())
}

func retirementInventory(domain sensitive.KeyDomain) (string, []string, bool) {
	switch domain {
	case sensitive.DomainPIIPayload:
		return "pii", rewrapTables["pii"], true
	case sensitive.DomainInterviewPayload:
		return "interview", rewrapTables["interview"], true
	case sensitive.DomainAssessmentPayload:
		return "assessment", rewrapTables["assessment"], true
	case sensitive.DomainFinancialPayload:
		return "financial", rewrapTables["financial"], true
	default:
		return "", nil, false
	}
}

// PrepareCryptoRetirement proves that no database wrapper still references the
// A1 source key, then fences application traffic before keyd destroys it.
func (r *Repository) PrepareCryptoRetirement(ctx context.Context, domain sensitive.KeyDomain, approvalManifest []byte, now time.Time) (sensitive.KeyReference, []byte, bool, error) {
	storeDomain, tables, ok := retirementInventory(domain)
	if !ok || len(approvalManifest) != 32 {
		return sensitive.KeyReference{}, nil, false, fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return sensitive.KeyReference{}, nil, false, safeError(err)
	}
	defer tx.Rollback()
	control, err := scanCryptoControl(tx.QueryRowContext(ctx, r.read().sql("SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1", "SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1 FOR UPDATE")))
	if err != nil {
		return sensitive.KeyReference{}, nil, false, safeError(err)
	}
	if control.Phase == "retiring" {
		if control.Domain != domain || len(control.ManifestDigest) != 32 {
			return sensitive.KeyReference{}, nil, false, fault.Unavailable
		}
		return control.Target, bytes.Clone(control.ManifestDigest), true, safeError(tx.Commit())
	}
	if control.Phase != "stable" {
		return sensitive.KeyReference{}, nil, false, fault.Unavailable
	}
	var activeJSON []byte
	query := r.read().sql("SELECT active_json FROM crypto_material_receipt WHERE kind='A1' AND manifest_digest=?", "SELECT active_json FROM crypto_material_receipt WHERE kind='A1' AND manifest_digest=$1")
	if err = tx.QueryRowContext(ctx, query, approvalManifest).Scan(&activeJSON); err != nil {
		return sensitive.KeyReference{}, nil, false, safeError(err)
	}
	var oldKeys map[sensitive.KeyDomain]sensitive.KeyReference
	if json.Unmarshal(activeJSON, &oldKeys) != nil {
		return sensitive.KeyReference{}, nil, false, fault.Unavailable
	}
	old := oldKeys[domain]
	if old.KeyID == "" || old.Version == 0 || old == control.State.ActiveKeys[domain] {
		return sensitive.KeyReference{}, nil, false, fault.Unavailable
	}
	var retired int
	retiredQuery := r.read().sql("SELECT count(*) FROM crypto_material_receipt WHERE kind='R' AND domain=? AND target_key_id=? AND target_key_version=?", "SELECT count(*) FROM crypto_material_receipt WHERE kind='R' AND domain=$1 AND target_key_id=$2 AND target_key_version=$3")
	if err = tx.QueryRowContext(ctx, retiredQuery, string(domain), old.KeyID, int64(old.Version)).Scan(&retired); err != nil {
		return sensitive.KeyReference{}, nil, false, safeError(err)
	}
	if retired != 0 {
		return old, nil, false, safeError(tx.Commit())
	}
	for _, table := range tables {
		statement := fmt.Sprintf("SELECT count(*) FROM %s WHERE kek_id=? AND kek_version=?", table)
		if r.Backend == "postgres" {
			statement = fmt.Sprintf("SELECT count(*) FROM %s WHERE kek_id=$1 AND kek_version=$2", table)
		}
		var references int64
		if err = tx.QueryRowContext(ctx, statement, old.KeyID, int64(old.Version)).Scan(&references); err != nil {
			return sensitive.KeyReference{}, nil, false, safeError(err)
		}
		if references != 0 {
			return sensitive.KeyReference{}, nil, false, fault.Unavailable
		}
	}
	proof := sha256.Sum256([]byte(fmt.Sprintf("TEAMLEDGER-RETIRE\x00%s\x00%s\x00%d\x00%s", storeDomain, old.KeyID, old.Version, hex.EncodeToString(approvalManifest))))
	update := r.read().sql("UPDATE crypto_control SET phase='retiring',domain=?,manifest_digest=?,target_key_id=?,target_key_version=?,updated_at=? WHERE id=1 AND phase='stable'", "UPDATE crypto_control SET phase='retiring',domain=$1,manifest_digest=$2,target_key_id=$3,target_key_version=$4,updated_at=$5 WHERE id=1 AND phase='stable'")
	result, err := tx.ExecContext(ctx, update, string(domain), proof[:], old.KeyID, int64(old.Version), now.UTC().UnixMicro())
	if err != nil {
		return sensitive.KeyReference{}, nil, false, safeError(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return sensitive.KeyReference{}, nil, false, fault.Unavailable
	}
	if err = tx.Commit(); err != nil {
		return sensitive.KeyReference{}, nil, false, safeError(err)
	}
	return old, bytes.Clone(proof[:]), true, nil
}

func (r *Repository) CompleteCryptoRetirement(ctx context.Context, state sensitive.ReadyState, domain sensitive.KeyDomain, old sensitive.KeyReference, proof []byte, now time.Time) error {
	active, err := canonicalActive(state)
	if err != nil || !state.WriteEnabled || len(state.Staged) != 0 || len(proof) != 32 || state.ActiveKeys[domain] == old {
		return fault.Invalid
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return safeError(err)
	}
	defer tx.Rollback()
	control, err := scanCryptoControl(tx.QueryRowContext(ctx, r.read().sql("SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1", "SELECT phase,material_generation,keyring_digest,active_json,domain,manifest_digest,target_key_id,target_key_version FROM crypto_control WHERE id=1 FOR UPDATE")))
	if err != nil || control.Phase != "retiring" || control.Domain != domain || control.Target != old || !bytes.Equal(control.ManifestDigest, proof) || control.State.MaterialGeneration >= state.MaterialGeneration {
		return fault.Unavailable
	}
	beforeActive, beforeErr := canonicalActive(control.State)
	if beforeErr != nil || !bytes.Equal(beforeActive, active) {
		return fault.Unavailable
	}
	update := r.read().sql("UPDATE crypto_control SET phase='stable',material_generation=?,keyring_digest=?,active_json=?,domain=NULL,manifest_digest=NULL,target_key_id=NULL,target_key_version=NULL,updated_at=? WHERE id=1 AND phase='retiring'", "UPDATE crypto_control SET phase='stable',material_generation=$1,keyring_digest=$2,active_json=$3,domain=NULL,manifest_digest=NULL,target_key_id=NULL,target_key_version=NULL,updated_at=$4 WHERE id=1 AND phase='retiring'")
	result, err := tx.ExecContext(ctx, update, int64(state.MaterialGeneration), state.Digest, string(active), now.UTC().UnixMicro())
	if err != nil {
		return safeError(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fault.Unavailable
	}
	insert := r.read().sql("INSERT INTO crypto_material_receipt(kind,manifest_digest,domain,target_key_id,target_key_version,material_generation,keyring_digest,active_json,recorded_at) VALUES('R',?,?,?,?,?,?,?,?)", "INSERT INTO crypto_material_receipt(kind,manifest_digest,domain,target_key_id,target_key_version,material_generation,keyring_digest,active_json,recorded_at) VALUES('R',$1,$2,$3,$4,$5,$6,$7,$8)")
	if _, err = tx.ExecContext(ctx, insert, proof, string(domain), old.KeyID, int64(old.Version), int64(state.MaterialGeneration), state.Digest, string(active), now.UTC().UnixMicro()); err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit())
}
