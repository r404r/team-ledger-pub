package store

import (
	"context"
	"strings"

	"github.com/r404r/team-ledger/internal/organization"
)

// Validate physical tables as well as the migration ledger. SQLite preserves the
// complete DDL; PostgreSQL's catalog exposes structural constraint definitions.
func (r *Repository) checkStructure(ctx context.Context, db queryer) error {
	ddl, _, err := r.migration()
	if err != nil {
		return err
	}
	var count int
	err = db.QueryRowContext(ctx, r.sql("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'", "SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_type='BASE TABLE'")).Scan(&count)
	if err != nil || count != 12 {
		return organization.Unavailable
	}
	for _, statement := range strings.Split(ddl, ";") {
		statement = strings.TrimSpace(statement)
		if !strings.HasPrefix(statement, "CREATE TABLE ") && !strings.HasPrefix(statement, "CREATE INDEX ") {
			continue
		}
		fields := strings.Fields(statement)
		name := strings.Split(fields[2], "(")[0]
		if r.Backend == "sqlite" {
			var actual string
			err = db.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE name=?", name).Scan(&actual)
			if err != nil || compactSQL(actual) != compactSQL(statement) {
				return organization.Unavailable
			}
			continue
		}
		if strings.HasPrefix(statement, "CREATE INDEX ") {
			var actual string
			err = db.QueryRowContext(ctx, "SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname=$1", name).Scan(&actual)
			if err != nil || !strings.Contains(compactSQL(actual), compactSQL(statement[strings.Index(statement, " ON ")+4:strings.Index(statement, "(")])+"usingbtree") {
				return organization.Unavailable
			}
			continue
		}
		// Counts include every declared check, ownership FK, primary and unique key.
		// ALTER's deferred head FK is counted explicitly for PostgreSQL's cycle.
		checks := strings.Count(statement, "CHECK(")
		foreign := strings.Count(statement, "REFERENCES ")
		primary := strings.Count(statement, "PRIMARY KEY")
		unique := strings.Count(statement, "UNIQUE(")
		if name == "employee" {
			foreign++
		}
		rows, e := db.QueryContext(ctx, "SELECT contype::text,count(*) FROM pg_constraint WHERE conrelid=to_regclass($1) GROUP BY contype", name)
		if e != nil {
			return organization.Unavailable
		}
		found := map[string]int{}
		for rows.Next() {
			var kind string
			var n int
			if e = rows.Scan(&kind, &n); e != nil {
				rows.Close()
				return organization.Unavailable
			}
			found[kind] = n
		}
		e = rows.Err()
		rows.Close()
		if e != nil || found["c"] != checks || found["f"] != foreign || found["p"] != primary || found["u"] != unique {
			return organization.Unavailable
		}
		var invalid int
		e = db.QueryRowContext(ctx, "SELECT count(*) FROM pg_constraint WHERE conrelid=to_regclass($1) AND NOT convalidated", name).Scan(&invalid)
		if e != nil || invalid != 0 {
			return organization.Unavailable
		}
	}
	if r.Backend == "postgres" {
		for _, binding := range postgresOwnerConstraints {
			var present bool
			err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass($1) AND contype='f' AND regexp_replace(pg_get_constraintdef(oid),'[[:space:]]','','g')=$2)", binding[0], binding[1]).Scan(&present)
			if err != nil || !present {
				return organization.Unavailable
			}
		}
	}
	return nil
}
func compactSQL(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), "")) }

var postgresOwnerConstraints = [][2]string{
	{"employee", "FOREIGNKEY(org_id,id,profile_head_id)REFERENCESemployee_profile_version(org_id,employee_id,id)DEFERRABLEINITIALLYDEFERRED"},
	{"encrypted_payload", "FOREIGNKEY(org_id,employee_id)REFERENCESemployee(org_id,id)"},
	{"employee_profile_version", "FOREIGNKEY(org_id,employee_id)REFERENCESemployee(org_id,id)"},
	{"employee_profile_version", "FOREIGNKEY(org_id,employee_id,payload_id)REFERENCESencrypted_payload(org_id,employee_id,id)"},
	{"employee_profile_version", "FOREIGNKEY(org_id,employee_id,supersedes_id)REFERENCESemployee_profile_version(org_id,employee_id,id)"},
	{"capability_assignment", "FOREIGNKEY(org_id,subject_id)REFERENCESsubject(org_id,id)"},
	{"capability_assignment", "FOREIGNKEY(org_id,employee_id)REFERENCESemployee(org_id,id)"},
	{"access_grant", "FOREIGNKEY(org_id,subject_id)REFERENCESsubject(org_id,id)"},
	{"access_grant", "FOREIGNKEY(org_id,employee_id)REFERENCESemployee(org_id,id)"},
	{"command_receipt", "FOREIGNKEY(org_id,subject_id)REFERENCESsubject(org_id,id)"},
	{"command_receipt", "FOREIGNKEY(org_id,result_id)REFERENCESemployee(org_id,id)"},
	{"audit_event", "FOREIGNKEY(org_id,subject_id)REFERENCESsubject(org_id,id)"},
	{"audit_event", "FOREIGNKEY(org_id,employee_id)REFERENCESemployee(org_id,id)"},
}
