package store

import (
	"context"
	"reflect"
	"strings"

	"github.com/r404r/team-ledger/internal/fault"
)

// A migration statement occupies one line, including a complete trigger body.
// This keeps semicolons inside SQLite triggers and PostgreSQL function bodies intact.
func migrationStatements(ddl string) []string {
	var statements []string
	for _, line := range strings.Split(ddl, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "--") {
			statements = append(statements, line)
		}
	}
	return statements
}

func (r *Repository) checkStructure(ctx context.Context, db queryer, version int) error {
	if r.Backend == "postgres" {
		return r.checkPostgresStructure(ctx, db, version)
	}
	expected := map[string]string{}
	for v := 1; v <= version; v++ {
		ddl, _, err := r.migration(v)
		if err != nil {
			return err
		}
		for _, statement := range migrationStatements(ddl) {
			if !strings.HasPrefix(statement, "CREATE TABLE ") && !strings.HasPrefix(statement, "CREATE INDEX ") && !strings.HasPrefix(statement, "CREATE TRIGGER ") {
				continue
			}
			name := strings.Split(strings.Fields(statement)[2], "(")[0]
			if strings.HasSuffix(name, "_v2") {
				finalName := strings.TrimSuffix(name, "_v2")
				statement = strings.Replace(statement, "CREATE TABLE "+name+"(", "CREATE TABLE "+finalName+"(", 1)
				name = finalName
			}
			expected[name] = compactSQL(statement)
		}
	}
	rows, err := db.QueryContext(ctx, "SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL ORDER BY name")
	if err != nil {
		return fault.Unavailable
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		var name, ddl string
		if err = rows.Scan(&name, &ddl); err != nil || expected[name] == "" || expected[name] != compactSQL(ddl) {
			return fault.Unavailable
		}
		found++
	}
	if rows.Err() != nil || found != len(expected) {
		return fault.Unavailable
	}
	return nil
}

// Normalize layout and quoted identifiers, never string literal contents. In
// particular replacing a finite enum with differently-cased values is drift.
func compactSQL(s string) string {
	var out strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' {
			out.WriteByte(c)
			if quoted && i+1 < len(s) && s[i+1] == '\'' {
				out.WriteByte(s[i+1])
				i++
				continue
			}
			quoted = !quoted
			continue
		}
		if !quoted {
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == ';' {
				continue
			}
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}

// PostgreSQL deparses checks (IN becomes ANY, implicit casts are exposed). Let
// the same server canonicalize the supported checked-in definitions in TEMP
// tables rather than guessing its expression formatting or checking counts.
// The savepoint removes every reference object and restores search_path; the
// application namespace is only read, never repaired or automatically migrated.
func (r *Repository) checkPostgresStructure(ctx context.Context, db queryer, version int) error {
	var namespace string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&namespace); err != nil || namespace == "" {
		return fault.Unavailable
	}
	actual, err := postgresCatalog(ctx, db, namespace)
	if err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, "SAVEPOINT store_schema_reference"); err != nil {
		return safeError(err)
	}
	// On any failure the caller rolls back its transaction. Successful cleanup
	// explicitly restores all settings even when this check is inside Migrate.
	if _, err = db.ExecContext(ctx, "SET LOCAL search_path = pg_temp, pg_catalog"); err != nil {
		return safeError(err)
	}
	for v := 1; v <= version; v++ {
		ddl, _, e := r.migration(v)
		if e != nil {
			return e
		}
		for _, statement := range migrationStatements(ddl) {
			statement = strings.Replace(statement, "CREATE TABLE ", "CREATE TEMP TABLE ", 1)
			statement = strings.Replace(statement, "CREATE FUNCTION delegation_authority_immutable", "CREATE FUNCTION pg_temp.delegation_authority_immutable", 1)
			statement = strings.Replace(statement, "EXECUTE FUNCTION delegation_authority_immutable", "EXECUTE FUNCTION pg_temp.delegation_authority_immutable", 1)
			if _, e = db.ExecContext(ctx, statement); e != nil {
				return safeError(e)
			}
		}
	}
	var referenceNamespace string
	if err = db.QueryRowContext(ctx, "SELECT nspname FROM pg_namespace WHERE oid=pg_my_temp_schema()").Scan(&referenceNamespace); err != nil {
		return safeError(err)
	}
	expected, err := postgresCatalog(ctx, db, referenceNamespace)
	if err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, "ROLLBACK TO SAVEPOINT store_schema_reference"); err != nil {
		return safeError(err)
	}
	if _, err = db.ExecContext(ctx, "RELEASE SAVEPOINT store_schema_reference"); err != nil {
		return safeError(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		return fault.Unavailable
	}
	return nil
}

// Include complete column order/type/default/nullability, table properties,
// canonical constraint definitions/validation, every index definition, triggers
// and immutable-authority function body. Only the known owning namespace is
// normalized: an otherwise identical FK pointing to another namespace is drift.
func postgresCatalog(ctx context.Context, db queryer, namespace string) (map[string]string, error) {
	// UNION must preserve text: PostgreSQL's name type truncates composite
	// identities to 63 bytes, merging distinct ownership/check constraints.
	const query = `
SELECT 'table',c.relname::text,jsonb_build_array(c.relkind,CASE WHEN n.oid=pg_my_temp_schema() THEN 'p' ELSE c.relpersistence END,c.relam,c.reloptions,c.relrowsecurity,c.relforcerowsecurity,c.relispartition)::text
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname=$1 AND c.relkind IN('r','p','v','m','f','S')
UNION ALL
SELECT 'column',c.relname||'.'||a.attnum::text,jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attcollation::regcollation::text,a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid))::text
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
WHERE n.nspname=$1 AND a.attnum>0 AND NOT a.attisdropped
UNION ALL
SELECT 'constraint',c.relname||'.'||k.conname,jsonb_build_array(k.contype,k.convalidated,k.condeferrable,k.condeferred,pg_get_constraintdef(k.oid,true))::text
FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
UNION ALL
SELECT 'index',i.relname::text,jsonb_build_array(x.indisvalid,x.indisready,x.indisunique,x.indisprimary,pg_get_indexdef(i.oid))::text
FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_namespace n ON n.oid=i.relnamespace WHERE n.nspname=$1
UNION ALL
SELECT 'trigger',c.relname||'.'||t.tgname,jsonb_build_array(t.tgenabled,pg_get_triggerdef(t.oid,true))::text
FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND NOT t.tgisinternal
UNION ALL
SELECT 'function',p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',pg_get_functiondef(p.oid)
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1`
	rows, err := db.QueryContext(ctx, query, namespace)
	if err != nil {
		return nil, fault.Unavailable
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var kind, name, definition string
		if err = rows.Scan(&kind, &name, &definition); err != nil {
			return nil, fault.Unavailable
		}
		definition = normalizeCatalogNamespace(definition, namespace)
		// TEMP schemas may be printed by their session alias in function DDL.
		if strings.HasPrefix(namespace, "pg_temp_") {
			definition = normalizeCatalogNamespace(definition, "pg_temp")
		}
		key := kind + ":" + name
		if _, duplicate := result[key]; duplicate {
			return nil, fault.Unavailable
		}
		result[key] = definition
	}
	if rows.Err() != nil {
		return nil, fault.Unavailable
	}
	return result, nil
}

// Namespace normalization must not erase a prefix inside an enum/string
// literal: doing so could make a replaced CHECK look like the supported one.
func normalizeCatalogNamespace(definition, namespace string) string {
	prefixes := []string{namespace + ".", `"` + namespace + `".`, `\"` + namespace + `\".`}
	var out strings.Builder
	quoted := false
	for i := 0; i < len(definition); {
		if definition[i] == '\'' {
			out.WriteByte(definition[i])
			i++
			if quoted && i < len(definition) && definition[i] == '\'' {
				out.WriteByte(definition[i])
				i++
				continue
			}
			quoted = !quoted
			continue
		}
		if !quoted {
			matched := false
			for _, prefix := range prefixes {
				if strings.HasPrefix(definition[i:], prefix) {
					i += len(prefix)
					matched = true
					break
				}
			}
			if matched {
				continue
			}
		}
		out.WriteByte(definition[i])
		i++
	}
	return out.String()
}
