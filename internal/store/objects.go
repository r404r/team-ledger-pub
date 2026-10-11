package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
)

func (r *Repository) Object(ctx context.Context, org string, ref authz.ObjectReference) (authz.ObjectInfo, error) {
	return r.read().Object(ctx, org, ref)
}

func (r reader) Object(ctx context.Context, org string, ref authz.ObjectReference) (authz.ObjectInfo, error) {
	if !authz.ValidObjectReference(ref) {
		return authz.ObjectInfo{}, fault.NotFound
	}
	var query string
	switch ref.Kind {
	case "interview":
		query = "SELECT employee_id,'metadata',revision,id,'','' FROM interview"
	case "note_head":
		query = "SELECT employee_id,category,revision,interview_id,id,'' FROM note_head"
	case "note_version":
		query = "SELECT employee_id,category,version_no,interview_id,head_id,status FROM note_version"
	case "action_item":
		query = "SELECT employee_id,'shared',revision,interview_id,'','' FROM action_item"
	}
	query += r.sql(" WHERE org_id=? AND id=?", " WHERE org_id=$1 AND id=$2")
	info := authz.ObjectInfo{Reference: ref}
	var revision int64
	var interview, head, status string
	err := r.db.QueryRowContext(ctx, query, org, ref.ID).Scan(&info.EmployeeID, &info.Category, &revision, &interview, &head, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return authz.ObjectInfo{}, fault.NotFound
	}
	if err != nil {
		return authz.ObjectInfo{}, safeError(err)
	}
	if revision < 1 {
		return authz.ObjectInfo{}, fault.Unavailable
	}
	info.Revision, info.Published = strconv.FormatInt(revision, 10), status == "published"
	info.Lineage = []authz.ObjectReference{{Kind: "interview", ID: interview}}
	if head != "" {
		info.Lineage = append(info.Lineage, authz.ObjectReference{Kind: "note_head", ID: head})
	}
	if ref.Kind == "note_version" || ref.Kind == "action_item" {
		info.Lineage = append(info.Lineage, ref)
	}
	if !authz.CanonicalLineage(info.Lineage...) {
		return authz.ObjectInfo{}, fault.Unavailable
	}
	return info, nil
}

type sourceApprovalFacts struct {
	refs      []authz.ObjectReference
	employees map[string]string
}

// Approval IDs come from immutable typed source facts, not note text or a head
// pointer. Batch loading keeps the bounded list and session snapshot finite.
func (r reader) sourceApprovals(ctx context.Context, org string, ids []string) (map[string]sourceApprovalFacts, error) {
	var result map[string]sourceApprovalFacts
	if len(ids) == 0 {
		return result, nil
	}
	args := make([]any, 1, len(ids)+1)
	args[0] = org
	var query strings.Builder
	query.WriteString("SELECT grant_id,source_note_version_id,employee_id FROM access_grant_source_approval WHERE org_id=" + r.sql("?", "$1") + " AND grant_id IN (")
	for i, id := range ids {
		if i != 0 {
			query.WriteByte(',')
		}
		args = append(args, id)
		query.WriteString(r.sql("?", "$"+strconv.Itoa(i+2)))
	}
	query.WriteString(" ) ORDER BY grant_id,source_note_version_id")
	rows, err := r.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, safeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var grant, source, employee string
		if err := rows.Scan(&grant, &source, &employee); err != nil {
			return nil, safeError(err)
		}
		if result == nil {
			result = make(map[string]sourceApprovalFacts)
		}
		facts := result[grant]
		if facts.employees == nil {
			facts.employees = make(map[string]string)
		}
		facts.refs = append(facts.refs, authz.ObjectReference{Kind: "note_version", ID: source})
		facts.employees[source] = employee
		result[grant] = facts
		if len(facts.refs) > 10 {
			return nil, fault.Unavailable
		}
	}
	return result, safeError(rows.Err())
}

func (r reader) grantApprovals(ctx context.Context, grant authz.GrantDTO, err error) (authz.GrantDTO, error) {
	if err != nil {
		return authz.GrantDTO{}, err
	}
	if grant.Capability != "note.publish" && grant.Capability != "action.write" {
		grant.ApprovedSourceRefs = []authz.ObjectReference{}
		return grant, nil
	}
	refs, err := r.sourceApprovals(ctx, grant.OrgID, []string{grant.ID})
	if err != nil {
		return authz.GrantDTO{}, err
	}
	grant.ApprovedSourceRefs = refs[grant.ID].refs
	if grant.ApprovedSourceRefs == nil {
		grant.ApprovedSourceRefs = []authz.ObjectReference{}
	}
	return grant, nil
}
