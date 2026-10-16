package organization

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/r404r/team-ledger/internal/authz"
	"github.com/r404r/team-ledger/internal/fault"
)

func (s *Service) structureAuthority(ctx context.Context, reader Reader, request Request, org, operation string, write bool) (authz.Snapshot, error) {
	if len(request.TokenHash) != 32 || reader == nil {
		return authz.Snapshot{}, fault.Unauthenticated
	}
	snapshot, err := reader.Security(ctx, request.TokenHash, "", "")
	if err != nil {
		return snapshot, err
	}
	now := s.clock()
	if !snapshot.Valid(now) {
		return snapshot, fault.Unauthenticated
	}
	if snapshot.OrgID != org {
		return snapshot, fault.NotFound
	}
	if write {
		if !snapshot.Allows("organization.write", "metadata", "", request.Purpose, now) {
			return snapshot, fault.Forbidden
		}
	} else if !snapshot.Allows("organization.read", "metadata", "", request.Purpose, now) &&
		!(operation == "OP-ORG-04" && len(snapshot.StaffDefaultScope(now)) > 0) {
		return snapshot, fault.NotFound
	}
	return snapshot, nil
}

func codeValid(code string) bool {
	if len(code) == 0 || len(code) > 64 {
		return false
	}
	for _, char := range code {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func textValid(text *string, max int, nonempty bool) bool {
	return text == nil || utf8.ValidString(*text) && len(*text) <= max && (!nonempty || strings.TrimSpace(*text) != "")
}
