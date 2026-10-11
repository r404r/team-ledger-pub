package fault

type Fault struct {
	Status       int
	Code, Reason string
}

func (e *Fault) Error() string { return e.Code }

var (
	Invalid          = &Fault{422, "INVALID_INPUT", "INVALID_INPUT"}
	Unauthenticated  = &Fault{401, "UNAUTHENTICATED", "SESSION_INVALID"}
	NotFound         = &Fault{404, "NOT_FOUND", "NOT_FOUND"}
	Forbidden        = &Fault{403, "FORBIDDEN", "ACTION_FORBIDDEN"}
	Conflict         = &Fault{409, "CONFLICT", "REVISION_STALE"}
	Mismatch         = &Fault{409, "CONFLICT", "IDEMPOTENCY_MISMATCH"}
	Unavailable      = &Fault{503, "UNAVAILABLE", "DEPENDENCY_UNAVAILABLE"}
	AuditUnavailable = &Fault{503, "UNAVAILABLE", "AUDIT_UNAVAILABLE"}
	Busy             = &Fault{503, "UNAVAILABLE", "WRITE_BUSY"}
)
