package store

type bootstrapAuthority struct {
	capability string
	category   string
	purpose    string
}

var bootstrapAuthorities = [...]bootstrapAuthority{
	{"organization.read", "metadata", "organization_management"},
	{"organization.write", "metadata", "organization_management"},
	{"pii.read", "pii", "organization_management"},
	{"pii.write", "pii", "organization_management"},
	{"audit.read", "audit", "security_administration"},
	{"identity.manage", "audit", "security_administration"},
	{"interview.read", "metadata", "interview_followup"},
	{"interview.write", "metadata", "interview_followup"},
	{"interview_policy.manage", "metadata", "interview_followup"},
	{"assessment.request", "metadata", "interview_followup"},
	{"assessment.read", "metadata", "interview_followup"},
	{"assessment.input.approve", "metadata", "interview_followup"},
	{"assessment.publish", "metadata", "interview_followup"},
	{"note.read", "shared", "interview_followup"},
	{"note.read", "manager_private", "interview_followup"},
	{"note.read", "hr_confidential", "interview_followup"},
	{"note.write", "shared", "interview_followup"},
	{"note.write", "manager_private", "interview_followup"},
	{"note.write", "hr_confidential", "interview_followup"},
	{"note.publish", "shared", "interview_followup"},
	{"note.publish", "manager_private", "interview_followup"},
	{"note.publish", "hr_confidential", "interview_followup"},
	{"action.read", "shared", "interview_followup"},
	{"action.write", "shared", "interview_followup"},
	{"compensation.read", "financial", "compensation_management"},
	{"compensation.propose", "financial", "compensation_management"},
	{"compensation.approve", "financial", "compensation_management"},
	{"bonus.target.manage", "financial", "compensation_management"},
	{"bonus.propose", "financial", "compensation_management"},
	{"bonus.approve", "financial", "compensation_management"},
	{"bonus.payment.record", "financial", "compensation_management"},
	{"compensation.extension.manage", "financial", "compensation_management"},
	{"sensitive.export", "pii", "organization_management"},
	{"sensitive.export", "metadata", "interview_followup"},
	{"sensitive.export", "shared", "interview_followup"},
	{"sensitive.export", "manager_private", "interview_followup"},
	{"sensitive.export", "hr_confidential", "interview_followup"},
	{"sensitive.export", "financial", "compensation_management"},
}
