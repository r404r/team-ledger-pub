package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/audit"
	"github.com/r404r/team-ledger/internal/organization"
	"github.com/r404r/team-ledger/internal/testsupport"
	"github.com/r404r/team-ledger/internal/value"
)

func TestAuditOutboxClaimsRetriesAndPersistsIndependentReceipt(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			fixture := testsupport.NewHarness(t, backend)
			ctx := context.Background()
			now := fixture.Now.Add(time.Minute)
			if err := fixture.Repo.AuditDenied(ctx, organization.Audit{ID: value.NewID(), OrgID: fixture.OrgID, SubjectID: fixture.Owner.SubjectID, Operation: "OP-SEC-04", Purpose: "security_administration", RequestID: value.NewID(), Outcome: "denied", At: fixture.Now}); err != nil {
				t.Fatal("queue audit", err)
			}
			before, oldest, err := fixture.Repo.AuditDeliveryBacklog(ctx, now)
			if err != nil || before < 1 || oldest == nil {
				t.Fatal("committed business audit was not atomically queued", before, oldest, err)
			}
			first, found, err := fixture.Repo.ClaimAuditDelivery(ctx, now, time.Minute)
			if err != nil || !found || !value.ValidID(first.ID) || !value.ValidID(first.ClaimToken) || first.Attempt != 1 || first.Operation == "" || first.RequestID == "" {
				t.Fatal("claim did not return safe durable metadata", first, found, err)
			}
			if err = fixture.Repo.RetryAuditDelivery(ctx, first.ID, first.ClaimToken, now.Add(-time.Hour)); err != nil {
				t.Fatal("release failed delivery", err)
			}
			_, retryOldest, backlogErr := fixture.Repo.AuditDeliveryBacklog(ctx, now)
			if backlogErr != nil || retryOldest == nil || !retryOldest.Equal(*oldest) {
				t.Fatal("retry schedule changed immutable backlog age", oldest, retryOldest, backlogErr)
			}
			retry, found, err := fixture.Repo.ClaimAuditDelivery(ctx, now, time.Minute)
			if err != nil || !found || retry.ID != first.ID || retry.Attempt != 2 || retry.ClaimToken == first.ClaimToken {
				t.Fatal("retry did not fence the previous claimant", retry, found, err)
			}
			digest := sha256.Sum256([]byte(retry.ID + "\x00" + retry.RequestID))
			receipt := audit.DeliveryReceipt{ReceiptID: value.NewID(), Digest: digest[:]}
			if err = fixture.Repo.AckAuditDelivery(ctx, retry.ID, retry.ClaimToken, receipt, now.Add(30*time.Second)); err != nil {
				t.Fatal("durable receipt acknowledgement failed", err)
			}
			after, _, err := fixture.Repo.AuditDeliveryBacklog(ctx, now.Add(30*time.Second))
			if err != nil || after != before-1 {
				t.Fatal("acknowledged delivery remained in backlog", before, after, err)
			}
		})
	}
}
