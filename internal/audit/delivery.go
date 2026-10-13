package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

func retryAt(now time.Time, attempt int64, entropy string) time.Time {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 9 {
		attempt = 9
	}
	base := time.Second * time.Duration(1<<uint(attempt-1))
	hash := uint64(1469598103934665603)
	for i := range len(entropy) {
		hash ^= uint64(entropy[i])
		hash *= 1099511628211
	}
	window := base / 8
	jitter := time.Duration(hash % uint64(window/time.Millisecond+1) * uint64(time.Millisecond))
	return now.Add(base + jitter)
}

func auditEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid audit delivery endpoint")
	}
	return u, nil
}

func ProbeReceiver(ctx context.Context, client *http.Client, endpoint string) error {
	if client == nil {
		return errors.New("invalid audit receiver probe")
	}
	u, err := auditEndpoint(endpoint)
	if err != nil {
		return err
	}
	u.Path = "/health/ready"
	u.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("audit receiver unavailable")
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	if readErr != nil || len(body) != 0 || response.StatusCode != http.StatusNoContent {
		return errors.New("audit receiver unavailable")
	}
	return nil
}

// DeliverOne transfers one body-free audit event and acknowledges it only
// after validating the receiver's persisted chain receipt.
func DeliverOne(ctx context.Context, store DeliveryStore, client *http.Client, endpoint, deployment string, receiptKeys ReceiptKeys, now time.Time) (bool, error) {
	if store == nil || client == nil || !validName(deployment) || len(receiptKeys) == 0 {
		return false, errors.New("invalid audit delivery configuration")
	}
	u, err := auditEndpoint(endpoint)
	if err != nil {
		return false, err
	}
	item, found, err := store.ClaimAuditDelivery(ctx, now, time.Minute)
	if err != nil || !found {
		return found, err
	}
	release := func(cause error) (bool, error) {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		retryErr := store.RetryAuditDelivery(releaseCtx, item.ID, item.ClaimToken, retryAt(now, item.Attempt, item.ID))
		if retryErr != nil {
			return true, retryErr
		}
		return true, cause
	}
	body, digest, err := DeliveryRequestBytes(deployment, item)
	if err != nil {
		return release(err)
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return release(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", item.ID)
	response, err := client.Do(request)
	if err != nil {
		return release(err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 16<<10+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) > 16<<10 || response.StatusCode != http.StatusCreated || response.Header.Get("Content-Type") != "application/json" {
		return release(errors.New("audit facility rejected delivery"))
	}
	verified, verifyErr := VerifyDeliveryReceipt(encoded, deployment, item.ID, digest, receiptKeys, now)
	if verifyErr != nil {
		return release(errors.New("untrusted audit receipt"))
	}
	if err = store.AckAuditDelivery(ctx, item.ID, item.ClaimToken, DeliveryReceipt{ReceiptID: verified.ReceiptID, Digest: digest[:]}, now); err != nil {
		return true, err
	}
	return true, nil
}
