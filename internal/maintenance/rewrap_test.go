package maintenance_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/maintenance"
	"github.com/r404r/team-ledger/internal/sensitive"
)

type wrapper struct {
	id      string
	version uint32
	fail    bool
}

func (w wrapper) Wrap(_ context.Context, dek []byte) (sensitive.WrappedKey, error) {
	if w.fail {
		return sensitive.WrappedKey{}, errors.New("synthetic wrap failure")
	}
	data := append([]byte(nil), dek...)
	for i := range data {
		data[i] ^= byte(w.version)
	}
	return sensitive.WrappedKey{KEKID: w.id, Version: w.version, Data: data}, nil
}
func (w wrapper) Unwrap(_ context.Context, key sensitive.WrappedKey) ([]byte, error) {
	if w.fail || key.KEKID != w.id || key.Version != w.version {
		return nil, errors.New("synthetic unwrap failure")
	}
	data := append([]byte(nil), key.Data...)
	for i := range data {
		data[i] ^= byte(w.version)
	}
	return data, nil
}

type memoryStore struct {
	items       []maintenance.Item
	next        int
	begun, done bool
	commits     []sensitive.WrappedKey
}

func (m *memoryStore) BeginKeyRewrap(context.Context, maintenance.Target, time.Time) error {
	m.begun = true
	return nil
}
func (m *memoryStore) NextKeyRewrap(context.Context, maintenance.Target) (maintenance.Item, bool, error) {
	if m.next >= len(m.items) {
		return maintenance.Item{}, false, nil
	}
	return m.items[m.next], true, nil
}
func (m *memoryStore) CommitKeyRewrap(_ context.Context, _ maintenance.Target, _ maintenance.Item, key sensitive.WrappedKey, _ time.Time) error {
	key.Data = bytes.Clone(key.Data)
	m.commits = append(m.commits, key)
	m.next++
	return nil
}
func (m *memoryStore) CompleteKeyRewrap(context.Context, maintenance.Target, maintenance.Actor, time.Time) error {
	m.done = true
	return nil
}
func TestRunKeyRewrapIsBoundedResumableAndNeverChangesDEK(t *testing.T) {
	source := wrapper{"old", 1, false}
	target := wrapper{"new", 2, false}
	plain := bytes.Repeat([]byte{0x42}, 32)
	old, _ := source.Wrap(context.Background(), plain)
	store := &memoryStore{items: []maintenance.Item{{Table: "encrypted_payload", ID: "one", Key: old}, {Table: "encrypted_payload", ID: "two", Key: old}}}
	plan := maintenance.Target{OrgID: "10000000-0000-4000-8000-000000000001", Domain: "pii", KEKID: "new", Version: 2, ManifestDigest: bytes.Repeat([]byte{1}, 32)}
	actor := maintenance.Actor{UID: 1000, HostDigest: bytes.Repeat([]byte{2}, 32)}
	count, done, err := maintenance.RunKeyRewrap(context.Background(), store, source, target, plan, actor, 1, time.Now())
	if err != nil || count != 1 || done || store.done {
		t.Fatal("first bounded batch", count, done, err)
	}
	count, done, err = maintenance.RunKeyRewrap(context.Background(), store, source, target, plan, actor, 1, time.Now())
	if err != nil || count != 1 || !done || !store.done || len(store.commits) != 2 {
		t.Fatal("resumed batch", count, done, err)
	}
	for _, key := range store.commits {
		unwrapped, e := target.Unwrap(context.Background(), key)
		if e != nil || !bytes.Equal(unwrapped, plain) {
			t.Fatal("rewrap changed DEK", e)
		}
	}
}
func TestRunKeyRewrapLeavesOriginalOnKeyFailure(t *testing.T) {
	source := wrapper{"old", 1, false}
	old, _ := source.Wrap(context.Background(), bytes.Repeat([]byte{3}, 32))
	store := &memoryStore{items: []maintenance.Item{{Table: "interview_payload", ID: "one", Key: old}}}
	plan := maintenance.Target{OrgID: "10000000-0000-4000-8000-000000000001", Domain: "interview", KEKID: "new", Version: 2, ManifestDigest: bytes.Repeat([]byte{1}, 32)}
	_, _, err := maintenance.RunKeyRewrap(context.Background(), store, source, wrapper{"new", 2, true}, plan, maintenance.Actor{}, 1, time.Now())
	if err == nil || len(store.commits) != 0 || store.done {
		t.Fatal("failed wrapper modified durable state", err)
	}
}
