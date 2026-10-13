package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
)

func startIdentityKeyd(t testing.TB) (*sensitive.KeydClient, string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp(home, ".teamledger-identity-keyd-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory, socket := filepath.Join(parent, "keys"), filepath.Join(parent, "keyd.sock")
	if err = sensitive.InitKeyDirectory(directory); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- sensitive.ServeKeyd(ctx, sensitive.KeydServerConfig{KeyDirectory: directory, Socket: socket, APIUIDs: []uint32{uint32(os.Geteuid())}, MaintenanceUIDs: []uint32{uint32(os.Geteuid())}})
	}()
	client := &sensitive.KeydClient{Socket: socket, Timeout: time.Second}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = client.Ready(context.Background()); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		<-done
		os.RemoveAll(parent)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		if err := os.RemoveAll(parent); err != nil {
			t.Error(err)
		}
	})
	return client, socket
}
