package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/store"
)

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Database migration failed")
		os.Exit(1)
	}
}
func run() error {
	backend, dsn := os.Getenv("TEAMLEDGER_BACKEND"), os.Getenv("TEAMLEDGER_DSN")
	if strings.TrimSpace(backend) == "" || strings.TrimSpace(dsn) == "" {
		return fmt.Errorf("missing configuration")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	repo, e := store.Open(ctx, backend, dsn)
	if e != nil {
		return e
	}
	defer repo.Close()
	return repo.Migrate(ctx)
}
