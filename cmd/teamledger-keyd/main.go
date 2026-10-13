package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
)

func required(name string) (string, error) {
	value := os.Getenv("TEAMLEDGER_" + name)
	if value == "" {
		return "", errors.New("missing required configuration")
	}
	return value, nil
}

func run() error {
	directory, err := required("KEYD_DIR")
	if err != nil {
		return err
	}
	socket, err := required("KEYD_SOCKET")
	if err != nil {
		return err
	}
	apiText, err := required("KEYD_API_UIDS")
	if err != nil {
		return err
	}
	api, err := sensitive.ParseUIDList(apiText)
	if err != nil {
		return err
	}
	maintenance := []uint32{}
	if text := os.Getenv("TEAMLEDGER_KEYD_MAINTENANCE_UIDS"); text != "" {
		maintenance, err = sensitive.ParseUIDList(text)
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return sensitive.ServeKeyd(ctx, sensitive.KeydServerConfig{KeyDirectory: directory, Socket: socket, APIUIDs: api, MaintenanceUIDs: maintenance})
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		socket, err := required("KEYD_SOCKET")
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = (&sensitive.KeydClient{Socket: socket, Timeout: time.Second}).Ready(ctx)
		}
		if err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "teamledger-keyd failed")
		os.Exit(1)
	}
}
