package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/attackerlab"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	attackerLabConfig, err := config.LoadAttackerLab(workingDirectory)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	attackerLab, err := attackerlab.New(filepath.Join(workingDirectory, "attacker-lab"))
	if err != nil {
		return err
	}
	defer attackerLab.Close()

	server := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", attackerLabConfig.Port),
		Handler:           attackerLab,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		fmt.Printf("Attacker lab is running at http://localhost:%d\n", attackerLabConfig.Port)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve attacker lab: %w", err)
	}
}
