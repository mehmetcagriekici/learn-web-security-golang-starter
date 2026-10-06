package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/config"
	"github.com/mehmetcagriekici/learn-web-security-golang-starter/internal/database"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	appConfig, err := config.Load(workingDirectory)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	databaseConnection, err := database.Open(ctx, appConfig.DatabasePath)
	if err != nil {
		return err
	}
	defer databaseConnection.Close()

	if err := database.Reset(ctx, databaseConnection); err != nil {
		return fmt.Errorf("seed database: %w", err)
	}
	fmt.Printf("Seeded %s\n", appConfig.DatabasePath)
	return nil
}
