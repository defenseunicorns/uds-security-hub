//go:build integration
// +build integration

package main

import (
	"os"
	"testing"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

// TestStore is a test for the store command e2e.
func TestStore(t *testing.T) {
	github := os.Getenv("GITHUB_TOKEN")
	ghcrCreds := os.Getenv("GHCR_CREDS")
	registry1Creds := os.Getenv("REGISTRY1_CREDS")
	dockerCreds := os.Getenv("DOCKER_IO_CREDS")
	if github == "" || ghcrCreds == "" || registry1Creds == "" {
		t.Fatalf("GITHUB_TOKEN, GHCR_CREDS, and REGISTRY1_CREDS are required")
	}

	os.Args = []string{
		"program",
		"--registry-creds", ghcrCreds,
		"--registry-creds", registry1Creds,
		"--registry-creds", dockerCreds,
		"-n", "packages/uds/gitlab-runner",
		"--db-host", "localhost",
		"--db-password", "test_password",
		"--db-user", "test_user",
		"--db-ssl-mode", "disable",
		"-v", "2",
		"-t", github,
	}

	main()

	// Use a connection string for a test database
	connStr := "host=localhost port=5432 user=test_user dbname=test_db password=test_password sslmode=disable"

	db, err := setupDBConnection(connStr)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check if the connection is valid
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer sqlDB.Close()

	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check the number of rows in the scans table
	var count int64
	row := db.Model(&model.Scan{}).Count(&count)
	if err := row.Error; err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if count <= 1 {
		t.Fatalf("Expected more than 1 row in scans table, got %d", count)
	}
	t.Logf("Scan %d rows", count)

	row = db.Model(&model.Package{}).Count(&count)
	if err := row.Error; err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if count <= 0 {
		t.Fatalf("Expected more than 0 row in package table, got %d", count)
	}
	t.Logf("Package %d rows", count)
}

func TestSetupDBConnection_Success(t *testing.T) {
	// Use a connection string for a test database
	connStr := "host=localhost port=5432 user=test_user dbname=test_db password=test_password sslmode=disable"

	db, err := setupDBConnection(connStr)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check if the connection is valid
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer sqlDB.Close()

	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}
