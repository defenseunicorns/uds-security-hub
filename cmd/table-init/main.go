package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
	"github.com/defenseunicorns/uds-security-hub/internal/sql"
)

// migrateDatabase performs the database migrations.
func migrateDatabase(db *gorm.DB) error {
	models := []interface{}{&model.Package{}, &model.Scan{}, &model.Vulnerability{}}
	for _, model := range models {
		err := db.AutoMigrate(model)
		if err != nil {
			log.Printf("failed to auto-migrate model: %v", err)
		}
	}
	return nil
}

// getEnv retrieves environment variables or returns a default value.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func main() {
	ctx := context.Background()
	config := getConfig()

	if err := run(ctx, &config, func(dbPath string) sql.DBConnector {
		return sql.CreateDBConnector(dbPath)
	}, migrateDatabase); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(
	ctx context.Context,
	config *Config,
	connectorFactory func(string) sql.DBConnector,
	migrator func(*gorm.DB) error,
) error {
	connector := connectorFactory(config.DBPath)
	db, err := connector.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := migrator(db); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	return nil
}

type Config struct {
	DBType string
	DBPath string
}

func getConfig() Config {
	return Config{
		DBType: getEnv("DB_TYPE", "sqlite"),
		DBPath: getEnv("DB_PATH", "test.db"),
	}
}
