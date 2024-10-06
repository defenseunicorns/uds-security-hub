package sql

import (
	"context"
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DBConnector is an interface for database connections.
type DBConnector interface {
	Connect(ctx context.Context) (*gorm.DB, error)
}

// SQLiteConnector implements DBConnector for SQLite connections.
type SQLiteConnector struct {
	dbPath string
}

// Connect connects to the SQLite database.
func (c *SQLiteConnector) Connect(ctx context.Context) (*gorm.DB, error) {
	database, err := gorm.Open(sqlite.Open(c.dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SQLite database: %w", err)
	}
	return database, nil
}

// CreateDBConnector creates a new SQLiteConnector.
func CreateDBConnector(dbPath string) *SQLiteConnector {
	return &SQLiteConnector{
		dbPath: dbPath,
	}
}
