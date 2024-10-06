package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/defenseunicorns/uds-security-hub/internal/data/model"
)

type DatabaseInitializer interface {
	Initialize(config *DatabaseConfig) (*gorm.DB, error)
}

type defaultDatabaseInitializer struct{}

func (d *defaultDatabaseInitializer) Initialize(config *DatabaseConfig) (*gorm.DB, error) {
	initializer := getInitializer()

	dbConn, err := initializer.Initialize(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize db: %w", err)
	}

	return dbConn, nil
}

type sqliteDatabaseInitializer struct{}

func (s *sqliteDatabaseInitializer) Initialize(config *DatabaseConfig) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(config.DBPath), os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create directory for database: %w", err)
	}

	dbConn, err := gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return dbConn, nil
}

func getInitializer() DatabaseInitializer {
	return &sqliteDatabaseInitializer{}
}

type DatabaseMigrator interface {
	Migrate(dbConn gormMigrator) error
}

type gormMigrator interface {
	AutoMigrate(...interface{}) error
}

type autoMigratingMigrator struct{}

func (d *autoMigratingMigrator) Migrate(dbConn gormMigrator) error {
	err := dbConn.AutoMigrate(&model.Package{}, &model.Scan{}, &model.Vulnerability{}, &model.Report{})
	if err != nil {
		return fmt.Errorf("failed to migrate: %w", err)
	}

	return nil
}

var DefaultDatabaseInitializer DatabaseInitializer = &migratingDatabaseInitializer{
	initializer: &defaultDatabaseInitializer{},
	migrator:    &autoMigratingMigrator{},
}

type migratingDatabaseInitializer struct {
	initializer DatabaseInitializer
	migrator    DatabaseMigrator
}

func (d *migratingDatabaseInitializer) Initialize(config *DatabaseConfig) (*gorm.DB, error) {
	dbConn, err := d.initializer.Initialize(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize: %w", err)
	}

	if err := d.migrator.Migrate(dbConn); err != nil {
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}

	return dbConn, nil
}
